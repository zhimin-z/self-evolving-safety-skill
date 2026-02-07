"""
Model Router: Routes LLM requests to SGLang (local) or OpenRouter (remote).

Features:
- Auto-deploys SGLang server on-demand when local models are requested
- Thread-safe server management (no race conditions)
- Automatic GPU detection for tensor parallelism
- Falls back to OpenRouter for closed-source or unavailable models
"""

import atexit
import os
import re
import signal
import subprocess
import threading
import time
import logging
from typing import Optional, Dict, Any, List, Set

import requests
import litellm
from tenacity import retry, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

# Models that should be routed to local SGLang (open-source models)
# Add model patterns here - supports prefix matching
LOCAL_MODEL_PATTERNS = [
    "qwen/",
    "meta-llama/",
    "mistralai/",
    "deepseek-ai/",
    "microsoft/",
    "google/",
    "tiiuae/",  # Falcon
    "bigcode/",  # StarCoder
    "codellama/",
    "01-ai/",  # Yi
    "internlm/",
    "baichuan-inc/",
    "thudm/",  # ChatGLM
    "alibaba-nlp/",
]

# Models that should ALWAYS go to OpenRouter (closed-source)
CLOSED_SOURCE_PATTERNS = [
    "anthropic/",
    "openai/",
    "cohere/",
    "google/gemini",  # Gemini is closed, but google/gemma is open
]


def _is_local_model(model_name: str) -> bool:
    """Check if a model should be deployed locally."""
    normalized = model_name.lower()

    # Remove common prefixes
    for prefix in ["openrouter/", "sglang/", "local/"]:
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix):]

    # Check if explicitly closed-source
    for pattern in CLOSED_SOURCE_PATTERNS:
        if normalized.startswith(pattern.lower()):
            return False

    # Check if matches local patterns
    for pattern in LOCAL_MODEL_PATTERNS:
        if normalized.startswith(pattern.lower()):
            return True

    # Default: try local if not obviously closed-source
    return False


def _get_cuda_visible_devices() -> str:
    """Read the current CUDA_VISIBLE_DEVICES env var (may change between calls)."""
    return os.environ.get("CUDA_VISIBLE_DEVICES", "")


def _get_gpu_count() -> int:
    """Detect number of available GPUs (respects CUDA_VISIBLE_DEVICES)."""
    cuda_env = _get_cuda_visible_devices()
    if cuda_env.strip():
        try:
            return len([g for g in cuda_env.split(",") if g.strip()])
        except ValueError:
            pass
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            gpus = [line.strip() for line in result.stdout.strip().split("\n") if line.strip()]
            return len(gpus)
    except Exception as e:
        logger.warning(f"Failed to detect GPUs: {e}")
    return 1


def _estimate_tp_size(model_name: str, gpu_count: int) -> int:
    """Estimate tensor parallelism size based on model and available GPUs."""
    normalized = model_name.lower()

    # Extract size indicators from model name
    size_match = re.search(r"(\d+)[bB]", normalized)
    if size_match:
        size_b = int(size_match.group(1))

        # Rough heuristic: ~2GB VRAM per 1B params (with some overhead)
        # A100 80GB can handle ~30-35B per GPU comfortably
        if size_b <= 8:
            needed_gpus = 1
        elif size_b <= 14:
            needed_gpus = 1
        elif size_b <= 32:
            needed_gpus = 2
        elif size_b <= 72:
            needed_gpus = 4
        else:
            needed_gpus = 8

        return min(needed_gpus, gpu_count)

    # Default: use 1 GPU for unknown sizes
    return 1


class SGLangServerManager:
    """
    Manages SGLang server lifecycle with thread-safe operations.

    Ensures only one server runs per model, handles startup/shutdown,
    and provides health checking.
    """

    def __init__(self, base_port: int = 30000):
        self.base_port = base_port
        self._lock = threading.Lock()
        self._servers: Dict[str, Dict[str, Any]] = {}  # model -> {process, port, url}
        self._gpu_count = _get_gpu_count()
        self._gpu_env_snapshot = _get_cuda_visible_devices()  # track GPU set at launch

        # Register cleanup on exit
        atexit.register(self.shutdown_all)
        # signal.signal() only works in the main thread
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

        logger.info(f"SGLangServerManager initialized with {self._gpu_count} GPUs")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down servers...")
        self.shutdown_all()

    def _normalize_model(self, model_name: str) -> str:
        """Normalize model name for consistent key lookup."""
        normalized = model_name.lower()
        for prefix in ["openrouter/", "sglang/", "local/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        return normalized

    def _find_free_port(self) -> int:
        """Find a free port starting from base_port."""
        used_ports = {s["port"] for s in self._servers.values()}
        port = self.base_port
        while port in used_ports:
            port += 1
        return port

    def _wait_for_server(self, url: str, timeout: int = 300) -> bool:
        """Wait for server to become healthy."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                resp = requests.get(f"{url}/v1/models", timeout=5)
                if resp.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            time.sleep(2)
        return False

    def _check_gpu_change(self):
        """Check if CUDA_VISIBLE_DEVICES changed; if so, restart all servers."""
        current_env = _get_cuda_visible_devices()
        if current_env != self._gpu_env_snapshot:
            logger.info(
                f"GPU set changed: '{self._gpu_env_snapshot}' -> '{current_env}'. "
                f"Restarting all SGLang servers."
            )
            # Restart all servers with new GPU set
            for normalized in list(self._servers.keys()):
                self._cleanup_server(normalized)
            self._gpu_env_snapshot = current_env
            self._gpu_count = _get_gpu_count()

    def ensure_server(self, model_name: str) -> Optional[str]:
        """
        Ensure a server is running for the given model.

        Thread-safe: only one server will be started even with concurrent calls.
        Re-reads CUDA_VISIBLE_DEVICES and restarts servers if GPU set changed.

        Args:
            model_name: HuggingFace model name (e.g., "Qwen/Qwen2.5-Coder-7B-Instruct")

        Returns:
            Server URL if successful, None if failed
        """
        normalized = self._normalize_model(model_name)

        # Fast path: check if already running (no lock needed for read)
        if normalized in self._servers:
            server = self._servers[normalized]
            # Verify it's still healthy
            try:
                resp = requests.get(f"{server['url']}/v1/models", timeout=5)
                if resp.status_code == 200:
                    return server["url"]
            except requests.RequestException:
                pass
            # Server died, will restart below

        with self._lock:
            # Check if GPU set changed since last server launch
            self._check_gpu_change()

            # Double-check after acquiring lock
            if normalized in self._servers:
                server = self._servers[normalized]
                try:
                    resp = requests.get(f"{server['url']}/v1/models", timeout=5)
                    if resp.status_code == 200:
                        return server["url"]
                except requests.RequestException:
                    # Clean up dead server
                    self._cleanup_server(normalized)

            # Start new server
            port = self._find_free_port()
            tp_size = _estimate_tp_size(model_name, self._gpu_count)

            logger.info(f"Starting SGLang server for {model_name} on port {port} with tp={tp_size}")

            cmd = [
                "python", "-m", "sglang.launch_server",
                "--model-path", model_name,
                "--port", str(port),
                "--tp", str(tp_size),
                "--host", "0.0.0.0",
            ]

            # Add memory optimization flags for large models
            if tp_size >= 2:
                cmd.extend(["--chunked-prefill-size", "8192"])

            try:
                # Start server process
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )

                url = f"http://localhost:{port}"

                # Wait for server to be ready
                logger.info(f"Waiting for SGLang server to start (this may take a few minutes)...")
                if self._wait_for_server(url, timeout=600):  # 10 min timeout for large models
                    self._servers[normalized] = {
                        "process": process,
                        "port": port,
                        "url": url,
                        "model": model_name,
                    }
                    logger.info(f"SGLang server ready at {url}")
                    return url
                else:
                    logger.error(f"SGLang server failed to start within timeout")
                    process.terminate()
                    return None

            except Exception as e:
                logger.error(f"Failed to start SGLang server: {e}")
                return None

    def _cleanup_server(self, normalized: str):
        """Clean up a specific server."""
        if normalized in self._servers:
            server = self._servers.pop(normalized)
            try:
                server["process"].terminate()
                server["process"].wait(timeout=10)
            except Exception:
                server["process"].kill()
            logger.info(f"Shut down server for {server['model']}")

    def shutdown_all(self):
        """Shut down all running servers."""
        with self._lock:
            for normalized in list(self._servers.keys()):
                self._cleanup_server(normalized)

    def get_server_url(self, model_name: str) -> Optional[str]:
        """Get URL for a running server (doesn't start new ones)."""
        normalized = self._normalize_model(model_name)
        if normalized in self._servers:
            return self._servers[normalized]["url"]
        return None

    def list_running(self) -> List[Dict[str, Any]]:
        """List all running servers."""
        return [
            {"model": s["model"], "port": s["port"], "url": s["url"]}
            for s in self._servers.values()
        ]


# Global server manager (singleton)
_server_manager: Optional[SGLangServerManager] = None
_server_manager_lock = threading.Lock()


def get_server_manager() -> SGLangServerManager:
    """Get or create the global server manager."""
    global _server_manager
    if _server_manager is None:
        with _server_manager_lock:
            if _server_manager is None:
                _server_manager = SGLangServerManager()
    return _server_manager


class ModelRouter:
    """Routes model requests to SGLang or OpenRouter based on availability."""

    def __init__(
        self,
        auto_deploy: bool = True,
        cache_ttl: int = 300,
    ):
        """
        Initialize the model router.

        Args:
            auto_deploy: Whether to auto-deploy SGLang for local models (default: True)
            cache_ttl: Seconds to cache the model list (default: 300)
        """
        self.auto_deploy = auto_deploy
        self.cache_ttl = cache_ttl
        self._server_manager = get_server_manager() if auto_deploy else None

    def _normalize_model_name(self, model_name: str) -> str:
        """Normalize model name for comparison."""
        name = model_name.lower()
        for prefix in ["openrouter/", "sglang/", "local/"]:
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    def get_routing_target(self, model_name: str) -> tuple[str, str]:
        """
        Determine where to route a model request.

        Args:
            model_name: The requested model name

        Returns:
            Tuple of (target, formatted_model_name) where target is "sglang" or "openrouter"
        """
        # Check if explicitly requesting OpenRouter
        if model_name.startswith("openrouter/"):
            return "openrouter", model_name

        # Check if this is a local-deployable model
        if self.auto_deploy and _is_local_model(model_name):
            return "sglang", self._normalize_model_name(model_name)

        # Fall back to OpenRouter
        if not model_name.startswith("openrouter/"):
            model_name = f"openrouter/{model_name}"
        return "openrouter", model_name

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    def _sglang_completion(
        self,
        url: str,
        model: str,
        messages: List[Dict[str, Any]],
        **kwargs,
    ) -> Any:
        """Make a completion request to SGLang server."""
        response = requests.post(
            f"{url}/v1/chat/completions",
            json={
                "model": model,
                "messages": messages,
                **kwargs,
            },
            timeout=300,  # Longer timeout for generation
        )
        response.raise_for_status()
        return response.json()

    def completion(
        self,
        model: str,
        messages: List[Dict[str, Any]],
        **kwargs,
    ) -> Any:
        """
        Route completion request to appropriate backend.

        Args:
            model: Model name
            messages: Chat messages
            **kwargs: Additional parameters (temperature, max_tokens, etc.)

        Returns:
            Completion response (OpenAI-compatible format)
        """
        target, formatted_model = self.get_routing_target(model)

        if target == "sglang" and self._server_manager:
            # Ensure server is running (thread-safe, will reuse existing)
            # Use original model name for HuggingFace path
            original_model = model
            for prefix in ["sglang/", "local/"]:
                if original_model.lower().startswith(prefix):
                    original_model = original_model[len(prefix):]

            server_url = self._server_manager.ensure_server(original_model)

            if server_url:
                logger.info(f"Routing '{model}' to SGLang at {server_url}")
                try:
                    return self._sglang_completion(server_url, formatted_model, messages, **kwargs)
                except Exception as e:
                    logger.warning(f"SGLang request failed: {e}")
                    # Fall through to OpenRouter
            else:
                logger.warning(f"Failed to start SGLang server for {model}")

            # Update target for fallback
            target = "openrouter"
            if not model.startswith("openrouter/"):
                formatted_model = f"openrouter/{model}"
            else:
                formatted_model = model

        # OpenRouter via litellm
        logger.info(f"Routing '{model}' to OpenRouter as '{formatted_model}'")
        return litellm.completion(
            model=formatted_model,
            messages=messages,
            **kwargs,
        )


# Global router instance (lazy initialization)
_router: Optional[ModelRouter] = None


def get_router() -> ModelRouter:
    """Get or create the global model router instance."""
    global _router
    if _router is None:
        auto_deploy = os.getenv("SGLANG_AUTO_DEPLOY", "true").lower() in ("true", "1", "yes")
        _router = ModelRouter(auto_deploy=auto_deploy)
    return _router


def completion_with_routing(
    model: str,
    messages: List[Dict[str, Any]],
    **kwargs,
) -> Any:
    """
    Convenience function for routed completion.

    Args:
        model: Model name (e.g., "qwen/qwen3-coder-next", "anthropic/claude-haiku-4.5")
        messages: Chat messages
        **kwargs: Additional parameters

    Returns:
        Completion response
    """
    return get_router().completion(model, messages, **kwargs)


def check_sglang_status() -> Dict[str, Any]:
    """Check SGLang server status and running servers."""
    manager = get_server_manager()
    return {
        "gpu_count": manager._gpu_count,
        "running_servers": manager.list_running(),
        "auto_deploy": os.getenv("SGLANG_AUTO_DEPLOY", "true").lower() in ("true", "1", "yes"),
    }


def shutdown_servers():
    """Manually shut down all SGLang servers."""
    get_server_manager().shutdown_all()


class RoutedLitellmModel:
    """
    A LitellmModel-compatible class that routes requests through ModelRouter.

    This class provides the same interface as minisweagent's LitellmModel but
    routes requests to SGLang when available, falling back to OpenRouter.
    """

    def __init__(
        self,
        model_name: str,
        model_kwargs: Optional[Dict[str, Any]] = None,
        cost_tracking: str = "default",
        **kwargs,
    ):
        """
        Initialize RoutedLitellmModel.

        Args:
            model_name: Model name (e.g., "qwen/qwen3-coder-next")
            model_kwargs: Additional model parameters
            cost_tracking: Cost tracking mode ("default" or "ignore_errors")
        """
        self.model_name = model_name
        self.model_kwargs = model_kwargs or {}
        self.cost_tracking = cost_tracking
        self.cost = 0.0
        self.n_calls = 0
        self._router = get_router()

        # Check routing target at init time for logging
        target, formatted = self._router.get_routing_target(model_name)
        logger.info(f"RoutedLitellmModel initialized: {model_name} -> {target} ({formatted})")

    def query(self, messages: List[Dict[str, str]], **kwargs) -> Dict[str, Any]:
        """
        Query the model with routing support.

        Args:
            messages: List of message dicts with "role" and "content"
            **kwargs: Additional parameters

        Returns:
            Dict with "content" and "extra" keys
        """
        # Merge kwargs with default model_kwargs
        merged_kwargs = {**self.model_kwargs, **kwargs}

        # Route and execute
        response = self._router.completion(
            model=self.model_name,
            messages=[{"role": m["role"], "content": m["content"]} for m in messages],
            **merged_kwargs,
        )

        # Handle both dict (SGLang raw response) and litellm response object
        if isinstance(response, dict):
            content = response["choices"][0]["message"]["content"] or ""
            response_dump = response
        else:
            content = response.choices[0].message.content or ""
            response_dump = response.model_dump()

        # Update stats
        self.n_calls += 1
        # Cost tracking is best-effort for routed models
        try:
            if hasattr(response, 'usage') and response.usage:
                # Estimate cost (simplified)
                pass
        except Exception:
            pass

        return {
            "content": content,
            "extra": {
                "response": response_dump,
            },
        }

    def get_template_vars(self) -> Dict[str, Any]:
        """Get template variables for the model."""
        return {
            "model_name": self.model_name,
            "model_kwargs": self.model_kwargs,
            "n_model_calls": self.n_calls,
            "model_cost": self.cost,
        }


if __name__ == "__main__":
    # Dry run test
    logging.basicConfig(level=logging.INFO)

    print("=" * 60)
    print("Model Router Dry Run Test")
    print("=" * 60)

    # Check status
    print("\n1. Checking system status...")
    status = check_sglang_status()
    print(f"   GPU count: {status['gpu_count']}")
    print(f"   Auto-deploy enabled: {status['auto_deploy']}")
    print(f"   Running servers: {status['running_servers']}")

    # Test routing decisions (no server start)
    print("\n2. Testing routing decisions...")
    router = get_router()

    test_models = [
        ("qwen/Qwen2.5-Coder-7B-Instruct", "Should route to SGLang (local)"),
        ("meta-llama/Llama-3.1-8B-Instruct", "Should route to SGLang (local)"),
        ("anthropic/claude-haiku-4.5", "Should route to OpenRouter (closed-source)"),
        ("openrouter/anthropic/claude-sonnet-4.5", "Should route to OpenRouter (explicit)"),
        ("deepseek-ai/DeepSeek-Coder-V2", "Should route to SGLang (local)"),
    ]

    for model, expected in test_models:
        target, formatted = router.get_routing_target(model)
        print(f"   {model}")
        print(f"      -> {target}: {formatted}")
        print(f"      Expected: {expected}")

    print("\n3. To test actual deployment, run with a local model:")
    print("   SGLANG_AUTO_DEPLOY=true python -c \"")
    print("   from src.model_router import completion_with_routing")
    print("   resp = completion_with_routing('qwen/Qwen2.5-Coder-7B-Instruct', [{'role': 'user', 'content': 'Hi'}])")
    print("   print(resp)\"")

    print("\n" + "=" * 60)
    print("Dry run complete!")
    print("=" * 60)
