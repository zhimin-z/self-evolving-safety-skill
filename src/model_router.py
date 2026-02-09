"""
Model Router: Routes LLM requests to vLLM (local) or OpenRouter (remote).

Features:
- Auto-deploys vLLM server on-demand when local models are requested
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
litellm.suppress_debug_info = True

logger = logging.getLogger(__name__)

# Models that should be routed to local vLLM (open-source models)
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
    for prefix in ["openrouter/", "vllm/", "sglang/", "local/"]:
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


def _get_gpu_ids() -> List[int]:
    """Return individual GPU IDs from CUDA_VISIBLE_DEVICES.

    If CUDA_VISIBLE_DEVICES="4,5,6,7", returns [4, 5, 6, 7].
    If unset, attempts nvidia-smi detection and returns [0, ..., N-1].
    """
    cuda_env = _get_cuda_visible_devices()
    if cuda_env.strip():
        try:
            return [int(g.strip()) for g in cuda_env.split(",") if g.strip()]
        except ValueError:
            pass
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=index", "--format=csv,noheader"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            return [int(line.strip()) for line in result.stdout.strip().split("\n") if line.strip()]
    except Exception:
        pass
    return [0]


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


class VLLMServerManager:
    """
    Manages vLLM server lifecycle with thread-safe operations.

    Ensures only one server runs per model, handles startup/shutdown,
    and provides health checking.
    """

    def __init__(self, base_port: int = 30000, failure_cooldown: int = 300):
        self.base_port = base_port
        self._lock = threading.Lock()
        self._servers: Dict[str, List[Dict[str, Any]]] = {}  # model -> list of {process, port, url, gpu_ids}
        self._rr_counters: Dict[str, int] = {}  # model -> round-robin counter
        self._failed_models: Dict[str, float] = {}  # model -> timestamp of last failure
        self._failure_cooldown = failure_cooldown  # seconds before retrying a failed model
        self._unhealthy_urls: Dict[str, float] = {}  # url -> timestamp of failure
        self._unhealthy_ttl = 120  # seconds before retrying an unhealthy server
        self._gpu_count = _get_gpu_count()
        self._gpu_ids = _get_gpu_ids()
        self._gpu_env_snapshot = _get_cuda_visible_devices()  # track GPU set at launch

        # Register cleanup on exit
        atexit.register(self.shutdown_all)
        # signal.signal() only works in the main thread
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, self._signal_handler)
            signal.signal(signal.SIGINT, self._signal_handler)

        logger.info(f"VLLMServerManager initialized with {self._gpu_count} GPUs (IDs: {self._gpu_ids})")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        logger.info(f"Received signal {signum}, shutting down vLLM servers...")
        self.shutdown_all()

    def _normalize_model(self, model_name: str) -> str:
        """Normalize model name for consistent key lookup."""
        normalized = model_name.lower()
        for prefix in ["openrouter/", "vllm/", "sglang/", "local/"]:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        return normalized

    def _find_free_port(self, reserved: Set[int] = None) -> int:
        """Find a free port starting from base_port."""
        used_ports: Set[int] = set()
        for instances in self._servers.values():
            for s in instances:
                used_ports.add(s["port"])
        if reserved:
            used_ports |= reserved
        port = self.base_port
        while port in used_ports:
            port += 1
        return port

    def _wait_for_server(self, url: str, process: subprocess.Popen = None, timeout: int = 300) -> bool:
        """Wait for server to become healthy.

        If process is provided, checks whether it has exited (crash/error)
        and surfaces the error output immediately instead of waiting for
        the full timeout.
        """
        start = time.time()
        while time.time() - start < timeout:
            # Check if the server process died
            if process is not None and process.poll() is not None:
                exit_code = process.returncode
                # Read whatever output the process produced
                output = ""
                try:
                    output = process.stdout.read() if process.stdout else ""
                except Exception:
                    pass
                # Extract last meaningful lines for the error message
                lines = [l for l in output.strip().split("\n") if l.strip()] if output else []
                tail = "\n".join(lines[-20:]) if lines else "(no output captured)"
                logger.error(
                    f"vLLM server process exited with code {exit_code}. "
                    f"Last output:\n{tail}"
                )
                print(
                    f"\n  [vLLM ERROR] Server process died (exit code {exit_code}).\n"
                    f"  Last output:\n{tail}\n"
                )
                return False

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
                f"Restarting all vLLM servers."
            )
            for normalized in list(self._servers.keys()):
                self._cleanup_model_servers(normalized)
            self._gpu_env_snapshot = current_env
            self._gpu_count = _get_gpu_count()
            self._gpu_ids = _get_gpu_ids()

    def _start_single_server(
        self,
        model_name: str,
        tp_size: int,
        gpu_ids: Optional[List[int]] = None,
        port: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Launch one vLLM server instance, optionally pinned to specific GPU(s).

        Args:
            model_name: HuggingFace model path
            tp_size: Tensor parallelism size
            gpu_ids: If provided, sets CUDA_VISIBLE_DEVICES for this subprocess
            port: If provided, use this port; otherwise find a free one

        Returns:
            Server info dict or None on failure.
        """
        if port is None:
            port = self._find_free_port()

        cmd = [
            "python", "-m", "vllm.entrypoints.openai.api_server",
            "--model", model_name,
            "--port", str(port),
            "--tensor-parallel-size", str(tp_size),
            "--host", "0.0.0.0",
            "--trust-remote-code",
        ]
        if tp_size >= 2:
            cmd.append("--enable-chunked-prefill")

        env = os.environ.copy()
        if gpu_ids is not None:
            env["CUDA_VISIBLE_DEVICES"] = ",".join(str(g) for g in gpu_ids)

        gpu_label = gpu_ids if gpu_ids else "all"
        logger.info(f"Starting vLLM for {model_name} on port {port}, tp={tp_size}, gpus={gpu_label}")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                start_new_session=True,
            )
            url = f"http://localhost:{port}"

            if self._wait_for_server(url, process=process, timeout=600):
                info = {
                    "process": process,
                    "port": port,
                    "url": url,
                    "model": model_name,
                    "gpu_ids": gpu_ids or [],
                }
                logger.info(f"vLLM server ready at {url} (gpus={gpu_label})")
                return info
            else:
                if process.poll() is None:
                    logger.error(f"vLLM server on port {port} failed to start within timeout")
                    self._kill_process_group(process)
                return None
        except Exception as e:
            logger.error(f"Failed to start vLLM server: {e}")
            return None

    def ensure_server_pool(self, model_name: str) -> bool:
        """Ensure a pool of servers is running for the given model.

        For tp=1 models: starts one server per available GPU (data parallelism).
        For tp>1 models: starts one server using tp GPUs (tensor parallelism).

        Thread-safe. Returns True if at least one server is healthy.
        """
        normalized = self._normalize_model(model_name)

        # Fast-fail: skip models that recently failed to start
        if normalized in self._failed_models:
            elapsed = time.time() - self._failed_models[normalized]
            if elapsed < self._failure_cooldown:
                logger.debug(
                    f"Skipping {model_name}: startup failed {elapsed:.0f}s ago "
                    f"(cooldown {self._failure_cooldown}s)"
                )
                return False
            else:
                # Cooldown expired, allow retry
                del self._failed_models[normalized]

        # Fast path: pool already exists with healthy servers
        if normalized in self._servers and self._servers[normalized]:
            for instance in self._servers[normalized]:
                try:
                    resp = requests.get(f"{instance['url']}/v1/models", timeout=5)
                    if resp.status_code == 200:
                        return True
                except requests.RequestException:
                    continue

        with self._lock:
            self._check_gpu_change()

            # Double-check under lock
            if normalized in self._servers and self._servers[normalized]:
                for instance in self._servers[normalized]:
                    try:
                        resp = requests.get(f"{instance['url']}/v1/models", timeout=5)
                        if resp.status_code == 200:
                            return True
                    except requests.RequestException:
                        continue
                # All dead, clean up
                self._cleanup_model_servers(normalized)

            tp_size = _estimate_tp_size(model_name, self._gpu_count)
            gpu_ids = self._gpu_ids

            # Pre-cleanup: kill any orphaned vLLM processes on target GPUs
            # (e.g. EngineCore children from a previous crashed server)
            self._kill_orphan_vllm_on_gpus(gpu_ids)

            self._servers[normalized] = []
            self._rr_counters[normalized] = 0

            if tp_size == 1 and len(gpu_ids) > 1:
                # Data parallelism: one server per GPU
                num_instances = len(gpu_ids)
                print(f"  [vLLM] Starting {num_instances} instances for {model_name} "
                      f"(tp=1, data-parallel across GPUs {gpu_ids})")

                # Pre-allocate ports to avoid collisions
                ports = []
                reserved: Set[int] = set()
                for _ in gpu_ids:
                    p = self._find_free_port(reserved=reserved)
                    ports.append(p)
                    reserved.add(p)

                ready_count = 0

                # --- Phase 1: Start FIRST instance and wait for it ---
                # This ensures the model is downloaded/cached before launching
                # the rest, avoiding concurrent download contention and OOM.
                first_gpu, first_port = gpu_ids[0], ports[0]
                print(f"  [vLLM] Phase 1: Starting first instance on GPU {first_gpu} "
                      f"(downloads & caches model)...")
                first_info = self._start_single_server(
                    model_name, tp_size=1, gpu_ids=[first_gpu], port=first_port,
                )
                if first_info is not None:
                    self._servers[normalized].append(first_info)
                    ready_count += 1
                    print(f"  [vLLM] First instance ready at {first_info['url']} "
                          f"({ready_count}/{num_instances})")
                else:
                    print(f"  [vLLM] First instance on GPU {first_gpu} failed. "
                          f"Trying remaining GPUs...")

                # --- Phase 2: Start remaining instances in parallel ---
                # Model is now cached on disk, so these load from cache.
                remaining_gpus = list(zip(gpu_ids[1:], ports[1:]))
                if remaining_gpus:
                    print(f"  [vLLM] Phase 2: Starting {len(remaining_gpus)} more instances "
                          f"in parallel (loading from cache)...")

                    pending = []  # (gpu_id, port, process)
                    for gpu_id, port in remaining_gpus:
                        cmd = [
                            "python", "-m", "vllm.entrypoints.openai.api_server",
                            "--model", model_name,
                            "--port", str(port),
                            "--tensor-parallel-size", "1",
                            "--host", "0.0.0.0",
                            "--trust-remote-code",
                        ]
                        env = os.environ.copy()
                        env["CUDA_VISIBLE_DEVICES"] = str(gpu_id)
                        try:
                            process = subprocess.Popen(
                                cmd,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                text=True,
                                env=env,
                                start_new_session=True,
                            )
                            pending.append((gpu_id, port, process))
                            logger.info(f"Launched vLLM on GPU {gpu_id}, port {port}")
                        except Exception as e:
                            logger.error(f"Failed to launch vLLM on GPU {gpu_id}: {e}")

                    # Wait for all remaining to become healthy
                    deadline = time.time() + 600
                    still_pending = list(pending)

                    while still_pending and time.time() < deadline:
                        remaining = []
                        for gpu_id, port, process in still_pending:
                            url = f"http://localhost:{port}"
                            # Check if process died
                            if process.poll() is not None:
                                exit_code = process.returncode
                                output = ""
                                try:
                                    output = process.stdout.read() if process.stdout else ""
                                except Exception:
                                    pass
                                lines = [l for l in output.strip().split("\n") if l.strip()] if output else []
                                tail = "\n".join(lines[-10:]) if lines else "(no output)"
                                logger.error(f"vLLM on GPU {gpu_id} died (exit {exit_code}): {tail}")
                                print(f"  [vLLM] Instance on GPU {gpu_id} failed (exit {exit_code})")
                                continue
                            # Check if healthy
                            try:
                                resp = requests.get(f"{url}/v1/models", timeout=3)
                                if resp.status_code == 200:
                                    self._servers[normalized].append({
                                        "process": process,
                                        "port": port,
                                        "url": url,
                                        "model": model_name,
                                        "gpu_ids": [gpu_id],
                                    })
                                    ready_count += 1
                                    print(f"  [vLLM] Instance on GPU {gpu_id} ready at {url} "
                                          f"({ready_count}/{num_instances})")
                                    continue
                            except requests.RequestException:
                                pass
                            remaining.append((gpu_id, port, process))
                        still_pending = remaining
                        if still_pending:
                            time.sleep(2)

                    # Kill any still-pending after timeout
                    for gpu_id, port, process in still_pending:
                        logger.error(f"vLLM on GPU {gpu_id} timed out, terminating")
                        self._kill_process_group(process)

                if not self._servers[normalized]:
                    logger.error(f"All vLLM instances failed for {model_name}")
                    del self._servers[normalized]
                    del self._rr_counters[normalized]
                    self._failed_models[normalized] = time.time()
                    return False

                print(f"  [vLLM] Pool ready: {len(self._servers[normalized])}/{num_instances} instances")
                return True

            else:
                # Tensor parallelism or single GPU: one server
                assigned_gpus = gpu_ids[:tp_size] if tp_size <= len(gpu_ids) else gpu_ids
                print(f"  [vLLM] Starting 1 instance for {model_name} (tp={tp_size}, GPUs {assigned_gpus})")

                info = self._start_single_server(model_name, tp_size=tp_size, gpu_ids=assigned_gpus)
                if info is not None:
                    self._servers[normalized].append(info)
                    return True
                else:
                    del self._servers[normalized]
                    del self._rr_counters[normalized]
                    self._failed_models[normalized] = time.time()
                    return False

    def ensure_server(self, model_name: str) -> Optional[str]:
        """Backward-compatible wrapper: ensure pool and return a server URL."""
        if self.ensure_server_pool(model_name):
            return self.get_next_server_url(model_name)
        return None

    def mark_unhealthy(self, url: str):
        """Mark a server URL as temporarily unhealthy (skipped for _unhealthy_ttl seconds)."""
        self._unhealthy_urls[url] = time.time()
        logger.warning(f"Marked {url} as unhealthy (will skip for {self._unhealthy_ttl}s)")

    def get_next_server_url(self, model_name: str) -> Optional[str]:
        """Return the next healthy server URL via round-robin.

        Skips servers marked unhealthy within the last _unhealthy_ttl seconds.
        Thread-safe: uses CPython GIL for the counter increment.
        """
        normalized = self._normalize_model(model_name)
        instances = self._servers.get(normalized, [])
        if not instances:
            return None
        n = len(instances)
        now = time.time()
        # Try up to n times to find a healthy server
        for _ in range(n):
            idx = self._rr_counters.get(normalized, 0)
            self._rr_counters[normalized] = (idx + 1) % n
            url = instances[idx % n]["url"]
            failed_at = self._unhealthy_urls.get(url)
            if failed_at and (now - failed_at) < self._unhealthy_ttl:
                continue  # skip this server, try next
            # Clear expired entry if any
            self._unhealthy_urls.pop(url, None)
            return url
        # All servers unhealthy — return next one anyway (let caller handle)
        logger.warning("All vLLM servers marked unhealthy, returning next available")
        idx = self._rr_counters.get(normalized, 0)
        self._rr_counters[normalized] = (idx + 1) % n
        return instances[idx % n]["url"]

    @staticmethod
    def _kill_process_group(process: subprocess.Popen):
        """Kill an entire process group (catches child EngineCore processes)."""
        try:
            pgid = os.getpgid(process.pid)
            os.killpg(pgid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(pgid, signal.SIGKILL)
                process.wait(timeout=5)
        except (ProcessLookupError, OSError):
            # Process/group already dead
            try:
                process.kill()
            except Exception:
                pass

    @staticmethod
    def _kill_orphan_vllm_on_gpus(gpu_ids: List[int]):
        """Kill any orphaned vLLM EngineCore processes on the given GPUs.

        After a vLLM API server crashes, its child EngineCore processes can
        become orphaned and continue holding GPU memory.  This scans for and
        kills them so the GPUs are actually free for a restart.
        """
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-compute-apps=pid,gpu_bus_id",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode != 0:
                return

            # Map GPU index → bus_id
            bus_result = subprocess.run(
                ["nvidia-smi", "--query-gpu=index,gpu_bus_id",
                 "--format=csv,noheader,nounits"],
                capture_output=True, text=True, timeout=10,
            )
            if bus_result.returncode != 0:
                return

            target_buses = set()
            for line in bus_result.stdout.strip().split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 2:
                    idx = int(parts[0])
                    if idx in gpu_ids:
                        target_buses.add(parts[1])

            killed = 0
            for line in result.stdout.strip().split("\n"):
                parts = [p.strip() for p in line.split(",")]
                if len(parts) == 2:
                    pid_str, bus_id = parts
                    if bus_id in target_buses:
                        try:
                            pid = int(pid_str)
                            # Verify it's actually a vLLM process before killing
                            cmd_result = subprocess.run(
                                ["ps", "-p", str(pid), "-o", "comm="],
                                capture_output=True, text=True, timeout=5,
                            )
                            if "vllm" in cmd_result.stdout.lower() or "python" in cmd_result.stdout.lower():
                                os.kill(pid, signal.SIGKILL)
                                killed += 1
                        except (ProcessLookupError, ValueError, OSError):
                            pass
            if killed:
                logger.info(f"Killed {killed} orphaned vLLM process(es) on GPUs {gpu_ids}")
                time.sleep(3)  # Give GPU memory time to be freed
        except Exception as e:
            logger.warning(f"Orphan cleanup failed (non-fatal): {e}")

    def _cleanup_model_servers(self, normalized: str):
        """Clean up ALL server instances for a model, including child processes."""
        instances = self._servers.pop(normalized, [])
        self._rr_counters.pop(normalized, None)
        all_gpu_ids = []
        for instance in instances:
            self._kill_process_group(instance["process"])
            all_gpu_ids.extend(instance.get("gpu_ids", []))
            logger.info(f"Shut down server for {instance['model']} on port {instance['port']}")
        # Also kill any orphaned EngineCore processes on those GPUs
        if all_gpu_ids:
            self._kill_orphan_vllm_on_gpus(all_gpu_ids)

    def _cleanup_server(self, normalized: str):
        """Backward compat alias."""
        self._cleanup_model_servers(normalized)

    def shutdown_all(self):
        """Shut down all running servers."""
        with self._lock:
            for normalized in list(self._servers.keys()):
                self._cleanup_model_servers(normalized)

    def get_server_url(self, model_name: str) -> Optional[str]:
        """Get URL for a running server (doesn't start new ones)."""
        normalized = self._normalize_model(model_name)
        instances = self._servers.get(normalized, [])
        if instances:
            return instances[0]["url"]
        return None

    def list_running(self) -> List[Dict[str, Any]]:
        """List all running server instances."""
        result = []
        for instances in self._servers.values():
            for s in instances:
                result.append({
                    "model": s["model"],
                    "port": s["port"],
                    "url": s["url"],
                    "gpu_ids": s.get("gpu_ids", []),
                })
        return result


# Global server manager (singleton)
_server_manager: Optional[VLLMServerManager] = None
_server_manager_lock = threading.Lock()


def get_server_manager() -> VLLMServerManager:
    """Get or create the global server manager."""
    global _server_manager
    if _server_manager is None:
        with _server_manager_lock:
            if _server_manager is None:
                _server_manager = VLLMServerManager()
    return _server_manager


class ModelRouter:
    """Routes model requests to vLLM (local) or OpenRouter (remote) based on availability."""

    def __init__(
        self,
        auto_deploy: bool = True,
        cache_ttl: int = 300,
    ):
        """
        Initialize the model router.

        Args:
            auto_deploy: Whether to auto-deploy vLLM for local models (default: True)
            cache_ttl: Seconds to cache the model list (default: 300)
        """
        self.auto_deploy = auto_deploy
        self.cache_ttl = cache_ttl
        self._server_manager = get_server_manager() if auto_deploy else None

    def _normalize_model_name(self, model_name: str) -> str:
        """Normalize model name for comparison."""
        name = model_name.lower()
        for prefix in ["openrouter/", "vllm/", "sglang/", "local/"]:
            if name.startswith(prefix):
                name = name[len(prefix):]
        return name

    def get_routing_target(self, model_name: str) -> tuple[str, str]:
        """
        Determine where to route a model request.

        Args:
            model_name: The requested model name

        Returns:
            Tuple of (target, formatted_model_name) where target is "vllm" or "openrouter"
        """
        # Check if explicitly requesting OpenRouter
        if model_name.startswith("openrouter/"):
            return "openrouter", model_name

        # Check if this is a local-deployable model
        if self.auto_deploy and _is_local_model(model_name):
            # Preserve original case for vLLM (it requires exact model name)
            clean_name = model_name
            for prefix in ["vllm/", "sglang/", "local/"]:
                if clean_name.lower().startswith(prefix):
                    clean_name = clean_name[len(prefix):]
                    break
            return "vllm", clean_name

        # Fall back to OpenRouter
        if not model_name.startswith("openrouter/"):
            model_name = f"openrouter/{model_name}"
        return "openrouter", model_name

    def _vllm_completion(
        self,
        url: str,
        model: str,
        messages: List[Dict[str, Any]],
        **kwargs,
    ) -> Any:
        """Make a single completion request to vLLM server via litellm.

        Uses litellm with hosted_vllm/ prefix and api_base pointing to local vLLM.
        This ensures the response object matches litellm format (.choices[0].message.content).

        No retry here — retry logic lives in completion() which picks a different
        server on each attempt via round-robin.
        """
        litellm_model = f"hosted_vllm/{model}"
        api_base = f"{url}/v1"
        try:
            return litellm.completion(
                model=litellm_model,
                messages=messages,
                api_base=api_base,
                api_key="unused",
                timeout=120,
                **kwargs,
            )
        except Exception as e:
            logger.error(f"_vllm_completion failed: model={litellm_model}, url={api_base}, error={type(e).__name__}: {e}")
            raise

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

        if target == "vllm" and self._server_manager:
            # Use original model name for HuggingFace path
            original_model = model
            for prefix in ["vllm/", "sglang/", "local/"]:
                if original_model.lower().startswith(prefix):
                    original_model = original_model[len(prefix):]

            # Ensure server pool is running
            pool_ok = self._server_manager.ensure_server_pool(original_model)

            if pool_ok:
                # Retry up to 3 times, picking a DIFFERENT server each attempt
                last_error = None
                for attempt in range(3):
                    server_url = self._server_manager.get_next_server_url(original_model)
                    if not server_url:
                        break
                    try:
                        logger.info(f"Routing '{model}' to vLLM at {server_url} (attempt {attempt + 1}/3)")
                        return self._vllm_completion(server_url, formatted_model, messages, **kwargs)
                    except Exception as e:
                        last_error = e
                        self._server_manager.mark_unhealthy(server_url)
                        logger.warning(f"vLLM attempt {attempt + 1}/3 failed on {server_url}: {type(e).__name__}")
                        continue
                # All attempts exhausted
                if last_error:
                    if _is_local_model(model):
                        raise RuntimeError(
                            f"All vLLM attempts failed for local model '{model}': {last_error}"
                        ) from last_error

            # vLLM failed — only fall back to OpenRouter for models that exist there
            if _is_local_model(model):
                raise RuntimeError(
                    f"vLLM server pool not available for local model '{model}'. "
                    f"Cannot fall back to OpenRouter for local-only models."
                )

            logger.warning(f"vLLM unavailable for {model}, falling back to OpenRouter")
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
        auto_deploy = os.getenv("VLLM_AUTO_DEPLOY", "true").lower() in ("true", "1", "yes")
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


def check_vllm_status() -> Dict[str, Any]:
    """Check vLLM server status and running servers."""
    manager = get_server_manager()
    return {
        "gpu_count": manager._gpu_count,
        "gpu_ids": manager._gpu_ids,
        "running_servers": manager.list_running(),
        "auto_deploy": os.getenv("VLLM_AUTO_DEPLOY", "true").lower() in ("true", "1", "yes"),
    }


def shutdown_servers():
    """Manually shut down all vLLM servers."""
    get_server_manager().shutdown_all()


def warmup_local_model(model_name: str) -> bool:
    """Pre-start vLLM server pool for a local model before workers spawn.

    Call this once on the main thread at startup. If the model is not local
    (closed-source / OpenRouter), this is a no-op.

    Returns:
        True if at least one server is ready, False if remote or all failed.
    """
    if not _is_local_model(model_name):
        print(f"  [Model] '{model_name}' -> remote API (no local GPU needed)")
        return False

    print(f"  [Model] '{model_name}' -> local model, pre-starting vLLM server pool...")
    router = get_router()
    if not router.auto_deploy or not router._server_manager:
        print(f"  [Model] vLLM auto-deploy is disabled (VLLM_AUTO_DEPLOY=false)")
        return False

    # Strip routing prefixes to get HuggingFace model path
    original = model_name
    for prefix in ["openrouter/", "vllm/", "sglang/", "local/"]:
        if original.lower().startswith(prefix):
            original = original[len(prefix):]

    success = router._server_manager.ensure_server_pool(original)
    if success:
        normalized = router._server_manager._normalize_model(original)
        instances = router._server_manager._servers.get(normalized, [])
        print(f"  [Model] vLLM server pool ready: {len(instances)} instance(s)")
        for inst in instances:
            print(f"    - {inst['url']} (GPU {inst.get('gpu_ids', '?')})")
        return True
    else:
        print(f"  [Model] vLLM server pool failed to start, will fallback to OpenRouter")
        return False


class RoutedLitellmModel:
    """
    A LitellmModel-compatible class that routes requests through ModelRouter.

    This class provides the same interface as minisweagent's LitellmModel but
    routes requests to vLLM when available, falling back to OpenRouter.
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

        # Handle both dict (vLLM raw response) and litellm response object
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
    status = check_vllm_status()
    print(f"   GPU count: {status['gpu_count']}")
    print(f"   Auto-deploy enabled: {status['auto_deploy']}")
    print(f"   Running servers: {status['running_servers']}")

    # Test routing decisions (no server start)
    print("\n2. Testing routing decisions...")
    router = get_router()

    test_models = [
        ("qwen/Qwen2.5-Coder-7B-Instruct", "Should route to vLLM (local)"),
        ("meta-llama/Llama-3.1-8B-Instruct", "Should route to vLLM (local)"),
        ("anthropic/claude-haiku-4.5", "Should route to OpenRouter (closed-source)"),
        ("openrouter/anthropic/claude-sonnet-4.5", "Should route to OpenRouter (explicit)"),
        ("deepseek-ai/DeepSeek-Coder-V2", "Should route to vLLM (local)"),
    ]

    for model, expected in test_models:
        target, formatted = router.get_routing_target(model)
        print(f"   {model}")
        print(f"      -> {target}: {formatted}")
        print(f"      Expected: {expected}")

    print("\n3. To test actual deployment, run with a local model:")
    print("   VLLM_AUTO_DEPLOY=true python -c \"")
    print("   from src.model_router import completion_with_routing")
    print("   resp = completion_with_routing('qwen/Qwen2.5-Coder-7B-Instruct', [{'role': 'user', 'content': 'Hi'}])")
    print("   print(resp)\"")

    print("\n" + "=" * 60)
    print("Dry run complete!")
    print("=" * 60)
