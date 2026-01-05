#!/usr/bin/env python3
"""Test mini-swe-agent with SWE-bench task using custom config."""

import yaml
from pathlib import Path
from minisweagent.agents.default import DefaultAgent
from minisweagent.models.litellm_model import LitellmModel
from minisweagent.environments.local import LocalEnvironment

def test_swebench_task():
    """Test with a simple SWE-bench-style task."""

    # Load config
    config_path = Path(__file__).parent / "configs" / "deepseek_swebench.yaml"
    print(f"Using config: {config_path}")

    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)

    # Create agent with config
    print("\nSetting up mini-swe-agent with DeepSeek...")

    # Extract model config
    model_config = config_data.get('model', {})
    model = LitellmModel(
        model_name=model_config.get('model_name', 'deepseek/deepseek-chat'),
        model_kwargs=model_config.get('model_kwargs', {})
    )

    # Use local environment with testbed directory
    testbed_dir = Path(__file__).parent / "test_workspace" / "testbed"
    testbed_dir.mkdir(parents=True, exist_ok=True)

    # Extract environment config
    env_config = config_data.get('environment', {})
    environment = LocalEnvironment(
        cwd=str(testbed_dir),
        timeout=env_config.get('timeout', 60),
        env=env_config.get('env', {})
    )

    # Extract agent config and create agent
    agent_config = config_data.get('agent', {})
    agent = DefaultAgent(
        model,
        environment,
        **agent_config
    )

    # Define a simple SWE-bench style task
    task = """
    # Bug Report

    There is a bug in the calculation function. The function `divide(a, b)` in `calculator.py`
    does not handle division by zero properly and raises an uncaught exception.

    ## Expected Behavior
    When dividing by zero, the function should return None and print a warning message.

    ## Current Behavior
    The function raises ZeroDivisionError without handling it.

    ## Steps to Reproduce
    1. Create a file calculator.py with a divide function
    2. Call divide(10, 0)
    3. Observe the uncaught exception

    ## Suggested Fix
    Add try-except block to handle ZeroDivisionError and return None.
    """

    print("\n" + "="*80)
    print("Task Description:")
    print("="*80)
    print(task)
    print("="*80)

    print("\nRunning agent...")
    print("This may take a few minutes...\n")

    try:
        result = agent.run(task)

        print("\n" + "="*80)
        print("Agent execution completed!")
        print("="*80)

        # Check what files were created/modified
        print("\nFiles in testbed:")
        for file in testbed_dir.glob("*"):
            if file.is_file():
                print(f"  - {file.name}")
                if file.suffix == '.py':
                    print(f"\n    Contents of {file.name}:")
                    print("    " + "-" * 60)
                    with open(file, 'r') as f:
                        for line in f:
                            print(f"    {line.rstrip()}")
                    print("    " + "-" * 60)

        return result

    except Exception as e:
        print(f"\n✗ Error during agent execution: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == '__main__':
    test_swebench_task()