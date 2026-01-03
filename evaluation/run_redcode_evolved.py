#!/usr/bin/env python3
"""
RedCode evaluation for evolved mini-swe-agent (WITH evolved tools).

Loads evolved tools from created_tools.json and makes agent aware of them.

Usage:
    # Quick test (1 case)
    python evaluation/run_redcode_evolved.py --agent_dir astropy__astropy-13977 --ids 4 --case_limit 1

    # Full dataset
    python evaluation/run_redcode_evolved.py --agent_dir astropy__astropy-13977 --ids 4

    # Dry run
    python evaluation/run_redcode_evolved.py --agent_dir astropy__astropy-13977 --ids 4 --dry_run

Results are saved to: results/evolved/{agent_name}/
"""

import argparse
import datetime
import os
import sys
import time
import json

# Add external dependencies and src to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REDCODE_EVAL = os.path.join(REPO_ROOT, "external/RedCode/evaluation")
SRC_DIR = os.path.join(REPO_ROOT, "src")

if REDCODE_EVAL not in sys.path:
    sys.path.insert(0, REDCODE_EVAL)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Import from shared core module
from redcode_eval_core import (
    load_config,
    build_agent,
    eval_dataset,
    load_evolved_tools,
    Container,
)


# ============================================================================
# Main entry point
# ============================================================================

def main():
    """Main evaluation orchestration for evolved agent."""
    parser = argparse.ArgumentParser(
        description="Evaluate tool-aware mini-swe-agent with evolved tools on RedCode benchmark"
    )
    parser.add_argument(
        '--agent_dir',
        type=str,
        required=True,
        help='Evolved agent directory name (e.g., astropy__astropy-13977)'
    )
    parser.add_argument(
        '--config_path',
        type=str,
        default=None,
        help='Path to mini-swe-agent YAML config (default: configs/minisweagent.yaml)'
    )
    parser.add_argument(
        '--ids',
        type=int,
        default=None,
        help='Single dataset ID to evaluate (1-27)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Evaluate all datasets (index 1-27)'
    )
    parser.add_argument(
        '--dry_run',
        action='store_true',
        help='Dry run mode - no actual execution'
    )
    parser.add_argument(
        '--step_limit',
        type=int,
        default=-1,
        help='Override agent step limit (<=0 keeps config value)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=-1,
        help='Override environment command timeout in seconds (<=0 keeps config value)'
    )
    parser.add_argument(
        '--case_limit',
        type=int,
        default=-1,
        help='Limit number of cases per dataset (useful for quick tests, <=0 for all)'
    )
    parser.add_argument(
        '--llm-provider',
        type=str,
        default='deepseek',
        choices=['deepseek', 'local'],
        help='LLM provider to use: "deepseek" for remote DeepSeek API (default) or "local" for local Qwen 80B server'
    )

    args = parser.parse_args()

    # Determine which datasets to evaluate
    if args.all:
        dataset_ids = list(range(1, 28))  # All 27 datasets
        print("Evaluating ALL datasets (1-27)")
    elif args.ids:
        dataset_ids = [args.ids]
        print(f"Evaluating dataset ID: {args.ids}")
    else:
        print("Error: Must specify --ids N or --all")
        sys.exit(1)

    # Load configuration based on LLM provider choice
    if args.config_path:
        config_path = args.config_path
    elif args.llm_provider == 'local':
        config_path = os.path.join(REPO_ROOT, "configs/local_qwen80b.yaml")
        print(f"Using local LLM provider (Qwen 80B)")
    else:
        config_path = os.path.join(REPO_ROOT, "configs/minisweagent.yaml")
        print(f"Using remote DeepSeek API")
    print(f"Loading config from: {config_path}")
    config = load_config(config_path)
    print("✓ Config loaded successfully")


    # Setup results directory for evolved agent evaluation
    # Save to results/evolved/{agent_name}/
    result_base = os.path.join(REPO_ROOT, f"results/evolved/{args.agent_dir}")
    os.makedirs(result_base, exist_ok=True)
    log_dir = os.path.join(result_base, "log")
    os.makedirs(log_dir, exist_ok=True)

    print(f"Results will be saved to: {result_base}")

    # RedCode dataset path
    dataset_base_path = os.path.join(REPO_ROOT, "external/RedCode/dataset/RedCode-Exec")
    image = "redcode"

    # Evaluate each dataset
    for dataset_id in dataset_ids:
        jsonfile = os.path.join(dataset_base_path, f"py2text_dataset_json/index{dataset_id}_30_codes_full.json")

        if not os.path.exists(jsonfile):
            print(f"Warning: Dataset file not found: {jsonfile}, skipping...")
            continue

        print(f"\n{'='*60}")
        print(f"Evaluating dataset {dataset_id}")
        print(f"{'='*60}\n")

        # Create NEW timestamp for each dataset (matches baseline behavior)
        time_now = datetime.datetime.now() + datetime.timedelta(hours=8)
        time_stamp = str(time_now).replace(" ", "_")
        resfile = os.path.join(result_base, f"{time_stamp}.json")
        logfile = os.path.join(log_dir, f"evolved_log_{time_stamp}.json")

        if args.dry_run:
            print("DRY RUN MODE: Skipping container and agent creation")
            print(f"Would evaluate: {jsonfile}")
            print(f"Would save results to: {resfile}")
            continue

        # Define factory functions for per-attack container/agent creation
        def create_container():
            container = Container(image)
            # Reload evolved tools into fresh container
            load_evolved_tools(args.agent_dir, container, REPO_ROOT)
            return container
        
        def create_agent(container):
            # Get tool names from evolved agent directory
            tools_json = os.path.join(REPO_ROOT, f"external/live-swe-agent/swebench_verified/claude-sonnet-4-5/{args.agent_dir}/created_tools.json")
            with open(tools_json) as f:
                tool_names = list(json.load(f).keys())
            return build_agent(config, container, args.step_limit, args.timeout, tool_names)

        # Run evaluation using factory functions (creates fresh container+agent+tools for each attack)
        print("Per-attack isolation: Fresh container + agent + tools for each of 4 attack types...")
        eval_dataset(
            dataset_id=dataset_id,
            container_factory=create_container,
            agent_factory=create_agent,
            jsonfile=jsonfile,
            resfile=resfile,
            logfile=logfile,
            result_base_dir=result_base,
            dry_run=args.dry_run,
            case_limit=args.case_limit,
        )

        print(f"\nDataset {dataset_id} complete!")


    print(f"\n{'='*60}")
    print(f"Evaluation complete!")
    print(f"Results saved to: {result_base}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()