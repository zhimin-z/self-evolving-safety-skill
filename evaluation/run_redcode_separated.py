#!/usr/bin/env python3
"""
RedCode evaluation script with optional skill generation (SEPARATED mode).

**Key Behavior:**
- If --skill is specified: generates TWO result files per evaluation
  - One WITH skill applied
  - One WITHOUT skill (baseline) for comparison on the same test cases
- If --skill is omitted: runs baseline evaluation only (single result file)

For reactive/proactive skills: per-dataset skill generation + evaluation.
  - For each dataset: split 50/50, train skill on first half, evaluate on second half
  - Use --n_runs to run multiple iterations per dataset with different random splits
  - Results are aggregated across all datasets and runs at the end

For constitutional skills: single generation from safety standards (no split).

Usage:
    # Baseline evaluation only (no skill, single result file)
    python evaluation/run_redcode_separated.py --split exec --dataset_ids 4
    python evaluation/run_redcode_separated.py --split exec --all

    # With skill: generates BOTH skill and baseline results for comparison
    python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 1 2 3
    python evaluation/run_redcode_separated.py --skill proactive --split all --all

    # Reactive/Proactive: multiple runs per dataset
    python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 4 --n_runs 5

    # Constitutional: generates BOTH skill and baseline results
    python evaluation/run_redcode_separated.py --skill constitutional --split exec --all

    # Dry run
    python evaluation/run_redcode_separated.py --split exec --dataset_ids 4 --dry_run

Output Files (all in results/ folder):
    With skill specified:
      - results/exec_4_agent_reactive_runs5_model_timestamp.json  (with skill)
      - results/exec_4_agent_reactive_baseline_runs5_model_timestamp.json  (baseline)
    Without skill:
      - results/exec_4_agent_baseline_model_timestamp.json
"""

import argparse
import copy
import hashlib
import os
import sys
import time

# ============================================================================
# Path setup
# ============================================================================

_SCRIPT_DIR = os.path.dirname(__file__)
_SRC_DIR = os.path.abspath(os.path.join(_SCRIPT_DIR, "..", "src"))

if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

# Import all shared functionality from core module
from redcode_eval_core import (
    # Constants
    REPO_ROOT,
    SKILL_TYPES,
    AGENT_CONFIGS,
    # Utilities
    load_config,
    get_model_full_name,
    get_model_short_name,
    get_agent_name,
    get_exec_dataset_ids,
    get_gen_dataset_ids,
    split_cases_by_dataset,
    load_redcode_datasets_for_generation,
    # Skill generation
    generate_skill_from_cases,
    inject_skill_into_config,
    # Evaluation
    eval_exec_cases,
    eval_gen_cases,
    generate_skill,
    run_evaluation,
    Container,
)


# ============================================================================
# Per-Dataset Reactive/Proactive Experiment (unique to this script)
# ============================================================================

def run_reactive_proactive_experiment(
    skill_type: str,
    split: str,
    dataset_ids: list,
    all_datasets: bool,
    n_runs: int,
    config: dict,
    step_limit: int,
    timeout: int,
    agent_name: str,
    model_name: str,
    dry_run: bool,
    agent_type: str = "mini",
):
    """Per-dataset skill generation + evaluation with 50/50 train/test splits.

    For each dataset_id:
      For each run (1 to n_runs):
        1. Split that dataset 50/50 with run-specific seed
        2. Generate skill from train half
        3. Evaluate skill on test half immediately
        4. Save results per run with successive run indices

    Uses eval_exec_cases/eval_gen_cases from core module for consistent evaluation.
    """
    benchmark_dir = os.path.join(REPO_ROOT, "external/RedCode/dataset")
    output_dir = os.path.join(REPO_ROOT, "security-skills")
    result_base = os.path.join(REPO_ROOT, "results")
    os.makedirs(result_base, exist_ok=True)

    # Determine which datasets to process
    exec_ids = []
    gen_ids = []

    if split in ('exec', 'all'):
        exec_ids = get_exec_dataset_ids(dataset_ids, all_datasets)
    if split in ('gen', 'all'):
        gen_ids = get_gen_dataset_ids(dataset_ids, all_datasets)

    all_dataset_ids = exec_ids + gen_ids

    if not all_dataset_ids:
        print("Error: No valid dataset IDs to evaluate")
        sys.exit(1)

    print("=" * 60)
    print(f"Per-dataset {skill_type} skill generation + evaluation")
    print(f"Split: {split}, Datasets: {all_dataset_ids}, Runs: {n_runs}")
    print("=" * 60)

    start_time = time.time()

    # Track global run index across all datasets for successive numbering
    global_run_idx = 0

    total_iterations = len(all_dataset_ids) * n_runs
    iteration = 0

    for dataset_id in all_dataset_ids:
        # Determine if this is exec or gen
        is_exec = dataset_id in exec_ids

        # Load cases for this dataset only (once per dataset)
        dataset_split = "exec" if is_exec else "gen"
        cases = load_redcode_datasets_for_generation(benchmark_dir, dataset_split, [dataset_id])

        if not cases:
            print(f"  Warning: No cases found for dataset {dataset_id}, skipping...")
            continue

        for local_run_idx in range(1, n_runs + 1):
            global_run_idx += 1
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[{iteration}/{total_iterations}] Dataset: {dataset_id}, Run: {global_run_idx}")
            print(f"{'='*60}")

            print(f"  Loaded {len(cases)} cases")

            # Split 50/50 with seed based on both dataset_id and local_run_idx
            # Use hashlib for deterministic hashing (Python's hash() is randomized by default)
            dataset_hash = int(hashlib.md5(str(dataset_id).encode()).hexdigest(), 16)
            seed = (dataset_hash + local_run_idx) % (2**31)
            train_cases, test_cases = split_cases_by_dataset(cases, train_ratio=0.5, seed=seed)

            print(f"  Train: {len(train_cases)} cases, Test: {len(test_cases)} cases")

            # Generate skill from train half
            skill_content = generate_skill_from_cases(
                skill_type=skill_type,
                cases=train_cases,
                split=dataset_split,
                output_dir=output_dir,
                dataset_ids=[dataset_id],
                run_idx=global_run_idx,
                model=get_model_full_name(config),
            )

            # Inject skill into config
            dataset_config = copy.deepcopy(config)
            dataset_config = inject_skill_into_config(dataset_config, skill_content, skill_type)

            def create_container():
                return Container("redcode")

            # Separate test cases by split type (all should be same type here)
            exec_test = [c for c in test_cases if c["split"] == "exec"]
            gen_test = [c for c in test_cases if c["split"] == "gen"]

            # =====================================================================
            # PART A: Evaluate WITH skill
            # =====================================================================
            print(f"\n  [A] Evaluating WITH {skill_type} skill on {len(test_cases)} test cases...")

            if exec_test:
                eval_exec_cases(
                    cases=exec_test,
                    config=dataset_config,
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,
                    run_idx=global_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=False,
                )

            if gen_test:
                eval_gen_cases(
                    cases=gen_test,
                    config=dataset_config,
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,
                    run_idx=global_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=False,
                )

            # =====================================================================
            # PART B: Evaluate baseline (no skill) on same test cases for comparison
            # =====================================================================
            print(f"\n  [B] Evaluating BASELINE (no skill) on same {len(test_cases)} test cases...")

            if exec_test:
                eval_exec_cases(
                    cases=exec_test,
                    config=config,  # Original config WITHOUT skill injection
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,  # Keep skill_type for context in filename
                    run_idx=global_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                )

            if gen_test:
                eval_gen_cases(
                    cases=gen_test,
                    config=config,  # Original config WITHOUT skill injection
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,  # Keep skill_type for context in filename
                    run_idx=global_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                )

            print(f"\n  Run {global_run_idx} complete! (with skill + baseline)")

    total_duration = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"All {total_iterations} runs complete!")
    print(f"Total duration: {total_duration:.1f}s")
    print(f"Results saved to: {result_base}")
    print(f"  - Each run generates TWO result files:")
    print(f"    - *_{skill_type}_run*.json (with skill)")
    print(f"    - *_{skill_type}_baseline_run*.json (baseline comparison)")
    print(f"{'='*60}\n")


# ============================================================================
# Main
# ============================================================================

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="RedCode evaluation with optional skill generation (separated mode)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Baseline evaluation only (no skill, single result file)
  python evaluation/run_redcode_separated.py --split exec --dataset_ids 4

  # With skill: generates BOTH skill and baseline results for comparison
  python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 1 2 3
  python evaluation/run_redcode_separated.py --skill proactive --split all --all

  # Reactive/Proactive: multiple runs per dataset
  python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 4 --n_runs 5

  # Constitutional: generates BOTH skill and baseline results
  python evaluation/run_redcode_separated.py --skill constitutional --split exec --all

Output:
  With --skill: TWO files per evaluation (skill + baseline on same test cases)
  Without --skill: ONE file (baseline only)
"""
    )

    parser.add_argument(
        '--agent', type=str, choices=list(AGENT_CONFIGS.keys()), default='mini',
        help='Agent to use for evaluation (default: mini)'
    )
    parser.add_argument(
        '--model', type=str, default=None,
        help='Model to use (e.g., anthropic/anthropic/claude-haiku-4.5). Overrides config file.'
    )
    parser.add_argument(
        '--config_path', type=str, default=None,
        help='Path to agent YAML config (overrides --agent)'
    )
    parser.add_argument(
        '--skill', type=str, choices=SKILL_TYPES, default=None,
        help='Skill type to generate and evaluate with (omit for baseline)'
    )
    parser.add_argument(
        '--split', type=str, choices=['exec', 'gen', 'all'], default='exec',
        help='Dataset split to evaluate'
    )
    parser.add_argument(
        '--dataset_ids', type=str, nargs='+', default=None,
        help='Dataset IDs: 1-27 for exec, category names for gen'
    )
    parser.add_argument(
        '--all', action='store_true',
        help='Evaluate all datasets in the specified split'
    )
    parser.add_argument(
        '--n_runs', type=int, default=1,
        help='Number of random train/test splits per dataset for reactive/proactive (default: 1)'
    )
    parser.add_argument(
        '--dry_run', action='store_true',
        help='Dry run mode - no actual execution'
    )
    parser.add_argument(
        '--step_limit', type=int, default=-1,
        help='Override agent step limit'
    )
    parser.add_argument(
        '--timeout', type=int, default=-1,
        help='Override command timeout in seconds'
    )

    args = parser.parse_args()

    # Validate arguments
    if not args.all and not args.dataset_ids:
        print("Error: Must specify --dataset_ids or --all")
        sys.exit(1)

    # Load config
    config_path = args.config_path or os.path.join(REPO_ROOT, AGENT_CONFIGS[args.agent])
    print(f"Loading config from: {config_path}")
    config = load_config(config_path)
    print("Config loaded successfully")

    # Override model if specified
    if args.model:
        if "model" not in config:
            config["model"] = {}
        config["model"]["model_name"] = args.model
        print(f"Model override: {args.model}")

    agent_name = get_agent_name(config_path)
    model_name = get_model_short_name(config)
    print(f"Agent: {agent_name}")
    print(f"Model: {model_name}\n")

    # Route based on skill type
    if args.skill in ('reactive', 'proactive'):
        # Reactive/Proactive: per-dataset skill generation + evaluation
        run_reactive_proactive_experiment(
            skill_type=args.skill,
            split=args.split,
            dataset_ids=args.dataset_ids,
            all_datasets=args.all,
            n_runs=args.n_runs,
            config=config,
            step_limit=args.step_limit,
            timeout=args.timeout,
            agent_name=agent_name,
            model_name=model_name,
            dry_run=args.dry_run,
            agent_type=args.agent,
        )

    elif args.skill == 'constitutional':
        # Constitutional: single generation from safety standards, then evaluate on all data
        skill_content = generate_skill(args.skill, args.split, args.dataset_ids, model=get_model_full_name(config))

        print("=" * 60)
        print("[2/3] Running RedCode evaluation WITH constitutional skill")
        print("=" * 60 + "\n")

        run_evaluation(
            config=config,
            skill_type=args.skill,
            skill_content=skill_content,
            split=args.split,
            dataset_ids=args.dataset_ids,
            all_datasets=args.all,
            dry_run=args.dry_run,
            step_limit=args.step_limit,
            timeout=args.timeout,
            agent_name=agent_name,
            model_name=model_name,
            agent_type=args.agent,
        )

        print("=" * 60)
        print("[3/3] Running BASELINE evaluation (no skill) for comparison")
        print("=" * 60 + "\n")

        run_evaluation(
            config=config,
            skill_type=args.skill,  # Keep skill_type for context in filename
            skill_content=None,  # No skill injection = baseline
            split=args.split,
            dataset_ids=args.dataset_ids,
            all_datasets=args.all,
            dry_run=args.dry_run,
            step_limit=args.step_limit,
            timeout=args.timeout,
            agent_name=agent_name,
            model_name=model_name,
            agent_type=args.agent,
        )

    else:
        # Baseline: no skill, just evaluate
        print("=" * 60)
        print("Running baseline RedCode evaluation (no skill)")
        print("=" * 60 + "\n")

        run_evaluation(
            config=config,
            skill_type=None,
            skill_content=None,
            split=args.split,
            dataset_ids=args.dataset_ids,
            all_datasets=args.all,
            dry_run=args.dry_run,
            step_limit=args.step_limit,
            timeout=args.timeout,
            agent_name=agent_name,
            model_name=model_name,
            agent_type=args.agent,
        )


if __name__ == "__main__":
    main()
