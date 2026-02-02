#!/usr/bin/env python3
"""
RedCode evaluation script with optional skill generation.

Supports two modes for reactive/proactive skill evaluation:
- aggregate: Pool all datasets, split 50/50 globally, generate one skill from train pool
- separate: Per-dataset skill generation + evaluation with independent splits

Constitutional skills and baseline evaluation are mode-independent.

Usage:
    # Baseline evaluation only (no skill, no mode needed)
    python evaluation/run_redcode.py --split exec --dataset_ids 4
    python evaluation/run_redcode.py --split exec --dataset_ids all

    # Reactive/Proactive with aggregate mode (default)
    python evaluation/run_redcode.py --skill reactive --mode aggregate --split exec --dataset_ids 1 2 3 --n_runs 5
    python evaluation/run_redcode.py --skill proactive --mode aggregate --split all --dataset_ids all --n_runs 3

    # Reactive/Proactive with separate mode (per-dataset)
    python evaluation/run_redcode.py --skill reactive --mode separate --split exec --dataset_ids 1 2 3 --n_runs 5
    python evaluation/run_redcode.py --skill proactive --mode separate --split exec --dataset_ids 4 --n_runs 5

    # Constitutional (--mode is ignored)
    python evaluation/run_redcode.py --skill constitutional --split exec --dataset_ids all
    python evaluation/run_redcode.py --skill constitutional --filenames claudes-constitution.pdf --split exec --dataset_ids all
    python evaluation/run_redcode.py --skill constitutional --filenames nist_ai_rmf_playbook.json owaspai_general_controls.md --split exec --dataset_ids all

    # Dry run
    python evaluation/run_redcode.py --split exec --dataset_ids 4 --dry_run

Output Files (all in results/ folder):
    With skill specified:
      - results/exec_4_agent_reactive_skill_run1_model_timestamp.json  (with skill)
      - results/exec_4_agent_reactive_baseline_run1_model_timestamp.json  (baseline)
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
    filter_failed_cases_from_baseline,
    load_redcode_datasets_for_generation,
    _skill_mode_suffix,
    # Skill generation
    generate_skill_filename,
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
# Skill Checkpoint
# ============================================================================

def _check_skill_checkpoint(output_dir, skill_type, split=None, dataset_ids=None, run_idx=None, skill_mode=None):
    """Check if a skill file already exists and return its content if so.

    This avoids expensive re-generation of skills that have already been created.
    The filename is computed using the same logic as save_skill() to ensure exact match.
    """
    filename = generate_skill_filename(skill_type, split, dataset_ids, run_idx, skill_mode=skill_mode)
    skill_path = os.path.join(output_dir, filename)
    if os.path.exists(skill_path):
        with open(skill_path, "r") as f:
            content = f.read()
        if content.strip():
            print(f"  [Checkpoint] Found existing skill: {filename}")
            print(f"  [Checkpoint] Skipping skill generation (reusing cached skill)")
            return content
    return None


# ============================================================================
# Aggregated Reactive/Proactive Experiment
# ============================================================================

def _cleanup_latest_result(result_base: str, split: str, skill_type: str, run_idx: int, is_baseline: bool, skill_mode):
    """Delete the most recently created result file matching the pattern (intermediate cleanup)."""
    import glob
    mode_str = _skill_mode_suffix(skill_mode)
    pattern = os.path.join(result_base, f"{split}_*_{skill_type}-{mode_str}_{'baseline' if is_baseline else 'skill'}_run{run_idx}_*.json")
    matches = sorted(glob.glob(pattern), key=os.path.getmtime)
    if matches:
        latest = matches[-1]
        os.remove(latest)
        print(f"  [Cleanup] Deleted intermediate result: {os.path.basename(latest)}")


def run_aggregate_experiment(
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
    """Run N iterations of skill generation + evaluation with global 50/50 train/test splits.

    For each run:
    1. Load all cases from specified datasets
    2. Split each dataset 50/50 into train/test (no leakage)
    3. Aggregate train halves -> generate skill
    4. Aggregate test halves -> evaluate skill
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
    print(f"Running {n_runs} iterations of {skill_type} skill generation + evaluation (aggregate mode)")
    print(f"Split: {split}, Dataset IDs: {all_dataset_ids}")
    print("=" * 60)

    # Load all cases once
    print(f"\nLoading RedCode benchmark cases...")
    all_cases = load_redcode_datasets_for_generation(benchmark_dir, split, all_dataset_ids)

    if not all_cases:
        print("Error: No cases found")
        sys.exit(1)

    print(f"Total cases loaded: {len(all_cases)}")

    # Run N iterations
    for run_idx in range(1, n_runs + 1):
        print(f"\n{'='*60}")
        print(f"[Run {run_idx}/{n_runs}]")
        print(f"{'='*60}")

        # Split cases: 50% train, 50% test (per-dataset split, no leakage)
        seed = run_idx  # Reproducible but different each run
        train_cases, test_cases = split_cases_by_dataset(all_cases, train_ratio=0.5, seed=seed)

        print(f"  Train cases: {len(train_cases)}, Test cases: {len(test_cases)}")

        # Check for existing skill checkpoint (avoids expensive regeneration)
        cached_skill = _check_skill_checkpoint(
            output_dir, skill_type, split, all_dataset_ids,
            run_idx, skill_mode="aggregate"
        )

        if cached_skill is not None:
            skill_content = cached_skill
        elif skill_type == "reactive":
            # REACTIVE: Run baseline on train set first, then generate skill
            # from only the failed/non-refused cases (retrospection)
            print(f"\n  [Reactive] Running baseline on {len(train_cases)} train cases to identify failures...")

            def create_container():
                return Container("redcode")

            # Separate train cases by split type
            exec_train = [c for c in train_cases if c["split"] == "exec"]
            gen_train = [c for c in train_cases if c["split"] == "gen"]

            train_baseline_results = []

            if exec_train:
                exec_log = eval_exec_cases(
                    cases=exec_train,
                    config=config,  # No skill - baseline
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,
                    run_idx=run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                    skill_mode="aggregate",
                )
                train_baseline_results.extend(exec_log.get("Results", []))

                # Delete intermediate train baseline result file
                _cleanup_latest_result(result_base, "exec", skill_type, run_idx, is_baseline=True, skill_mode="aggregate")

            if gen_train:
                gen_log = eval_gen_cases(
                    cases=gen_train,
                    config=config,  # No skill - baseline
                    container_factory=create_container,
                    step_limit=step_limit,
                    timeout=timeout,
                    result_base=result_base,
                    agent_name=agent_name,
                    model_name=model_name,
                    skill_type=skill_type,
                    run_idx=run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                    skill_mode="aggregate",
                )
                train_baseline_results.extend(gen_log.get("Results", []))

                # Delete intermediate train baseline result file
                _cleanup_latest_result(result_base, "gen", skill_type, run_idx, is_baseline=True, skill_mode="aggregate")

            # Filter for failed cases only
            failed_cases = filter_failed_cases_from_baseline(train_baseline_results, train_cases)
            print(f"\n  [Reactive] Baseline failures: {len(failed_cases)}/{len(train_cases)} train cases failed (score=3 or 1)")

            if not failed_cases:
                print(f"  [Reactive] No failures found - baseline refused all train cases. Skipping skill generation.")
                print(f"  [Reactive] Still running test set evaluation for completeness...")
                skill_content = None
            else:
                skill_content = generate_skill_from_cases(
                    skill_type=skill_type,
                    cases=failed_cases,
                    split=split,
                    output_dir=output_dir,
                    dataset_ids=all_dataset_ids,
                    run_idx=run_idx,
                    model=get_model_full_name(config),
                    skill_mode="aggregate",
                )
        else:
            # PROACTIVE: Generate skill from ALL train cases (no baseline needed)
            skill_content = generate_skill_from_cases(
                skill_type=skill_type,
                cases=train_cases,
                split=split,
                output_dir=output_dir,
                dataset_ids=all_dataset_ids,
                run_idx=run_idx,
                model=get_model_full_name(config),
                skill_mode="aggregate",
            )

        # Inject skill into config (if skill was generated)
        if skill_content:
            run_config = copy.deepcopy(config)
            run_config = inject_skill_into_config(run_config, skill_content, skill_type)
        else:
            run_config = config  # No skill to inject

        def create_container():
            return Container("redcode")

        # Separate test cases by split type
        exec_test = [c for c in test_cases if c["split"] == "exec"]
        gen_test = [c for c in test_cases if c["split"] == "gen"]

        # =====================================================================
        # PART A: Evaluate WITH skill
        # =====================================================================
        print(f"\n  [A] Evaluating WITH {skill_type} skill on {len(test_cases)} test cases...")

        if exec_test:
            eval_exec_cases(
                cases=exec_test,
                config=run_config,
                container_factory=create_container,
                step_limit=step_limit,
                timeout=timeout,
                result_base=result_base,
                agent_name=agent_name,
                model_name=model_name,
                skill_type=skill_type,
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=False,
                skill_mode="aggregate",
            )

        if gen_test:
            eval_gen_cases(
                cases=gen_test,
                config=run_config,
                container_factory=create_container,
                step_limit=step_limit,
                timeout=timeout,
                result_base=result_base,
                agent_name=agent_name,
                model_name=model_name,
                skill_type=skill_type,
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=False,
                skill_mode="aggregate",
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
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=True,
                skill_mode="aggregate",
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
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=True,
                skill_mode="aggregate",
            )

        print(f"\n[Run {run_idx}/{n_runs}] Complete! (with skill + baseline)")

    print(f"\n{'='*60}")
    print(f"All {n_runs} runs complete!")
    print(f"Results saved to: {result_base}")
    print(f"  - Each run generates TWO result files:")
    print(f"    - *_{skill_type}_run*.json (with skill)")
    print(f"    - *_{skill_type}_baseline_run*.json (baseline comparison)")
    print(f"{'='*60}\n")


# ============================================================================
# Separated (Per-Dataset) Reactive/Proactive Experiment
# ============================================================================

def run_separate_experiment(
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
    print(f"Per-dataset {skill_type} skill generation + evaluation (separate mode)")
    print(f"Split: {split}, Datasets: {all_dataset_ids}, Runs: {n_runs}")
    print("=" * 60)

    start_time = time.time()

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
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[{iteration}/{total_iterations}] Dataset: {dataset_id}, Run: {local_run_idx}/{n_runs}")
            print(f"{'='*60}")

            print(f"  Loaded {len(cases)} cases")

            # Split 50/50 with seed based on both dataset_id and local_run_idx
            # Use hashlib for deterministic hashing (Python's hash() is randomized by default)
            dataset_hash = int(hashlib.md5(str(dataset_id).encode()).hexdigest(), 16)
            seed = (dataset_hash + local_run_idx) % (2**31)
            train_cases, test_cases = split_cases_by_dataset(cases, train_ratio=0.5, seed=seed)

            print(f"  Train: {len(train_cases)} cases, Test: {len(test_cases)} cases")

            # Check for existing skill checkpoint (avoids expensive regeneration)
            cached_skill = _check_skill_checkpoint(
                output_dir, skill_type, dataset_split, [dataset_id],
                local_run_idx, skill_mode="separate"
            )

            if cached_skill is not None:
                skill_content = cached_skill
            elif skill_type == "reactive":
                # REACTIVE: Run baseline on train set first, then use only failed cases
                print(f"\n  [Reactive] Running baseline on {len(train_cases)} train cases to identify failures...")

                def create_container():
                    return Container("redcode")

                exec_train = [c for c in train_cases if c["split"] == "exec"]
                gen_train = [c for c in train_cases if c["split"] == "gen"]

                train_baseline_results = []

                if exec_train:
                    exec_log = eval_exec_cases(
                        cases=exec_train,
                        config=config,
                        container_factory=create_container,
                        step_limit=step_limit,
                        timeout=timeout,
                        result_base=result_base,
                        agent_name=agent_name,
                        model_name=model_name,
                        skill_type=skill_type,
                        run_idx=local_run_idx,
                        dry_run=dry_run,
                        agent_type=agent_type,
                        is_baseline=True,
                        skill_mode="separate",
                    )
                    train_baseline_results.extend(exec_log.get("Results", []))
                    _cleanup_latest_result(result_base, "exec", skill_type, local_run_idx, is_baseline=True, skill_mode="separate")

                if gen_train:
                    gen_log = eval_gen_cases(
                        cases=gen_train,
                        config=config,
                        container_factory=create_container,
                        step_limit=step_limit,
                        timeout=timeout,
                        result_base=result_base,
                        agent_name=agent_name,
                        model_name=model_name,
                        skill_type=skill_type,
                        run_idx=local_run_idx,
                        dry_run=dry_run,
                        agent_type=agent_type,
                        is_baseline=True,
                        skill_mode="separate",
                    )
                    train_baseline_results.extend(gen_log.get("Results", []))
                    _cleanup_latest_result(result_base, "gen", skill_type, local_run_idx, is_baseline=True, skill_mode="separate")

                failed_cases = filter_failed_cases_from_baseline(train_baseline_results, train_cases)
                print(f"\n  [Reactive] Baseline failures: {len(failed_cases)}/{len(train_cases)} train cases failed")

                if not failed_cases:
                    print(f"  [Reactive] No failures found - skipping skill generation.")
                    skill_content = None
                else:
                    skill_content = generate_skill_from_cases(
                        skill_type=skill_type,
                        cases=failed_cases,
                        split=dataset_split,
                        output_dir=output_dir,
                        dataset_ids=[dataset_id],
                        run_idx=local_run_idx,
                        model=get_model_full_name(config),
                        skill_mode="separate",
                    )
            else:
                # PROACTIVE: use all train cases
                skill_content = generate_skill_from_cases(
                    skill_type=skill_type,
                    cases=train_cases,
                    split=dataset_split,
                    output_dir=output_dir,
                    dataset_ids=[dataset_id],
                    run_idx=local_run_idx,
                    model=get_model_full_name(config),
                    skill_mode="separate",
                )

            # Inject skill into config (if skill was generated)
            if skill_content:
                dataset_config = copy.deepcopy(config)
                dataset_config = inject_skill_into_config(dataset_config, skill_content, skill_type)
            else:
                dataset_config = config

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
                    run_idx=local_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=False,
                    skill_mode="separate",
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
                    run_idx=local_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=False,
                    skill_mode="separate",
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
                    run_idx=local_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                    skill_mode="separate",
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
                    run_idx=local_run_idx,
                    dry_run=dry_run,
                    agent_type=agent_type,
                    is_baseline=True,
                    skill_mode="separate",
                )

            print(f"\n  Run {local_run_idx}/{n_runs} for dataset {dataset_id} complete! (with skill + baseline)")

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
        description="RedCode evaluation with skill generation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Reactive/Proactive with aggregate mode (pool all datasets)
  python evaluation/run_redcode.py --skill reactive --mode aggregate --split exec --dataset_ids 1 2 3 --n_runs 5

  # Reactive/Proactive with separate mode (per-dataset)
  python evaluation/run_redcode.py --skill reactive --mode separate --split exec --dataset_ids 1 2 3 --n_runs 5
  python evaluation/run_redcode.py --skill proactive --mode separate --split all --dataset_ids all --n_runs 3

  # Constitutional (--mode specifies safety standard filenames)
  python evaluation/run_redcode.py --skill constitutional --mode all --split exec --dataset_ids all
  python evaluation/run_redcode.py --skill constitutional --mode owaspai_general_controls.md --split exec --dataset_ids all
  python evaluation/run_redcode.py --skill constitutional --mode owaspai_general_controls.md nist_ai_rmf_playbook.json --split exec --dataset_ids all --n_runs 3

Output:
  Each run generates TWO result files: skill + baseline comparison
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
        '--skill', type=str, choices=SKILL_TYPES, required=True,
        help='Skill type to generate and evaluate (required)'
    )
    parser.add_argument(
        '--mode', type=str, nargs='+', default=None,
        help='Skill mode. For reactive/proactive: "aggregate" or "separate". '
             'For constitutional: safety standard filenames or "all". '
             'Default: "aggregate" for reactive/proactive, "all" for constitutional.'
    )
    parser.add_argument(
        '--split', type=str, choices=['exec', 'gen', 'all'], default='exec',
        help='Dataset split to evaluate'
    )
    parser.add_argument(
        '--dataset_ids', type=str, nargs='+', required=True,
        help='Dataset IDs: 1-27 for exec, category names for gen, or "all" for all datasets'
    )
    parser.add_argument(
        '--n_runs', type=int, default=1,
        help='Number of runs (default: 1). For reactive/proactive: different train/test splits. For constitutional: repeated generation + evaluation.'
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

    # ================================================================
    # Validate and compute skill_mode
    # ================================================================
    if args.skill in ('reactive', 'proactive'):
        # Default to aggregate
        mode_raw = args.mode or ['aggregate']
        if len(mode_raw) != 1 or mode_raw[0] not in ('aggregate', 'separate'):
            parser.error("--mode must be 'aggregate' or 'separate' for reactive/proactive skills")
        skill_mode = mode_raw[0]  # str: "aggregate" or "separate"
    else:
        # Constitutional: mode is the list of filenames
        skill_mode = args.mode or ['all']  # list: ["all"] or ["owaspai.md", ...]

    # Check if "all" was specified
    all_datasets = 'all' in args.dataset_ids
    dataset_ids = None if all_datasets else args.dataset_ids

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
    print(f"Model: {model_name}")
    print(f"Skill: {args.skill}, Mode: {skill_mode}\n")

    # ================================================================
    # Route based on skill type
    # ================================================================
    if args.skill in ('reactive', 'proactive'):
        experiment_fn = run_aggregate_experiment if skill_mode == 'aggregate' else run_separate_experiment
        experiment_fn(
            skill_type=args.skill,
            split=args.split,
            dataset_ids=dataset_ids,
            all_datasets=all_datasets,
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
        # Constitutional: generate skill from safety standards, evaluate on all data
        # Supports n_runs for repeated generation + evaluation
        output_dir = os.path.join(REPO_ROOT, "security-skills")

        for run_idx in range(1, args.n_runs + 1):
            if args.n_runs > 1:
                print(f"\n{'='*60}")
                print(f"[Run {run_idx}/{args.n_runs}]")
                print(f"{'='*60}")

            cached_skill = _check_skill_checkpoint(output_dir, args.skill, run_idx=run_idx, skill_mode=skill_mode)
            if cached_skill is not None:
                skill_content = cached_skill
            else:
                skill_content = generate_skill(args.skill, args.split, dataset_ids, model=get_model_full_name(config), skill_mode=skill_mode, run_idx=run_idx)

            print("=" * 60)
            print(f"Running RedCode evaluation WITH constitutional skill (run {run_idx})")
            print("=" * 60 + "\n")

            run_evaluation(
                config=config,
                skill_type=args.skill,
                skill_content=skill_content,
                split=args.split,
                dataset_ids=dataset_ids,
                all_datasets=all_datasets,
                dry_run=args.dry_run,
                step_limit=args.step_limit,
                timeout=args.timeout,
                agent_name=agent_name,
                model_name=model_name,
                agent_type=args.agent,
                skill_mode=skill_mode,
                run_idx=run_idx,
            )

            print("=" * 60)
            print(f"Running BASELINE evaluation (no skill) for comparison (run {run_idx})")
            print("=" * 60 + "\n")

            run_evaluation(
                config=config,
                skill_type=args.skill,
                skill_content=None,  # No skill injection = baseline
                split=args.split,
                dataset_ids=dataset_ids,
                all_datasets=all_datasets,
                dry_run=args.dry_run,
                step_limit=args.step_limit,
                timeout=args.timeout,
                agent_name=agent_name,
                model_name=model_name,
                agent_type=args.agent,
                skill_mode=skill_mode,
                run_idx=run_idx,
            )


if __name__ == "__main__":
    main()
