#!/usr/bin/env python3
import os
os.environ.setdefault("VLLM_DISABLE_CUDNN_CHECK", "1")
"""
RedCode evaluation script with optional skill generation.

The --mode flag is the variant selector for all skill types:
- reactive/proactive/fusion: "aggregate" or "separate"
- constitutional: safety standard filenames or "all" (default, expands to all standards)

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

    # Constitutional (--mode selects safety standards; default "all")
    python evaluation/run_redcode.py --skill constitutional --split exec --dataset_ids all
    python evaluation/run_redcode.py --skill constitutional --mode owaspai_general_controls.md --split exec --dataset_ids all
    python evaluation/run_redcode.py --skill constitutional --mode nist_ai_rmf_playbook.json owaspai_general_controls.md --split exec --dataset_ids all

    # Fusion (reuses existing base skill + constitutional skill files, fuses and evaluates)
    python evaluation/run_redcode.py --skill fusion --fusion_base reactive --mode aggregate --split exec --dataset_ids all
    python evaluation/run_redcode.py --skill fusion --fusion_base proactive --mode separate --fusion_std owaspai_general_controls.md --split exec --dataset_ids 1 2 3

    # Dry run
    python evaluation/run_redcode.py --split exec --dataset_ids 4 --dry_run
"""

import argparse
import copy
import hashlib
import json
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
from container import cleanup_stale_containers
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
    resolve_constitutional_mode,
    get_available_gpus,
    warmup_local_model,
    # Skill generation
    generate_skill_filename,
    generate_result_filename,
    generate_skill_from_cases,
    inject_skill_into_config,
    save_skill,
    # Fusion
    fuse_skills,
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

def _check_skill_checkpoint(output_dir, skill_type, split=None, dataset_ids=None, run_idx=None, skill_mode=None, model_name="", agent_type=""):
    """Check if a skill file already exists and return its content if so.

    This avoids expensive re-generation of skills that have already been created.
    The filename is computed using the same logic as save_skill() to ensure exact match.
    """
    filename = generate_skill_filename(skill_type, split, dataset_ids, run_idx, skill_mode=skill_mode, model_name=model_name, agent_type=agent_type)
    skill_path = os.path.join(output_dir, filename)
    if os.path.exists(skill_path):
        with open(skill_path, "r") as f:
            content = f.read()
        if content.strip():
            print(f"  [Checkpoint] Found existing skill: {filename}")
            print(f"  [Checkpoint] Skipping skill generation (reusing cached skill)")
            return content
    return None


def _result_exists(result_base, split, dataset_ids, agent_name, model_name,
                    skill_type, run_idx, is_baseline, skill_mode, agent_type):
    """Silently check if a final result JSON already exists."""
    result_filename = generate_result_filename(
        split, dataset_ids, agent_name, model_name, skill_type, run_idx,
        is_baseline=is_baseline, skill_mode=skill_mode, agent_type=agent_type
    )
    return os.path.exists(os.path.join(result_base, result_filename))


def _check_result_checkpoint(result_base, split, dataset_ids, agent_name, model_name,
                              skill_type, run_idx, is_baseline, skill_mode, agent_type):
    """Check if a final result JSON already exists for this evaluation.

    Returns (True, filename) if the result file exists and the evaluation
    should be skipped, or (False, filename) otherwise.
    """
    result_filename = generate_result_filename(
        split, dataset_ids, agent_name, model_name, skill_type, run_idx,
        is_baseline=is_baseline, skill_mode=skill_mode, agent_type=agent_type
    )
    result_path = os.path.join(result_base, result_filename)
    if os.path.exists(result_path):
        return True, result_filename
    return False, result_filename


def _all_results_exist(result_base, exec_ids, gen_ids, agent_name, model_name,
                        skill_type, run_idx, skill_mode, agent_type):
    """Check if ALL per-dataset result files (both skill and baseline) exist for a run.

    Returns True if every expected result file exists, meaning the entire run
    (including training/skill generation) can be skipped.
    """
    for did in exec_ids:
        for is_baseline in (False, True):
            if not _result_exists(result_base, "exec", did, agent_name, model_name,
                                  skill_type, run_idx, is_baseline, skill_mode, agent_type):
                return False
    for did in gen_ids:
        for is_baseline in (False, True):
            if not _result_exists(result_base, "gen", did, agent_name, model_name,
                                  skill_type, run_idx, is_baseline, skill_mode, agent_type):
                return False
    return True


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


def _derive_training_cases_from_results(
    benchmark_dir: str,
    split: str,
    dataset_ids: list,
    result_base: str,
    agent_name: str,
    model_name: str,
    skill_type: str,
    run_idx: int,
    skill_mode,
    agent_type: str,
) -> list:
    """Reconstruct training cases by excluding test case IDs found in result JSONs.

    For each dataset_id, loads the result JSON (skill, not baseline) to find
    which test case IDs were used for evaluation. All other cases become the
    training set.

    Returns:
        List of case dicts suitable for generate_skill_from_cases().
    """
    all_cases = load_redcode_datasets_for_generation(benchmark_dir, split, dataset_ids)
    if not all_cases:
        print("  Warning: No cases loaded from benchmark")
        return []

    # Build exclusion set per dataset: {dataset_id -> set of test case IDs}
    # Test Case IDs are int for exec (e.g. [2, 3, 5]) and str for gen (e.g. ["script_name"])
    exclude_by_dataset = {}  # dataset_id (str) -> set of test case IDs

    for did in dataset_ids:
        result_filename = generate_result_filename(
            split, did, agent_name, model_name, skill_type, run_idx,
            is_baseline=False, skill_mode=skill_mode, agent_type=agent_type,
        )
        result_path = os.path.join(result_base, result_filename)

        if not os.path.exists(result_path):
            print(f"  Warning: Result file not found: {result_filename}")
            print(f"    Including ALL cases from dataset {did} in training set")
            continue

        with open(result_path, "r") as f:
            data = json.load(f)

        test_case_ids = data.get("Test Case IDs", [])
        dataset_id = str(data.get("Dataset ID", did))
        exclude_by_dataset[dataset_id] = set(test_case_ids)

    def _is_test_case(case):
        """Check if a case is in the test set (should be excluded from training)."""
        did = str(case["dataset_id"])
        if did not in exclude_by_dataset:
            return False  # No result file found; include in training
        test_ids = exclude_by_dataset[did]
        if case["split"] == "exec":
            # case['index'] is like "10_2"; test case ID is int 2
            case_num = case["index"].rsplit("_", 1)[-1]
            try:
                return int(case_num) in test_ids
            except ValueError:
                return case_num in test_ids
        else:
            # gen: case['index'] is filename stem; test case ID is same string
            return case["index"] in test_ids

    # Filter: keep cases NOT in the test set
    training_cases = [c for c in all_cases if not _is_test_case(c)]

    print(f"  Derived training set: {len(training_cases)} cases "
          f"(excluded {len(all_cases) - len(training_cases)} test cases from {len(all_cases)} total)")
    return training_cases


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
    output_dir = os.path.join(REPO_ROOT, "skills")
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

        # Early skip: if ALL per-dataset results (skill + baseline) already exist, skip entire run
        if _all_results_exist(result_base, exec_ids, gen_ids, agent_name, model_name,
                              skill_type, run_idx, skill_mode="aggregate", agent_type=agent_type):
            print(f"  [Checkpoint] All results exist for run {run_idx}, skipping entire run (incl. training)")
            continue

        # Split cases: 50% train, 50% test (per-dataset split, no leakage)
        seed = run_idx  # Reproducible but different each run
        train_cases, test_cases = split_cases_by_dataset(all_cases, train_ratio=0.5, seed=seed)

        print(f"  Train cases: {len(train_cases)}, Test cases: {len(test_cases)}")

        # Check for existing skill checkpoint (avoids expensive regeneration)
        cached_skill = _check_skill_checkpoint(
            output_dir, skill_type, split, all_dataset_ids,
            run_idx, skill_mode="aggregate", model_name=model_name, agent_type=agent_type
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
                    agent_type=agent_type,
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
                agent_type=agent_type,
            )

        # Inject skill into config (if skill was generated)
        if skill_content:
            run_config = copy.deepcopy(config)
            run_config = inject_skill_into_config(run_config, skill_content, skill_type)
        else:
            run_config = config  # No skill to inject

        def create_container():
            return Container("redcode")

        # Group test cases by dataset for per-dataset interleaving
        from collections import defaultdict
        exec_by_dataset = defaultdict(list)
        for c in [c for c in test_cases if c["split"] == "exec"]:
            exec_by_dataset[c["dataset_id"]].append(c)
        gen_by_dataset = defaultdict(list)
        for c in [c for c in test_cases if c["split"] == "gen"]:
            gen_by_dataset[c["dataset_id"]].append(c)

        # Per-dataset interleaving: skill then baseline for each dataset
        for dataset_id in sorted(exec_by_dataset.keys()):
            ds_cases = exec_by_dataset[dataset_id]

            if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=False, skill_mode="aggregate", agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH {skill_type} skill on exec dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_exec_cases(
                    cases=ds_cases,
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

            if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=True, skill_mode="aggregate", agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on exec dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_exec_cases(
                    cases=ds_cases,
                    config=config,
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

        for dataset_id in sorted(gen_by_dataset.keys()):
            ds_cases = gen_by_dataset[dataset_id]

            if not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=False, skill_mode="aggregate", agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH {skill_type} skill on gen dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_gen_cases(
                    cases=ds_cases,
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

            if not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=True, skill_mode="aggregate", agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on gen dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_gen_cases(
                    cases=ds_cases,
                    config=config,
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
    output_dir = os.path.join(REPO_ROOT, "skills")
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

            # Early skip: if both skill and baseline results exist, skip entire iteration
            skill_done = _result_exists(result_base, dataset_split, dataset_id, agent_name, model_name,
                                        skill_type, local_run_idx, is_baseline=False, skill_mode="separate", agent_type=agent_type)
            baseline_done = _result_exists(result_base, dataset_split, dataset_id, agent_name, model_name,
                                           skill_type, local_run_idx, is_baseline=True, skill_mode="separate", agent_type=agent_type)
            if skill_done and baseline_done:
                print(f"  [Checkpoint] All results exist for dataset {dataset_id} run {local_run_idx}, skipping entire iteration (incl. training)")
                continue
            print(f"{'='*60}")

            print(f"  Loaded {len(cases)} cases")

            # Split 50/50 with seed based on both dataset_id and local_run_idx
            # Use hashlib for deterministic hashing (Python's hash() is randomized by default)
            dataset_hash = int(hashlib.md5(str(dataset_id).encode()).hexdigest(), 16)
            seed = (dataset_hash + local_run_idx) % (2**31)
            train_cases, test_cases = split_cases_by_dataset(cases, train_ratio=0.5, seed=seed)

            print(f"  Train: {len(train_cases)} cases, Test: {len(test_cases)} cases")

            skill_result_exists, skill_result_name = _check_result_checkpoint(
                result_base=result_base,
                split=dataset_split,
                dataset_ids=[dataset_id],
                agent_name=agent_name,
                model_name=model_name,
                skill_type=skill_type,
                run_idx=local_run_idx,
                is_baseline=False,
                skill_mode="separate",
                agent_type=agent_type,
            )
            baseline_result_exists, baseline_result_name = _check_result_checkpoint(
                result_base=result_base,
                split=dataset_split,
                dataset_ids=[dataset_id],
                agent_name=agent_name,
                model_name=model_name,
                skill_type=skill_type,
                run_idx=local_run_idx,
                is_baseline=True,
                skill_mode="separate",
                agent_type=agent_type,
            )

            if skill_result_exists:
                print(f"  [Checkpoint] Found existing WITH-skill result: {skill_result_name} (skip part A + skill generation)")
            if baseline_result_exists:
                print(f"  [Checkpoint] Found existing BASELINE result: {baseline_result_name} (skip part B)")
            if skill_result_exists and baseline_result_exists:
                print("  [Checkpoint] Both results exist; skipping this dataset/run")
                continue

            # Check for existing skill checkpoint (avoids expensive regeneration)
            cached_skill = None if skill_result_exists else _check_skill_checkpoint(
                output_dir, skill_type, dataset_split, [dataset_id],
                local_run_idx, skill_mode="separate", model_name=model_name, agent_type=agent_type
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
                        agent_type=agent_type,
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
                    agent_type=agent_type,
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
            if exec_test and not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                          skill_type, local_run_idx, is_baseline=False, skill_mode="separate", agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH {skill_type} skill on {len(exec_test)} exec test cases...")
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

            if gen_test and not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                                         skill_type, local_run_idx, is_baseline=False, skill_mode="separate", agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH {skill_type} skill on {len(gen_test)} gen test cases...")
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
            if exec_test and not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                          skill_type, local_run_idx, is_baseline=True, skill_mode="separate", agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE (no skill) on {len(exec_test)} exec test cases...")
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

            if gen_test and not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                                         skill_type, local_run_idx, is_baseline=True, skill_mode="separate", agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE (no skill) on {len(gen_test)} gen test cases...")
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
# Fusion Experiment (reuses existing skill files, fuses, evaluates)
# ============================================================================

def _fusion_skill_mode(fusion_base: str, base_mode: str, fusion_std: list) -> str:
    """Build a compound skill_mode string for fusion filenames.

    Format: {fusion_base}.{aggregate|separate}.{std1-std2-...}
    Uses '.' to separate structural parts from the '-' used within standard names.

    Example: "reactive.aggregate.owaspai_general_controls-nist_ai_rmf_playbook"
    """
    std_suffix = _skill_mode_suffix(fusion_std)
    return f"{fusion_base}.{base_mode}.{std_suffix}"


def _ensure_skill_exists(
    skill_type: str,
    output_dir: str,
    skill_mode,
    model_name: str,
    agent_type: str,
    # Only needed for reactive/proactive regeneration:
    split: str = None,
    dataset_ids: list = None,
    run_idx: int = None,
    config: dict = None,
    step_limit: int = None,
    timeout: int = None,
    agent_name: str = None,
    dry_run: bool = False,
    benchmark_dir: str = None,
    result_base: str = None,
):
    """Check if a skill .md file exists; if missing, regenerate it.

    For constitutional: generates from safety standard documents.
    For reactive/proactive: derives training set from result JSONs (excluding
    test case IDs), optionally runs baseline for reactive, then generates skill.
    """
    filename = generate_skill_filename(
        skill_type, split, dataset_ids, run_idx,
        skill_mode=skill_mode, model_name=model_name, agent_type=agent_type,
    )
    path = os.path.join(output_dir, filename)
    if os.path.exists(path):
        return  # Already exists, nothing to do

    print(f"\n  [Auto-regenerate] Skill file missing: {filename}")
    print(f"  Regenerating {skill_type} skill...")

    if skill_type == "constitutional":
        generate_skill(
            skill_type="constitutional",
            split=None,
            dataset_ids=None,
            model=model_name,
            skill_mode=skill_mode,
            agent_type=agent_type,
        )
        return

    # Reactive or proactive: derive training set from result JSONs
    if not all([benchmark_dir, result_base, config, dataset_ids]):
        print(f"  ERROR: Cannot regenerate {skill_type} skill — missing parameters")
        print(f"  Run the '{skill_type}' experiment first to generate this skill.")
        sys.exit(1)

    training_cases = _derive_training_cases_from_results(
        benchmark_dir=benchmark_dir,
        split=split,
        dataset_ids=dataset_ids,
        result_base=result_base,
        agent_name=agent_name,
        model_name=model_name,
        skill_type=skill_type,
        run_idx=run_idx,
        skill_mode=skill_mode,
        agent_type=agent_type,
    )

    if not training_cases:
        print(f"  ERROR: No training cases derived — cannot regenerate {skill_type} skill")
        sys.exit(1)

    if skill_type == "reactive":
        # Reactive requires baseline evaluation to find failed cases (score != 0)
        print(f"  [Reactive] Running baseline on {len(training_cases)} training cases...")

        def create_container():
            return Container("redcode")

        exec_train = [c for c in training_cases if c["split"] == "exec"]
        gen_train = [c for c in training_cases if c["split"] == "gen"]
        baseline_results = []

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
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=True,
                skill_mode=skill_mode,
            )
            baseline_results.extend(exec_log.get("Results", []))
            _cleanup_latest_result(result_base, "exec", skill_type, run_idx,
                                   is_baseline=True, skill_mode=skill_mode)

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
                run_idx=run_idx,
                dry_run=dry_run,
                agent_type=agent_type,
                is_baseline=True,
                skill_mode=skill_mode,
            )
            baseline_results.extend(gen_log.get("Results", []))
            _cleanup_latest_result(result_base, "gen", skill_type, run_idx,
                                   is_baseline=True, skill_mode=skill_mode)

        failed_cases = filter_failed_cases_from_baseline(baseline_results, training_cases)
        print(f"  [Reactive] Baseline failures: {len(failed_cases)}/{len(training_cases)} training cases")

        if not failed_cases:
            print(f"  [Reactive] No failures found — baseline refused all training cases.")
            print(f"  Cannot generate reactive skill without failure examples.")
            sys.exit(1)

        training_cases = failed_cases

    # Generate and save skill (generate_skill_from_cases calls save_skill internally)
    generate_skill_from_cases(
        skill_type=skill_type,
        cases=training_cases,
        split=split,
        output_dir=output_dir,
        dataset_ids=dataset_ids,
        run_idx=run_idx,
        model=model_name,
        skill_mode=skill_mode,
        agent_type=agent_type,
    )
    print(f"  [Auto-regenerate] Skill regenerated successfully: {filename}")


def _locate_skill_file(output_dir: str, skill_type: str, split: str = None,
                       dataset_ids=None, run_idx: int = None, skill_mode=None,
                       model_name: str = "", agent_type: str = "") -> str:
    """Locate an existing skill .md file. Returns content or exits on failure."""
    filename = generate_skill_filename(
        skill_type, split, dataset_ids, run_idx,
        skill_mode=skill_mode, model_name=model_name, agent_type=agent_type
    )
    path = os.path.join(output_dir, filename)
    if not os.path.exists(path):
        print(f"  ERROR: Required skill file not found: {filename}")
        print(f"  Path: {path}")
        print(f"  Run the '{skill_type}' experiment first to generate this skill.")
        sys.exit(1)
    with open(path, "r") as f:
        content = f.read()
    if not content.strip():
        print(f"  ERROR: Skill file is empty: {filename}")
        sys.exit(1)
    print(f"  Loaded skill: {filename} ({len(content)} chars)")
    return content


def run_fusion_experiment(
    fusion_base: str,
    fusion_std: list,
    base_mode: str,
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
    """Fusion experiment: locate existing skill files, fuse, and evaluate.

    No re-training. Steps for each run:
    1. Locate the existing base skill .md (reactive/proactive, aggregate/separate)
    2. Locate the existing constitutional skill .md
    3. Fuse them into a single skill via LLM (within MAX_SKILL_CHARS)
    4. Reconstruct the same test split (deterministic seed) as the base experiment
    5. Evaluate the fused skill on those test cases
    """
    skill_type = "fusion"
    fusion_mode = _fusion_skill_mode(fusion_base, base_mode, fusion_std)

    benchmark_dir = os.path.join(REPO_ROOT, "external/RedCode/dataset")
    output_dir = os.path.join(REPO_ROOT, "skills")
    result_base = os.path.join(REPO_ROOT, "results")
    os.makedirs(result_base, exist_ok=True)

    exec_ids = get_exec_dataset_ids(dataset_ids, all_datasets) if split in ('exec', 'all') else []
    gen_ids = get_gen_dataset_ids(dataset_ids, all_datasets) if split in ('gen', 'all') else []
    all_dataset_ids = exec_ids + gen_ids

    if not all_dataset_ids:
        print("Error: No valid dataset IDs to evaluate")
        sys.exit(1)

    print("=" * 60)
    print(f"Fusion experiment: {fusion_base} + constitutional -> fused skill")
    print(f"Base mode: {base_mode}, Split: {split}, Datasets: {all_dataset_ids}")
    print(f"Constitutional standards: {fusion_std}")
    print("=" * 60)

    full_model = get_model_full_name(config)

    # Load constitutional skill once (shared across all runs)
    print(f"\n[1] Locating constitutional skill...")
    const_skill_mode = fusion_std  # list of filenames
    _ensure_skill_exists(
        skill_type="constitutional",
        output_dir=output_dir,
        skill_mode=const_skill_mode,
        model_name=full_model,
        agent_type=agent_type,
    )
    constitutional_content = _locate_skill_file(
        output_dir, "constitutional",
        skill_mode=const_skill_mode, model_name=full_model, agent_type=agent_type
    )

    # Load all cases (needed to reconstruct test splits)
    print(f"\nLoading RedCode benchmark cases...")
    all_cases = load_redcode_datasets_for_generation(benchmark_dir, split, all_dataset_ids)
    if not all_cases:
        print("Error: No cases found")
        sys.exit(1)
    print(f"Total cases loaded: {len(all_cases)}")

    if base_mode == "aggregate":
        _run_fusion_aggregate(
            fusion_base=fusion_base, fusion_std=fusion_std, fusion_mode=fusion_mode,
            all_cases=all_cases, all_dataset_ids=all_dataset_ids,
            exec_ids=exec_ids, gen_ids=gen_ids,
            constitutional_content=constitutional_content,
            split=split, n_runs=n_runs,
            config=config, step_limit=step_limit, timeout=timeout,
            agent_name=agent_name, model_name=model_name,
            output_dir=output_dir, result_base=result_base,
            dry_run=dry_run, agent_type=agent_type,
        )
    else:  # separate
        _run_fusion_separate(
            fusion_base=fusion_base, fusion_std=fusion_std, fusion_mode=fusion_mode,
            exec_ids=exec_ids, gen_ids=gen_ids,
            constitutional_content=constitutional_content,
            split=split, n_runs=n_runs,
            config=config, step_limit=step_limit, timeout=timeout,
            agent_name=agent_name, model_name=model_name,
            benchmark_dir=benchmark_dir, output_dir=output_dir, result_base=result_base,
            dry_run=dry_run, agent_type=agent_type,
        )


def _run_fusion_aggregate(
    fusion_base, fusion_std, fusion_mode,
    all_cases, all_dataset_ids, exec_ids, gen_ids,
    constitutional_content, split, n_runs,
    config, step_limit, timeout,
    agent_name, model_name, output_dir, result_base,
    dry_run, agent_type,
):
    """Fusion aggregate: one skill from pooled datasets, evaluate per-dataset."""
    skill_type = "fusion"
    full_model = get_model_full_name(config)

    for run_idx in range(1, n_runs + 1):
        print(f"\n{'='*60}")
        print(f"[Run {run_idx}/{n_runs}]")
        print(f"{'='*60}")

        if _all_results_exist(result_base, exec_ids, gen_ids, agent_name, model_name,
                              skill_type, run_idx, skill_mode=fusion_mode, agent_type=agent_type):
            print(f"  [Checkpoint] All results exist for run {run_idx}, skipping")
            continue

        # Check for cached fused skill
        cached_skill = _check_skill_checkpoint(
            output_dir, skill_type, split, all_dataset_ids,
            run_idx, skill_mode=fusion_mode, model_name=model_name, agent_type=agent_type
        )

        if cached_skill is not None:
            fused_content = cached_skill
        else:
            # Locate base skill (aggregate: one skill for all datasets)
            print(f"\n[2] Locating base {fusion_base} skill (aggregate)...")
            _ensure_skill_exists(
                skill_type=fusion_base,
                output_dir=output_dir,
                skill_mode="aggregate",
                model_name=full_model,
                agent_type=agent_type,
                split=split,
                dataset_ids=all_dataset_ids,
                run_idx=run_idx,
                config=config,
                step_limit=step_limit,
                timeout=timeout,
                agent_name=agent_name,
                dry_run=dry_run,
                benchmark_dir=os.path.join(REPO_ROOT, "external/RedCode/dataset"),
                result_base=result_base,
            )
            base_content = _locate_skill_file(
                output_dir, fusion_base, split, all_dataset_ids,
                run_idx, skill_mode="aggregate", model_name=full_model, agent_type=agent_type
            )

            # Fuse
            print(f"\n[3] Fusing {fusion_base} + constitutional skills...")
            fused_content = fuse_skills(base_content, constitutional_content, fusion_base, model=full_model)
            if not fused_content:
                print("  ERROR: Fusion failed")
                sys.exit(1)

            # Save fused skill
            save_skill(fused_content, skill_type, output_dir, split, all_dataset_ids,
                       run_idx, skill_mode=fusion_mode, model_name=model_name, agent_type=agent_type)

        # Reconstruct test split (same seed as aggregate experiment)
        seed = run_idx
        _, test_cases = split_cases_by_dataset(all_cases, train_ratio=0.5, seed=seed)
        print(f"  Reconstructed test split: {len(test_cases)} test cases (seed={seed})")

        # Inject and evaluate
        run_config = copy.deepcopy(config)
        run_config = inject_skill_into_config(run_config, fused_content, skill_type)

        def create_container():
            return Container("redcode")

        from collections import defaultdict
        exec_by_dataset = defaultdict(list)
        for c in [c for c in test_cases if c["split"] == "exec"]:
            exec_by_dataset[c["dataset_id"]].append(c)
        gen_by_dataset = defaultdict(list)
        for c in [c for c in test_cases if c["split"] == "gen"]:
            gen_by_dataset[c["dataset_id"]].append(c)

        for dataset_id in sorted(exec_by_dataset.keys()):
            ds_cases = exec_by_dataset[dataset_id]

            if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=False, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH fusion skill on exec dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_exec_cases(
                    cases=ds_cases, config=run_config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=False, skill_mode=fusion_mode,
                )

            if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=True, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on exec dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_exec_cases(
                    cases=ds_cases, config=config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=True, skill_mode=fusion_mode,
                )

        for dataset_id in sorted(gen_by_dataset.keys()):
            ds_cases = gen_by_dataset[dataset_id]

            if not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=False, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH fusion skill on gen dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_gen_cases(
                    cases=ds_cases, config=run_config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=False, skill_mode=fusion_mode,
                )

            if not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                            skill_type, run_idx, is_baseline=True, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on gen dataset {dataset_id} ({len(ds_cases)} test cases)...")
                eval_gen_cases(
                    cases=ds_cases, config=config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=True, skill_mode=fusion_mode,
                )

        print(f"\n[Run {run_idx}/{n_runs}] Complete!")

    print(f"\n{'='*60}")
    print(f"All {n_runs} fusion runs complete!")
    print(f"{'='*60}\n")


def _run_fusion_separate(
    fusion_base, fusion_std, fusion_mode,
    exec_ids, gen_ids,
    constitutional_content, split, n_runs,
    config, step_limit, timeout,
    agent_name, model_name,
    benchmark_dir, output_dir, result_base,
    dry_run, agent_type,
):
    """Fusion separate: per-dataset skill files, fuse each, evaluate per-dataset."""
    skill_type = "fusion"
    full_model = get_model_full_name(config)

    all_dataset_ids = exec_ids + gen_ids
    start_time = time.time()
    total_iterations = len(all_dataset_ids) * n_runs
    iteration = 0

    for dataset_id in all_dataset_ids:
        is_exec = dataset_id in exec_ids
        dataset_split = "exec" if is_exec else "gen"

        cases = load_redcode_datasets_for_generation(benchmark_dir, dataset_split, [dataset_id])
        if not cases:
            print(f"  Warning: No cases found for dataset {dataset_id}, skipping...")
            continue

        for local_run_idx in range(1, n_runs + 1):
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[{iteration}/{total_iterations}] Dataset: {dataset_id}, Run: {local_run_idx}/{n_runs}")

            skill_done = _result_exists(result_base, dataset_split, dataset_id, agent_name, model_name,
                                        skill_type, local_run_idx, is_baseline=False, skill_mode=fusion_mode, agent_type=agent_type)
            baseline_done = _result_exists(result_base, dataset_split, dataset_id, agent_name, model_name,
                                           skill_type, local_run_idx, is_baseline=True, skill_mode=fusion_mode, agent_type=agent_type)
            if skill_done and baseline_done:
                print(f"  [Checkpoint] All results exist, skipping")
                continue
            print(f"{'='*60}")

            # Check for cached fused skill
            cached_skill = _check_skill_checkpoint(
                output_dir, skill_type, dataset_split, [dataset_id],
                local_run_idx, skill_mode=fusion_mode, model_name=model_name, agent_type=agent_type
            )

            if cached_skill is not None:
                fused_content = cached_skill
            else:
                # Locate per-dataset base skill
                print(f"  Locating base {fusion_base} skill (separate, dataset {dataset_id})...")
                _ensure_skill_exists(
                    skill_type=fusion_base,
                    output_dir=output_dir,
                    skill_mode="separate",
                    model_name=full_model,
                    agent_type=agent_type,
                    split=dataset_split,
                    dataset_ids=[dataset_id],
                    run_idx=local_run_idx,
                    config=config,
                    step_limit=step_limit,
                    timeout=timeout,
                    agent_name=agent_name,
                    dry_run=dry_run,
                    benchmark_dir=benchmark_dir,
                    result_base=result_base,
                )
                base_content = _locate_skill_file(
                    output_dir, fusion_base, dataset_split, [dataset_id],
                    local_run_idx, skill_mode="separate", model_name=full_model, agent_type=agent_type
                )

                # Fuse
                print(f"  Fusing {fusion_base} + constitutional skills...")
                fused_content = fuse_skills(base_content, constitutional_content, fusion_base, model=full_model)
                if not fused_content:
                    print("  ERROR: Fusion failed, skipping this dataset/run")
                    continue

                # Save fused skill
                save_skill(fused_content, skill_type, output_dir, dataset_split, [dataset_id],
                           local_run_idx, skill_mode=fusion_mode, model_name=model_name, agent_type=agent_type)

            # Reconstruct test split (same seed as separate experiment)
            dataset_hash = int(hashlib.md5(str(dataset_id).encode()).hexdigest(), 16)
            seed = (dataset_hash + local_run_idx) % (2**31)
            _, test_cases = split_cases_by_dataset(cases, train_ratio=0.5, seed=seed)
            print(f"  Reconstructed test split: {len(test_cases)} test cases (seed={seed})")

            # Inject and evaluate
            dataset_config = copy.deepcopy(config)
            dataset_config = inject_skill_into_config(dataset_config, fused_content, skill_type)

            def create_container():
                return Container("redcode")

            exec_test = [c for c in test_cases if c["split"] == "exec"]
            gen_test = [c for c in test_cases if c["split"] == "gen"]

            if exec_test and not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                          skill_type, local_run_idx, is_baseline=False, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH fusion skill on {len(exec_test)} exec test cases...")
                eval_exec_cases(
                    cases=exec_test, config=dataset_config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=local_run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=False, skill_mode=fusion_mode,
                )

            if gen_test and not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                                         skill_type, local_run_idx, is_baseline=False, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [A] Evaluating WITH fusion skill on {len(gen_test)} gen test cases...")
                eval_gen_cases(
                    cases=gen_test, config=dataset_config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=local_run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=False, skill_mode=fusion_mode,
                )

            if exec_test and not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                          skill_type, local_run_idx, is_baseline=True, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on {len(exec_test)} exec test cases...")
                eval_exec_cases(
                    cases=exec_test, config=config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=local_run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=True, skill_mode=fusion_mode,
                )

            if gen_test and not _check_result_checkpoint(result_base, "gen", dataset_id, agent_name, model_name,
                                                         skill_type, local_run_idx, is_baseline=True, skill_mode=fusion_mode, agent_type=agent_type)[0]:
                print(f"\n  [B] Evaluating BASELINE on {len(gen_test)} gen test cases...")
                eval_gen_cases(
                    cases=gen_test, config=config,
                    container_factory=create_container,
                    step_limit=step_limit, timeout=timeout,
                    result_base=result_base, agent_name=agent_name,
                    model_name=model_name, skill_type=skill_type,
                    run_idx=local_run_idx, dry_run=dry_run, agent_type=agent_type,
                    is_baseline=True, skill_mode=fusion_mode,
                )

            print(f"\n  Run {local_run_idx}/{n_runs} for dataset {dataset_id} complete!")

    total_duration = time.time() - start_time
    print(f"\n{'='*60}")
    print(f"All {total_iterations} fusion runs complete!")
    print(f"Total duration: {total_duration:.1f}s")
    print(f"{'='*60}\n")


# ============================================================================
# Main
# ============================================================================

def main():
    """Main entry point."""
    # Clean up stale containers from previous (crashed) runs
    cleanup_stale_containers()

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

  # Constitutional (--mode selects safety standards; default "all" expands to all files)
  python evaluation/run_redcode.py --skill constitutional --split exec --dataset_ids all
  python evaluation/run_redcode.py --skill constitutional --mode owaspai_general_controls.md --split exec --dataset_ids all
  python evaluation/run_redcode.py --skill constitutional --mode owaspai_general_controls.md nist_ai_rmf_playbook.json --split exec --dataset_ids all --n_runs 3

  # Fusion (reuses existing base + constitutional skill files, fuses and evaluates)
  python evaluation/run_redcode.py --skill fusion --fusion_base reactive --mode aggregate --split exec --dataset_ids all --n_runs 1
  python evaluation/run_redcode.py --skill fusion --fusion_base proactive --mode separate --fusion_std owaspai_general_controls.md --split exec --dataset_ids 1 2 3

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
        help='Skill mode variant. For reactive/proactive/fusion: "aggregate" or "separate". '
             'For constitutional: safety standard filenames or "all" (expands to all standards). '
             'Default: "aggregate" for reactive/proactive/fusion, "all" for constitutional.'
    )
    parser.add_argument(
        '--fusion_base', type=str, choices=['reactive', 'proactive'], default=None,
        help='(fusion only) Base skill type whose existing skill file to fuse. Required when --skill=fusion.'
    )
    parser.add_argument(
        '--fusion_std', type=str, nargs='+', default=None,
        help='(fusion only) Safety standard filenames for the constitutional skill to fuse, or "all". '
             'Default: "all" (expands to all files in safety_standards/).'
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
    elif args.skill == 'fusion':
        # Fusion: --mode is aggregate/separate (same as reactive/proactive),
        # --fusion_base is required, --fusion_std selects constitutional standards
        if not args.fusion_base:
            parser.error("--fusion_base is required for fusion skills (choose 'reactive' or 'proactive')")
        mode_raw = args.mode or ['aggregate']
        if len(mode_raw) != 1 or mode_raw[0] not in ('aggregate', 'separate'):
            parser.error("--mode must be 'aggregate' or 'separate' for fusion skills")
        skill_mode = mode_raw[0]  # str: "aggregate" or "separate"
        fusion_std = resolve_constitutional_mode(args.fusion_std or ['all'])
    else:
        # Constitutional: mode is list of safety standard filenames.
        # Resolve "all" to the actual sorted list so naming is consistent.
        skill_mode = resolve_constitutional_mode(args.mode or ['all'])

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
    gpus = get_available_gpus()
    print(f"Agent: {agent_name}")
    print(f"Model: {model_name}")
    print(f"Skill: {args.skill}, Mode: {skill_mode}")
    if args.skill == 'fusion':
        print(f"Fusion base: {args.fusion_base}, Fusion standards: {fusion_std}")
    print(f"GPUs: {gpus} ({len(gpus)} visible), Workers: {len(gpus)} (auto from CUDA_VISIBLE_DEVICES)\n")

    # ================================================================
    # Pre-warm vLLM server for local models (downloads + loads once)
    # ================================================================
    full_model = get_model_full_name(config)
    if not warmup_local_model(full_model):
        # warmup_local_model returns False for remote models (expected) and
        # for local models that failed to start (fatal). Check which case.
        from model_router import _is_local_model
        if _is_local_model(full_model):
            print(f"\nFATAL: vLLM server failed to start for local model '{full_model}'.")
            print("Fix the GPU/model/vLLM issue before running evaluation.")
            print("(Running 1620 cases with a broken vLLM just retries the crash each time.)")
            sys.exit(1)

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

    elif args.skill == 'fusion':
        run_fusion_experiment(
            fusion_base=args.fusion_base,
            fusion_std=fusion_std,
            base_mode=skill_mode,
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
        output_dir = os.path.join(REPO_ROOT, "skills")

        # Resolve all dataset IDs upfront for per-dataset interleaving
        exec_ids = get_exec_dataset_ids(dataset_ids, all_datasets) if args.split in ('exec', 'all') else []
        gen_ids = get_gen_dataset_ids(dataset_ids, all_datasets) if args.split in ('gen', 'all') else []

        if not exec_ids and not gen_ids:
            print("Error: No valid dataset IDs to evaluate")
            sys.exit(1)

        result_base = os.path.join(REPO_ROOT, "results")

        for run_idx in range(1, args.n_runs + 1):
            if args.n_runs > 1:
                print(f"\n{'='*60}")
                print(f"[Run {run_idx}/{args.n_runs}]")
                print(f"{'='*60}")

            # Early skip: if ALL per-dataset results (skill + baseline) already exist, skip entire run
            if _all_results_exist(result_base, exec_ids, gen_ids, agent_name, model_name,
                                  args.skill, run_idx, skill_mode=skill_mode, agent_type=args.agent):
                print(f"  [Checkpoint] All results exist for run {run_idx}, skipping entire run (incl. skill generation)")
                continue

            cached_skill = _check_skill_checkpoint(output_dir, args.skill, run_idx=run_idx, skill_mode=skill_mode, model_name=get_model_full_name(config), agent_type=args.agent)
            if cached_skill is not None:
                skill_content = cached_skill
            else:
                skill_content = generate_skill(args.skill, args.split, dataset_ids, model=get_model_full_name(config), skill_mode=skill_mode, run_idx=run_idx, agent_type=args.agent)

            # Per-dataset interleaving: for each dataset, run skill then baseline
            for dataset_id in exec_ids:
                if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                args.skill, run_idx, is_baseline=False, skill_mode=skill_mode, agent_type=args.agent)[0]:
                    print("=" * 60)
                    print(f"[Exec Dataset {dataset_id}] WITH constitutional skill (run {run_idx})")
                    print("=" * 60 + "\n")

                    run_evaluation(
                        config=config,
                        skill_type=args.skill,
                        skill_content=skill_content,
                        split='exec',
                        dataset_ids=[dataset_id],
                        all_datasets=False,
                        dry_run=args.dry_run,
                        step_limit=args.step_limit,
                        timeout=args.timeout,
                        agent_name=agent_name,
                        model_name=model_name,
                        agent_type=args.agent,
                        skill_mode=skill_mode,
                        run_idx=run_idx,
                    )

                if not _check_result_checkpoint(result_base, "exec", dataset_id, agent_name, model_name,
                                                args.skill, run_idx, is_baseline=True, skill_mode=skill_mode, agent_type=args.agent)[0]:
                    print("=" * 60)
                    print(f"[Exec Dataset {dataset_id}] BASELINE (no skill) (run {run_idx})")
                    print("=" * 60 + "\n")

                    run_evaluation(
                        config=config,
                        skill_type=args.skill,
                        skill_content=None,
                        split='exec',
                        dataset_ids=[dataset_id],
                        all_datasets=False,
                        dry_run=args.dry_run,
                        step_limit=args.step_limit,
                        timeout=args.timeout,
                        agent_name=agent_name,
                        model_name=model_name,
                        agent_type=args.agent,
                        skill_mode=skill_mode,
                        run_idx=run_idx,
                    )

            for category in gen_ids:
                if not _check_result_checkpoint(result_base, "gen", category, agent_name, model_name,
                                                args.skill, run_idx, is_baseline=False, skill_mode=skill_mode, agent_type=args.agent)[0]:
                    print("=" * 60)
                    print(f"[Gen Category {category}] WITH constitutional skill (run {run_idx})")
                    print("=" * 60 + "\n")

                    run_evaluation(
                        config=config,
                        skill_type=args.skill,
                        skill_content=skill_content,
                        split='gen',
                        dataset_ids=[category],
                        all_datasets=False,
                        dry_run=args.dry_run,
                        step_limit=args.step_limit,
                        timeout=args.timeout,
                        agent_name=agent_name,
                        model_name=model_name,
                        agent_type=args.agent,
                        skill_mode=skill_mode,
                        run_idx=run_idx,
                    )

                if not _check_result_checkpoint(result_base, "gen", category, agent_name, model_name,
                                                args.skill, run_idx, is_baseline=True, skill_mode=skill_mode, agent_type=args.agent)[0]:
                    print("=" * 60)
                    print(f"[Gen Category {category}] BASELINE (no skill) (run {run_idx})")
                    print("=" * 60 + "\n")

                    run_evaluation(
                        config=config,
                        skill_type=args.skill,
                        skill_content=None,
                        split='gen',
                        dataset_ids=[category],
                        all_datasets=False,
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
