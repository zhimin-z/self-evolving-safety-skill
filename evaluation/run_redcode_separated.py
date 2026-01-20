#!/usr/bin/env python3
"""
RedCode evaluation script with optional skill generation (SEPARATED mode).

If --skill is specified, generates the skill first then evaluates with it.
If --skill is omitted, runs baseline evaluation (no skill).

For reactive/proactive skills: per-dataset skill generation + evaluation.
  - For each dataset: split 50/50, train skill on first half, evaluate on second half
  - Use --n_runs to run multiple iterations per dataset with different random splits
  - Results are aggregated across all datasets and runs at the end

For constitutional skills: single generation from safety standards (no split).

Usage:
    # Baseline evaluation (no skill)
    python evaluation/run_redcode_separated.py --split exec --dataset_ids 4
    python evaluation/run_redcode_separated.py --split exec --all

    # Reactive/Proactive: per-dataset train/test with aggregated results
    python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 1 2 3
    python evaluation/run_redcode_separated.py --skill proactive --split all --all

    # Reactive/Proactive: multiple runs per dataset
    python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 4 --n_runs 5

    # Constitutional (no random split, uses safety standards)
    python evaluation/run_redcode_separated.py --skill constitutional --split exec --all

    # Dry run
    python evaluation/run_redcode_separated.py --split exec --dataset_ids 4 --dry_run
"""

import argparse
import copy
import datetime
import hashlib
import json
import os
import sys
import time
from collections import Counter

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
    REDCODE_GEN_CATEGORIES,
    SKILL_TYPES,
    AGENT_CONFIGS,
    CODE_GENERATION_PROMPT,
    # Utilities
    load_config,
    get_model_full_name,
    get_model_short_name,
    get_agent_name,
    get_exec_dataset_ids,
    get_gen_dataset_ids,
    split_cases_by_dataset,
    load_redcode_datasets_for_generation,
    format_history,
    score_gen_response,
    score_exec_response,
    # Skill generation
    generate_skill_from_cases,
    inject_skill_into_config,
    # Evaluation
    build_agent,
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
        4. Collect results

    Finally: aggregate all results into final output.
    """
    benchmark_dir = os.path.join(REPO_ROOT, "external/RedCode/dataset")
    output_dir = os.path.join(REPO_ROOT, "security-skills")
    result_base = os.path.join(REPO_ROOT, "results/with_skills")
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

    # Collect results from all datasets
    aggregated_results = []

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

        for run_idx in range(1, n_runs + 1):
            iteration += 1
            print(f"\n{'='*60}")
            print(f"[{iteration}/{total_iterations}] Dataset: {dataset_id}, Run: {run_idx}/{n_runs}")
            print(f"{'='*60}")

            print(f"  Loaded {len(cases)} cases")

            # Split 50/50 with seed based on both dataset_id and run_idx
            # Use hashlib for deterministic hashing (Python's hash() is randomized by default)
            dataset_hash = int(hashlib.md5(str(dataset_id).encode()).hexdigest(), 16)
            seed = (dataset_hash + run_idx) % (2**31)
            train_cases, test_cases = split_cases_by_dataset(cases, train_ratio=0.5, seed=seed)

            print(f"  Train: {len(train_cases)} cases, Test: {len(test_cases)} cases")

            # Generate skill from train half
            skill_content = generate_skill_from_cases(
                skill_type=skill_type,
                cases=train_cases,
                split=dataset_split,
                output_dir=output_dir,
                dataset_ids=[dataset_id],
                run_idx=run_idx,
            )

            # Inject skill into config
            dataset_config = copy.deepcopy(config)
            dataset_config = inject_skill_into_config(dataset_config, skill_content, skill_type)

            def create_container():
                return Container("redcode")

            # Evaluate on test half immediately
            print(f"\n  Evaluating skill on {len(test_cases)} test cases...")

            run_results = []

            for case in test_cases:
                case_id = case["index"] if is_exec else f"{case['dataset_id']}_{case['index']}"
                print(f"    Processing case: {case_id}")

                if dry_run:
                    run_results.append({"case_id": case_id, "score": 1, "reason": "dry_run"})
                    continue

                container = create_container()
                agent = build_agent(dataset_config, container, step_limit, timeout, agent_type=agent_type)

                try:
                    agent.env.reset_history()

                    if is_exec:
                        prompt = case["content"]
                    else:
                        prompt = CODE_GENERATION_PROMPT + case["content"]

                    status, message = agent.run(prompt)

                    exec_history = agent.env.get_history()
                    response = message
                    if exec_history:
                        response = format_history(exec_history)

                    if is_exec:
                        # Exec scoring using proper RedCode evaluation
                        score = score_exec_response(
                            container=container.container,
                            case_index=case["index"],
                            response=response,
                            expected_result=case.get("expected_result", ""),
                            had_execution=bool(exec_history),
                        )
                    else:
                        # Gen scoring
                        score = score_gen_response(response, case["content"])

                    run_results.append({
                        "case_id": case_id,
                        "dataset_id": dataset_id,
                        "run_idx": run_idx,
                        "score": score,
                        "status": status,
                    })

                except Exception as exc:
                    run_results.append({
                        "case_id": case_id,
                        "dataset_id": dataset_id,
                        "run_idx": run_idx,
                        "score": 1,
                        "error": str(exc),
                    })

                finally:
                    container.close()

                print(f"      Score: {run_results[-1]['score']}")

            # Collect results
            aggregated_results.extend(run_results)

            # Print per-run summary
            scores = [r['score'] for r in run_results]
            if scores:
                score_dist = dict(Counter(scores))
                refusal_rate = scores.count(0) / len(scores)
                asr = scores.count(3) / len(scores)
                print(f"\n  Dataset {dataset_id} Run {run_idx} Summary:")
                print(f"    Score distribution: {score_dist}")
                print(f"    Refusal rate: {refusal_rate:.2%}")
                print(f"    Attack success rate: {asr:.2%}")

    # Save aggregated final results
    print(f"\n{'='*60}")
    print("Aggregating final results...")
    print(f"{'='*60}")

    duration = time.time() - start_time
    all_scores = [r['score'] for r in aggregated_results]
    final_score_dist = dict(Counter(all_scores))

    # Generate filename
    time_now = datetime.datetime.now()
    time_stamp = time_now.strftime("%Y-%m-%d_%H-%M-%S")

    final_eval_log = {
        "Skill": skill_type,
        "Split": split,
        "Datasets": all_dataset_ids,
        "N_Runs": n_runs,
        "Agent": agent_name,
        "Model": get_model_full_name(config),
        "Timestamp": time_stamp,
        "Duration (seconds)": round(duration, 2),
        "Config": {
            "step_limit": step_limit,
            "timeout": timeout,
            "n_runs": n_runs,
            "dry_run": dry_run,
        },
        "Total Cases": len(aggregated_results),
        "Score Distribution": final_score_dist,
        "Refusal Rate (score=0)": all_scores.count(0) / len(all_scores) if all_scores else 0,
        "Attack Success Rate (score=3)": all_scores.count(3) / len(all_scores) if all_scores else 0,
        "Per-Case Results": aggregated_results,
    }

    dataset_str = "-".join(all_dataset_ids) if len(all_dataset_ids) <= 5 else f"{len(all_dataset_ids)}datasets"
    runs_str = f"_runs{n_runs}" if n_runs > 1 else ""
    resfile = os.path.join(result_base, f"{split}_{dataset_str}_{skill_type}{runs_str}_{agent_name}_{model_name}_{time_stamp}.json")

    with open(resfile, "w") as f:
        json.dump(final_eval_log, f, indent=2)

    print(f"\nFinal Results:")
    print(f"  Total cases: {len(aggregated_results)}")
    print(f"  Score distribution: {final_score_dist}")
    print(f"  Refusal rate: {final_eval_log['Refusal Rate (score=0)']:.2%}")
    print(f"  Attack success rate: {final_eval_log['Attack Success Rate (score=3)']:.2%}")
    print(f"  Duration: {duration:.1f}s")
    print(f"\nResults saved to: {resfile}")
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
  # Baseline evaluation (no skill)
  python evaluation/run_redcode_separated.py --split exec --dataset_ids 4

  # Reactive/Proactive: per-dataset train/test with aggregated results
  python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 1 2 3
  python evaluation/run_redcode_separated.py --skill proactive --split all --all

  # Reactive/Proactive: multiple runs per dataset
  python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 4 --n_runs 5

  # Constitutional: single generation from safety standards (no split)
  python evaluation/run_redcode_separated.py --skill constitutional --split exec --all
"""
    )

    parser.add_argument(
        '--agent', type=str, choices=list(AGENT_CONFIGS.keys()), default='mini',
        help='Agent to use for evaluation (default: mini)'
    )
    parser.add_argument(
        '--model', type=str, default=None,
        help='Model to use (e.g., anthropic/anthropic/claude-haiku-4-5-20251001). Overrides config file.'
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
        skill_content = generate_skill(args.skill, args.split, args.dataset_ids)

        print("=" * 60)
        print("[2/2] Running RedCode evaluation with constitutional skill")
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
