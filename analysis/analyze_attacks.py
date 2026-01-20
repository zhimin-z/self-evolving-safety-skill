#!/usr/bin/env python3
"""
Compare baseline vs with-skills evaluation results.

Calculates ASR reduction and identifies effectiveness of different skill types.

Usage:
    # Summary comparison
    python analysis/compare_baseline_vs_skills.py

    # Detailed per-dataset analysis
    python analysis/compare_baseline_vs_skills.py --detailed

    # Visualization
    python analysis/compare_baseline_vs_skills.py --viz

    # All analysis
    python analysis/compare_baseline_vs_skills.py --all

    # Specify custom directories
    python analysis/compare_baseline_vs_skills.py --baseline results/baseline --skills results/with_skills
"""

import argparse
import json
import os
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ============================================================================
# Data Loading Functions
# ============================================================================

def load_results(results_dir: str) -> List[Dict]:
    """Load all result JSON files from a directory.

    Handles the new result format with:
    - Score Distribution: {0: N, 1: N, 3: N}
    - Refusal Rate (score=0)
    - Attack Success Rate (score=3)
    - Per-Case Results or Results list
    """
    results = []
    results_path = Path(results_dir)

    if not results_path.exists():
        return results

    for json_file in sorted(results_path.glob("*.json")):
        # Skip non-result files
        if "comparison" in json_file.name or "log" in json_file.name:
            continue

        try:
            with open(json_file) as f:
                data = json.load(f)

            # Handle both single result and list of results
            if isinstance(data, list):
                for item in data:
                    item["_source_file"] = json_file.name
                    results.append(item)
            else:
                data["_source_file"] = json_file.name
                results.append(data)

        except (json.JSONDecodeError, IOError) as e:
            print(f"  Warning: Could not load {json_file}: {e}")

    return results


def extract_scores_from_result(result: Dict) -> Tuple[int, int, int, int]:
    """Extract score counts from a result entry.

    Returns: (total, score_0, score_1, score_3)
    """
    # Try new format first: Score Distribution
    score_dist = result.get("Score Distribution", {})
    if score_dist:
        # Convert string keys to int if needed
        score_0 = score_dist.get(0, score_dist.get("0", 0))
        score_1 = score_dist.get(1, score_dist.get("1", 0))
        score_3 = score_dist.get(3, score_dist.get("3", 0))
        total = score_0 + score_1 + score_3
        return total, score_0, score_1, score_3

    # Try extracting from Per-Case Results or Results
    per_case = result.get("Per-Case Results", result.get("Results", []))
    if per_case:
        scores = [r.get("score", 1) for r in per_case]
        score_0 = scores.count(0)
        score_1 = scores.count(1)
        score_3 = scores.count(3)
        total = len(scores)
        return total, score_0, score_1, score_3

    # Fallback: try old format with Final Result
    final_result = result.get("Final Result", {})
    if final_result:
        total = 0
        score_0 = 0
        score_1 = 0
        score_3 = 0
        for attack_type, attack_scores in final_result.items():
            if isinstance(attack_scores, dict):
                score_0 += attack_scores.get("0", attack_scores.get(0, 0))
                score_1 += attack_scores.get("1", attack_scores.get(1, 0))
                score_3 += attack_scores.get("3", attack_scores.get(3, 0))
                total += sum(attack_scores.values())
        return total, score_0, score_1, score_3

    return 0, 0, 0, 0


# ============================================================================
# Analysis Functions
# ============================================================================

def aggregate_results(results: List[Dict]) -> Dict:
    """Aggregate results to compute overall statistics.

    Returns dict with:
    - total: total number of cases
    - score_0: refusals
    - score_1: execution failures
    - score_3: attack successes
    - refusal_rate: score_0 / total
    - failure_rate: score_1 / total
    - attack_success_rate: score_3 / total
    - by_skill: breakdown by skill type
    - by_dataset: breakdown by dataset
    - by_split: breakdown by split (exec/gen)
    """
    totals = {"total": 0, "score_0": 0, "score_1": 0, "score_3": 0}
    by_skill = defaultdict(lambda: {"total": 0, "score_0": 0, "score_1": 0, "score_3": 0})
    by_dataset = defaultdict(lambda: {"total": 0, "score_0": 0, "score_1": 0, "score_3": 0})
    by_split = defaultdict(lambda: {"total": 0, "score_0": 0, "score_1": 0, "score_3": 0})

    for result in results:
        total, score_0, score_1, score_3 = extract_scores_from_result(result)

        if total == 0:
            continue

        # Overall totals
        totals["total"] += total
        totals["score_0"] += score_0
        totals["score_1"] += score_1
        totals["score_3"] += score_3

        # By skill type
        skill = result.get("Skill", "baseline") or "baseline"
        by_skill[skill]["total"] += total
        by_skill[skill]["score_0"] += score_0
        by_skill[skill]["score_1"] += score_1
        by_skill[skill]["score_3"] += score_3

        # By dataset
        datasets = result.get("Datasets", [])
        if isinstance(datasets, list):
            for ds in datasets:
                by_dataset[str(ds)]["total"] += total // len(datasets)
                by_dataset[str(ds)]["score_0"] += score_0 // len(datasets)
                by_dataset[str(ds)]["score_1"] += score_1 // len(datasets)
                by_dataset[str(ds)]["score_3"] += score_3 // len(datasets)

        # By split
        split = result.get("Split", "exec")
        by_split[split]["total"] += total
        by_split[split]["score_0"] += score_0
        by_split[split]["score_1"] += score_1
        by_split[split]["score_3"] += score_3

    # Calculate rates
    def calc_rates(d):
        if d["total"] > 0:
            d["refusal_rate"] = d["score_0"] / d["total"]
            d["failure_rate"] = d["score_1"] / d["total"]
            d["attack_success_rate"] = d["score_3"] / d["total"]
        else:
            d["refusal_rate"] = 0
            d["failure_rate"] = 0
            d["attack_success_rate"] = 0
        return d

    totals = calc_rates(totals)

    return {
        "overall": totals,
        "by_skill": {k: calc_rates(dict(v)) for k, v in by_skill.items()},
        "by_dataset": {k: calc_rates(dict(v)) for k, v in by_dataset.items()},
        "by_split": {k: calc_rates(dict(v)) for k, v in by_split.items()},
        "n_files": len(results),
    }


# ============================================================================
# Summary Comparison
# ============================================================================

def print_summary_comparison(baseline_agg: Dict, skills_agg: Dict):
    """Print overall summary comparison."""
    print("=" * 80)
    print(" " * 15 + "BASELINE vs WITH-SKILLS COMPARISON")
    print("=" * 80)
    print()

    baseline = baseline_agg["overall"]
    skills = skills_agg["overall"]

    print(f"{'Metric':<30} {'Baseline':<20} {'With Skills':<20} {'Change':<15}")
    print("-" * 85)

    # Total cases
    print(f"{'Total Cases':<30} {baseline['total']:<20} {skills['total']:<20} {skills['total'] - baseline['total']:+d}")

    # Refusals (score 0) - higher is better for safety
    b_rr = baseline["refusal_rate"] * 100
    s_rr = skills["refusal_rate"] * 100
    delta_rr = s_rr - b_rr
    symbol = "+" if delta_rr > 0 else ""
    print(f"{'Refusals (score=0)':<30} {baseline['score_0']:>4} ({b_rr:5.1f}%)      {skills['score_0']:>4} ({s_rr:5.1f}%)      {symbol}{delta_rr:5.1f}%")

    # Execution failures (score 1)
    b_fr = baseline["failure_rate"] * 100
    s_fr = skills["failure_rate"] * 100
    delta_fr = s_fr - b_fr
    symbol = "+" if delta_fr > 0 else ""
    print(f"{'Exec Failures (score=1)':<30} {baseline['score_1']:>4} ({b_fr:5.1f}%)      {skills['score_1']:>4} ({s_fr:5.1f}%)      {symbol}{delta_fr:5.1f}%")

    # Attack successes (score 3) - lower is better for safety
    b_asr = baseline["attack_success_rate"] * 100
    s_asr = skills["attack_success_rate"] * 100
    delta_asr = s_asr - b_asr
    symbol = "+" if delta_asr > 0 else ""
    print(f"{'Attack Success (score=3)':<30} {baseline['score_3']:>4} ({b_asr:5.1f}%)      {skills['score_3']:>4} ({s_asr:5.1f}%)      {symbol}{delta_asr:5.1f}%")

    print("-" * 85)

    # Key metrics
    print()
    print("KEY METRICS:")
    print("-" * 85)

    asr_reduction = b_asr - s_asr
    if b_asr > 0:
        rel_reduction = (asr_reduction / b_asr) * 100
    else:
        rel_reduction = 0

    print(f"  Attack Success Rate (ASR):")
    print(f"    Baseline:    {b_asr:6.2f}%")
    print(f"    With Skills: {s_asr:6.2f}%")
    if asr_reduction > 0:
        print(f"    Reduction:   {asr_reduction:6.2f}% (↓{rel_reduction:.1f}% relative)")
    elif asr_reduction < 0:
        print(f"    INCREASE:    {-asr_reduction:6.2f}% (↑{-rel_reduction:.1f}% relative)")
    else:
        print(f"    No change")

    print()
    rr_increase = s_rr - b_rr
    print(f"  Refusal Rate (RR):")
    print(f"    Baseline:    {b_rr:6.2f}%")
    print(f"    With Skills: {s_rr:6.2f}%")
    if rr_increase > 0:
        print(f"    Increase:    {rr_increase:6.2f}% (more refusals = safer)")
    elif rr_increase < 0:
        print(f"    Decrease:    {-rr_increase:6.2f}%")
    else:
        print(f"    No change")

    print("=" * 80)


def print_analysis(baseline_agg: Dict, skills_agg: Dict):
    """Print analysis and conclusions."""
    print()
    print("ANALYSIS:")
    print("-" * 80)

    baseline = baseline_agg["overall"]
    skills = skills_agg["overall"]

    b_asr = baseline["attack_success_rate"] * 100
    s_asr = skills["attack_success_rate"] * 100
    asr_reduction = b_asr - s_asr

    b_rr = baseline["refusal_rate"] * 100
    s_rr = skills["refusal_rate"] * 100
    rr_increase = s_rr - b_rr

    if asr_reduction > 5:
        print(f"  [STRONG] Security skill SIGNIFICANTLY reduced ASR by {asr_reduction:.1f}%")
    elif asr_reduction > 0:
        print(f"  [POSITIVE] Security skill reduced ASR by {asr_reduction:.1f}%")
    elif asr_reduction < -5:
        print(f"  [WARNING] Security skill INCREASED ASR by {-asr_reduction:.1f}%!")
    elif asr_reduction < 0:
        print(f"  [CONCERN] Security skill slightly increased ASR by {-asr_reduction:.1f}%")
    else:
        print(f"  [NEUTRAL] No change in ASR")

    if rr_increase > 5:
        print(f"  [STRONG] Refusal rate increased by {rr_increase:.1f}% (better safety awareness)")
    elif rr_increase > 0:
        print(f"  [POSITIVE] Refusal rate increased by {rr_increase:.1f}%")

    # Check skill-specific results
    if skills_agg.get("by_skill"):
        print()
        print("  By Skill Type:")
        for skill, data in sorted(skills_agg["by_skill"].items()):
            if skill == "baseline":
                continue
            asr = data["attack_success_rate"] * 100
            rr = data["refusal_rate"] * 100
            print(f"    {skill}: ASR={asr:.1f}%, RR={rr:.1f}% (n={data['total']})")

    print("=" * 80)


# ============================================================================
# Detailed Analysis
# ============================================================================

def print_detailed_comparison(baseline_agg: Dict, skills_agg: Dict):
    """Print detailed breakdown by dataset and split."""
    print()
    print("=" * 80)
    print("DETAILED BREAKDOWN")
    print("=" * 80)

    # By Split
    print()
    print("By Split (exec/gen):")
    print("-" * 80)
    print(f"{'Split':<10} {'Baseline ASR':<15} {'Skills ASR':<15} {'Delta':<10} {'Baseline RR':<15} {'Skills RR':<15}")
    print("-" * 80)

    for split in ["exec", "gen"]:
        b_data = baseline_agg["by_split"].get(split, {"attack_success_rate": 0, "refusal_rate": 0, "total": 0})
        s_data = skills_agg["by_split"].get(split, {"attack_success_rate": 0, "refusal_rate": 0, "total": 0})

        if b_data["total"] == 0 and s_data["total"] == 0:
            continue

        b_asr = b_data["attack_success_rate"] * 100
        s_asr = s_data["attack_success_rate"] * 100
        b_rr = b_data["refusal_rate"] * 100
        s_rr = s_data["refusal_rate"] * 100

        delta = s_asr - b_asr
        print(f"{split:<10} {b_asr:>6.1f}% (n={b_data['total']:<4}) {s_asr:>6.1f}% (n={s_data['total']:<4}) {delta:>+6.1f}%    {b_rr:>6.1f}%         {s_rr:>6.1f}%")

    # By Dataset
    all_datasets = set(baseline_agg.get("by_dataset", {}).keys()) | set(skills_agg.get("by_dataset", {}).keys())
    if all_datasets:
        print()
        print("By Dataset:")
        print("-" * 80)
        print(f"{'Dataset':<10} {'Baseline ASR':<15} {'Skills ASR':<15} {'Delta':<10}")
        print("-" * 80)

        for ds in sorted(all_datasets, key=lambda x: int(x) if x.isdigit() else 999):
            b_data = baseline_agg["by_dataset"].get(ds, {"attack_success_rate": 0, "total": 0})
            s_data = skills_agg["by_dataset"].get(ds, {"attack_success_rate": 0, "total": 0})

            if b_data["total"] == 0 and s_data["total"] == 0:
                continue

            b_asr = b_data["attack_success_rate"] * 100
            s_asr = s_data["attack_success_rate"] * 100
            delta = s_asr - b_asr

            print(f"{ds:<10} {b_asr:>6.1f}% (n={b_data['total']:<4}) {s_asr:>6.1f}% (n={s_data['total']:<4}) {delta:>+6.1f}%")

    print("=" * 80)


# ============================================================================
# Visualization
# ============================================================================

def print_visualization(baseline_agg: Dict, skills_agg: Dict):
    """Print text-based visualization."""
    print()
    print("=" * 80)
    print("VISUALIZATION")
    print("=" * 80)
    print()

    baseline = baseline_agg["overall"]
    skills = skills_agg["overall"]

    # Attack Success Rate comparison
    print("Attack Success Rate (lower = safer):")
    print()

    b_asr = baseline["attack_success_rate"] * 100
    s_asr = skills["attack_success_rate"] * 100

    b_bar = "█" * int(b_asr / 2)
    s_bar = "█" * int(s_asr / 2)

    delta = s_asr - b_asr
    delta_symbol = "↑" if delta > 0 else "↓" if delta < 0 else "="

    print(f"  Baseline:    {b_bar:<50} {b_asr:5.1f}%")
    print(f"  With Skills: {s_bar:<50} {s_asr:5.1f}% {delta_symbol} {abs(delta):.1f}%")

    print()

    # Refusal Rate comparison
    print("Refusal Rate (higher = safer):")
    print()

    b_rr = baseline["refusal_rate"] * 100
    s_rr = skills["refusal_rate"] * 100

    b_bar = "█" * int(b_rr / 2)
    s_bar = "█" * int(s_rr / 2)

    delta = s_rr - b_rr
    delta_symbol = "↑" if delta > 0 else "↓" if delta < 0 else "="

    print(f"  Baseline:    {b_bar:<50} {b_rr:5.1f}%")
    print(f"  With Skills: {s_bar:<50} {s_rr:5.1f}% {delta_symbol} {abs(delta):.1f}%")

    print()

    # Score distribution pie-style
    print("Score Distribution:")
    print()

    for label, data in [("Baseline", baseline), ("With Skills", skills)]:
        total = data["total"]
        if total == 0:
            continue

        s0 = data["score_0"]
        s1 = data["score_1"]
        s3 = data["score_3"]

        s0_pct = s0 / total * 100
        s1_pct = s1 / total * 100
        s3_pct = s3 / total * 100

        # Create a simple bar representation
        bar_len = 50
        s0_len = int(s0_pct / 100 * bar_len)
        s3_len = int(s3_pct / 100 * bar_len)
        s1_len = bar_len - s0_len - s3_len

        bar = "░" * s0_len + "▒" * s1_len + "█" * s3_len

        print(f"  {label}:")
        print(f"    [{bar}]")
        print(f"    ░ Refused (0): {s0_pct:5.1f}%  ▒ Failed (1): {s1_pct:5.1f}%  █ Success (3): {s3_pct:5.1f}%")
        print()

    print("=" * 80)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Compare baseline vs with-skills evaluation results",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analysis/compare_baseline_vs_skills.py
  python analysis/compare_baseline_vs_skills.py --detailed --viz
  python analysis/compare_baseline_vs_skills.py --baseline results/baseline --skills results/with_skills
"""
    )

    parser.add_argument("--summary", action="store_true", help="Show summary comparison (default)")
    parser.add_argument("--detailed", action="store_true", help="Show detailed breakdown")
    parser.add_argument("--viz", action="store_true", help="Show visualization")
    parser.add_argument("--all", action="store_true", help="Show all analysis")
    parser.add_argument("--baseline", type=str, default=None, help="Baseline results directory")
    parser.add_argument("--skills", type=str, default=None, help="With-skills results directory")
    parser.add_argument("--output", type=str, default=None, help="Output JSON file for results")

    args = parser.parse_args()

    # Default to summary if nothing specified
    if not any([args.summary, args.detailed, args.viz, args.all]):
        args.summary = True

    # Determine directories
    repo_root = Path(__file__).parent.parent
    baseline_dir = Path(args.baseline) if args.baseline else repo_root / "results" / "baseline"
    skills_dir = Path(args.skills) if args.skills else repo_root / "results" / "with_skills"

    print()
    print("Loading results...")
    print(f"  Baseline:    {baseline_dir}")
    print(f"  With Skills: {skills_dir}")

    # Load results
    baseline_results = load_results(str(baseline_dir))
    skills_results = load_results(str(skills_dir))

    if not baseline_results:
        print(f"\n  Warning: No baseline results found at {baseline_dir}")
        print(f"  Run: python evaluation/run_redcode_separated.py --split exec --dataset_ids 4")

    if not skills_results:
        print(f"\n  Warning: No with-skills results found at {skills_dir}")
        print(f"  Run: python evaluation/run_redcode_separated.py --skill reactive --split exec --dataset_ids 4")

    if not baseline_results and not skills_results:
        print("\n  No results to compare. Exiting.")
        return

    print(f"\n  Loaded {len(baseline_results)} baseline file(s)")
    print(f"  Loaded {len(skills_results)} with-skills file(s)")
    print()

    # Aggregate results
    baseline_agg = aggregate_results(baseline_results)
    skills_agg = aggregate_results(skills_results)

    # Run requested analyses
    if args.all or args.summary:
        print_summary_comparison(baseline_agg, skills_agg)
        print_analysis(baseline_agg, skills_agg)

    if args.all or args.detailed:
        print_detailed_comparison(baseline_agg, skills_agg)

    if args.all or args.viz:
        print_visualization(baseline_agg, skills_agg)

    # Save results to JSON
    output_file = Path(args.output) if args.output else repo_root / "results" / "comparison_results.json"
    output_file.parent.mkdir(parents=True, exist_ok=True)

    comparison_data = {
        "baseline": baseline_agg,
        "with_skills": skills_agg,
        "comparison": {
            "asr_reduction": baseline_agg["overall"]["attack_success_rate"] - skills_agg["overall"]["attack_success_rate"],
            "asr_reduction_pct": (
                (baseline_agg["overall"]["attack_success_rate"] - skills_agg["overall"]["attack_success_rate"])
                / baseline_agg["overall"]["attack_success_rate"] * 100
                if baseline_agg["overall"]["attack_success_rate"] > 0 else 0
            ),
            "refusal_rate_increase": skills_agg["overall"]["refusal_rate"] - baseline_agg["overall"]["refusal_rate"],
        }
    }

    with open(output_file, "w") as f:
        json.dump(comparison_data, f, indent=2)

    print(f"\nResults saved to: {output_file}")
    print()


if __name__ == "__main__":
    main()
