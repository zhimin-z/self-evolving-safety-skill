#!/usr/bin/env python3
"""
Analyze RedCode evaluation results and output as CSV dataframe.

Each row contains score frequencies and rates for a unique combination of:
- agent_name, model_name, redcode_split, skill_type, is_baseline, dataset_id

Usage:
    python analysis/analyze_attacks.py
"""

import json

import pandas as pd
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class DataFrameRow:
    """Single row in the output dataframe."""
    agent_name: str
    model_name: str
    redcode_split: str
    skill_type: str
    is_baseline: str  # "yes" or "no"
    dataset_id: str
    score_0: int
    score_1: int
    score_3: int
    refusal_rate: float
    attack_success_rate: float

    def to_dict(self) -> Dict:
        return {
            "agent_name": self.agent_name,
            "model_name": self.model_name,
            "redcode_split": self.redcode_split,
            "skill_type": self.skill_type,
            "is_baseline": self.is_baseline,
            "dataset_id": self.dataset_id,
            "score_0": self.score_0,
            "score_1": self.score_1,
            "score_3": self.score_3,
            "refusal_rate": self.refusal_rate,
            "attack_success_rate": self.attack_success_rate,
        }


def load_and_process_results(results_dir: Path) -> List[DataFrameRow]:
    """Load all result files and aggregate by unique key."""
    # Key: (agent, model, split, skill, is_baseline, dataset_id)
    # Value: {score_0, score_1, score_3}
    aggregated: Dict[tuple, Dict[str, int]] = defaultdict(
        lambda: {"score_0": 0, "score_1": 0, "score_3": 0}
    )

    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        return []

    for json_file in sorted(results_dir.glob("*.json")):
        # Skip non-result files
        if "comparison" in json_file.name.lower() or "log" in json_file.name.lower():
            continue

        result = load_single_file(json_file, aggregated)
        if result:
            print(f"  Loaded: {json_file.name}")

    # Convert aggregated data to rows
    rows = []
    for key, scores in aggregated.items():
        agent, model, split, skill, is_baseline, dataset_id = key
        total = scores["score_0"] + scores["score_1"] + scores["score_3"]

        if total == 0:
            continue

        rows.append(DataFrameRow(
            agent_name=agent,
            model_name=model,
            redcode_split=split,
            skill_type=skill,
            is_baseline=is_baseline,
            dataset_id=dataset_id,
            score_0=scores["score_0"],
            score_1=scores["score_1"],
            score_3=scores["score_3"],
            refusal_rate=scores["score_0"] / total,
            attack_success_rate=scores["score_3"] / total,
        ))

    return rows


def parse_filename_metadata(filename: str) -> Dict[str, str]:
    """Parse metadata from result filename.

    Filename format: {split}_{datasets}_{agent}_{skill}_{baseline|skill}_run{N}_{model}_{timestamp}.json
    Examples:
        exec_1-2-3_minisweagent_proactive_baseline_claude-haiku-4.5_2026-01-22_10-30-00.json
        gen_ransomware_minisweagent_reactive_skill_run1_claude-haiku-4.5_2026-01-22_10-30-00.json
    """
    name = filename.replace(".json", "")
    parts = name.split("_")

    # Defaults
    meta = {
        "split": "exec",
        "skill": "unknown",
        "is_baseline": "no",
    }

    # First part is always split (exec/gen)
    if parts and parts[0] in ("exec", "gen"):
        meta["split"] = parts[0]

    # Find skill type (reactive/proactive/constitutional)
    skill_types = ("reactive", "proactive", "constitutional")
    for part in parts:
        if part in skill_types:
            meta["skill"] = part
            break

    # Baseline status from "_baseline_" or "_skill_" in filename
    if "_baseline_" in filename:
        meta["is_baseline"] = "yes"
    elif "_skill_" in filename:
        meta["is_baseline"] = "no"

    return meta


def load_single_file(filepath: Path, aggregated: Dict) -> Optional[bool]:
    """Load a single result file and add to aggregated data."""
    try:
        with open(filepath) as f:
            data = json.load(f)

        # Skip non-result files
        if isinstance(data, list) or "Score Distribution" not in data:
            return None

        # Extract metadata from JSON (agent, model) and filename (split, skill, baseline)
        agent = data.get("Agent", "unknown")
        model = data.get("Model", "unknown")

        # Parse split, skill, and baseline from filename
        filename_meta = parse_filename_metadata(filepath.name)
        split = filename_meta["split"]
        skill = filename_meta["skill"]
        is_baseline = filename_meta["is_baseline"]

        # Process per-case results
        per_case = data.get("Per-Case Results", data.get("Results", []))
        for case in per_case:
            # Extract dataset_id from case_id (format: "dataset_id_index", e.g., "4_1" or "ransomware_file1")
            case_id = case.get("case_id", "unknown_0")
            dataset_id = case_id.rsplit("_", 1)[0] if "_" in case_id else case_id
            score = case.get("score", 1)

            key = (agent, model, split, skill, is_baseline, dataset_id)

            if score == 0:
                aggregated[key]["score_0"] += 1
            elif score == 1:
                aggregated[key]["score_1"] += 1
            elif score == 3:
                aggregated[key]["score_3"] += 1

        return True

    except (json.JSONDecodeError, IOError, KeyError) as e:
        print(f"  Warning: Could not load {filepath}: {e}")
        return None


def print_dataframe(rows: List[DataFrameRow]):
    """Print dataframe as table."""
    if not rows:
        print("\nNo data to display.")
        return

    print("\n" + "=" * 130)
    print(f"{'Agent':<15} {'Model':<35} {'Split':<6} {'Skill':<12} {'Baseline':<8} {'DS':<4} {'S0':<4} {'S1':<4} {'S3':<4} {'RR':>7} {'ASR':>7}")
    print("=" * 130)

    # Sort rows
    sorted_rows = sorted(rows, key=lambda r: (
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.is_baseline, r.dataset_id
    ))

    for r in sorted_rows:
        print(
            f"{r.agent_name:<15} {r.model_name:<35} {r.redcode_split:<6} {r.skill_type:<12} "
            f"{r.is_baseline:<8} {r.dataset_id:<4} {r.score_0:<4} {r.score_1:<4} {r.score_3:<4} "
            f"{r.refusal_rate*100:>6.1f}% {r.attack_success_rate*100:>6.1f}%"
        )

    print("=" * 130)
    print(f"Total rows: {len(rows)}")


def main():
    # Fixed paths
    repo_root = Path(__file__).parent.parent
    results_dir = repo_root / "results"
    reports_dir = repo_root / "reports"

    print()
    print(f"Loading results from: {results_dir}")

    # Load and process
    rows = load_and_process_results(results_dir)

    if not rows:
        print("\n  No result files found.")
        print("  Run evaluations first to generate results.")
        return

    # Print table
    print_dataframe(rows)

    # Save as CSV
    reports_dir.mkdir(parents=True, exist_ok=True)
    output_path = reports_dir / "analysis_report.csv"

    sorted_rows = sorted(rows, key=lambda r: (
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.is_baseline, r.dataset_id
    ))

    df = pd.DataFrame([row.to_dict() for row in sorted_rows])
    df.to_csv(output_path, index=False)

    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
