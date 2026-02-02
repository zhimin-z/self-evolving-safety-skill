#!/usr/bin/env python3
"""
Analyze RedCode evaluation results and output as CSV dataframe.

Each row contains score frequencies and rates for a unique combination of:
- agent_name, model_name, redcode_split, skill_type, mode, is_baseline, dataset_id

The mode field is the unified variant identifier for all skill types:
- reactive/proactive: "aggregate" or "separate"
- constitutional: safety standard stems joined by hyphens
  (e.g., "claudes-constitution-nist_ai_rmf_playbook-owaspai_general_controls")

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
    mode: str  # "aggregate", "separate", or constitutional standard stems
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
            "mode": self.mode,
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
    # Key: (agent, model, split, skill, mode, is_baseline, dataset_id)
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
        agent, model, split, skill, mode, is_baseline, dataset_id = key
        total = scores["score_0"] + scores["score_1"] + scores["score_3"]

        if total == 0:
            continue

        rows.append(DataFrameRow(
            agent_name=agent,
            model_name=model,
            redcode_split=split,
            skill_type=skill,
            mode=mode,
            is_baseline=is_baseline,
            dataset_id=dataset_id,
            score_0=scores["score_0"],
            score_1=scores["score_1"],
            score_3=scores["score_3"],
            refusal_rate=scores["score_0"] / total if total else 0.0,
            attack_success_rate=scores["score_3"] / total if total else 0.0,
        ))

    return rows


def parse_filename_metadata(filename: str) -> Dict[str, str]:
    """Extract metadata from result filename.

    Filename format: {agent}_{model}_{split}_{datasets}_{skill-mode}_{baseline|skill}_run{N}.json

    The skill-mode part uses a hyphen to join skill_type and mode suffix:
    - reactive-aggregate, proactive-separate
    - constitutional-claudes-constitution-nist_ai_rmf_playbook-...
    """
    meta = {
        "split": "unknown",
        "skill": "unknown",
        "mode": "",
        "is_baseline": "unknown",
        "dataset_id": "unknown",
    }

    stem = Path(filename).stem
    parts = stem.split("_")

    # Find split (exec/gen)
    for part in parts:
        if part in ("exec", "gen"):
            meta["split"] = part
            break

    # Find skill type and mode (unified: mode contains the suffix for all skill types).
    # The mode suffix may contain underscores (e.g. nist_ai_rmf_playbook), so we
    # reconstruct it by joining parts from the skill-type prefix up to the next
    # known terminator (baseline, skill, run\d+).
    skill_types = ("reactive", "proactive", "constitutional")
    terminators = {"baseline", "skill"}
    for i, part in enumerate(parts):
        found_st = None
        if part in skill_types:
            found_st = part
            mode_start = None
        else:
            for st in skill_types:
                if part.startswith(f"{st}-"):
                    found_st = st
                    mode_start = part[len(f"{st}-"):]
                    break

        if found_st:
            meta["skill"] = found_st
            if mode_start is not None:
                # Collect remaining mode parts until a terminator
                mode_parts = [mode_start]
                for j in range(i + 1, len(parts)):
                    if parts[j] in terminators or parts[j].startswith("run"):
                        break
                    mode_parts.append(parts[j])
                meta["mode"] = "_".join(mode_parts)
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

        # Parse split, skill, and baseline from filename (as fallback)
        filename_meta = parse_filename_metadata(filepath.name)
        split = filename_meta["split"]

        # Prefer JSON metadata if available (new format), fallback to filename parsing
        skill = data.get("Skill Type", filename_meta["skill"])

        # Extract mode from JSON or filename (unified for all skill types)
        mode = data.get("Skill Mode") or filename_meta.get("mode", "")
        if mode is None:
            mode = ""
        # Handle legacy format where Skill Mode was a list
        if isinstance(mode, list):
            mode = "-".join(Path(f).stem for f in mode) if mode != ["all"] else "all"

        # Get baseline status from JSON or filename
        json_baseline = data.get("Is Baseline")
        if json_baseline is not None:
            is_baseline = "yes" if json_baseline else "no"
        else:
            is_baseline = filename_meta["is_baseline"]

        # Extract dataset_id from Dataset IDs field or filename
        dataset_ids = data.get("Dataset IDs", [])
        if not dataset_ids:
            dataset_ids = [filename_meta.get("dataset_id", "unknown")]

        # Aggregate scores from "Score Distribution"
        # Each prompt type has a dict like {"0": 15, "3": 10, "1": 5}
        score_by_type = data.get("Score Distribution", {})
        for dataset_id in dataset_ids:
            key = (agent, model, split, skill, mode, is_baseline, str(dataset_id))

            for _prompt_label, score_counts in score_by_type.items():
                for score_str, count in score_counts.items():
                    score = int(score_str)
                    if score == 0:
                        aggregated[key]["score_0"] += count
                    elif score == 1:
                        aggregated[key]["score_1"] += count
                    elif score == 3:
                        aggregated[key]["score_3"] += count

        return True

    except (json.JSONDecodeError, IOError, KeyError) as e:
        print(f"  Warning: Could not load {filepath}: {e}")
        return None


def print_dataframe(rows: List[DataFrameRow]):
    """Print dataframe as table."""
    if not rows:
        print("\nNo data to display.")
        return

    print("\n" + "=" * 150)
    print(f"{'Agent':<15} {'Model':<25} {'Split':<6} {'Skill':<14} {'Mode':<35} {'Base':<5} {'DS':<4} {'S0':<4} {'S1':<4} {'S3':<4} {'RR':>7} {'ASR':>7}")
    print("=" * 150)

    # Sort rows
    sorted_rows = sorted(rows, key=lambda r: (
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.mode, r.is_baseline, r.dataset_id
    ))

    for r in sorted_rows:
        # Truncate long fields for display
        model_short = r.model_name[:23] + ".." if len(r.model_name) > 25 else r.model_name
        mode_short = r.mode[:33] + ".." if len(r.mode) > 35 else r.mode
        print(
            f"{r.agent_name:<15} {model_short:<25} {r.redcode_split:<6} {r.skill_type:<14} "
            f"{mode_short:<35} {r.is_baseline:<5} {r.dataset_id:<4} {r.score_0:<4} {r.score_1:<4} {r.score_3:<4} "
            f"{r.refusal_rate*100:>6.1f}% {r.attack_success_rate*100:>6.1f}%"
        )

    print("=" * 150)
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
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.mode, r.is_baseline, r.dataset_id
    ))

    df = pd.DataFrame([row.to_dict() for row in sorted_rows])
    df.to_csv(output_path, index=False)

    print(f"\nReport saved to: {output_path}")


if __name__ == "__main__":
    main()
