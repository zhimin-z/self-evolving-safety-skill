#!/usr/bin/env python3
"""
Analyze RedCode evaluation results and output as CSV dataframe.

Each row contains per-prompt-type score frequencies, refusal rates, and attack
success rates for a unique combination of:
- agent_name, model_name, redcode_split, skill_type, mode, is_baseline, dataset_id

Prompt types tracked separately: Code, Code w/ jb, Summary, Details.
Each gets: s0, s1, s3, RR (refusal rate), ASR (attack success rate).
An "overall" aggregate across all prompt types is also computed.

Usage:
    python analysis/analyze_redcode.py
"""

import json

import pandas as pd
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# Canonical prompt type keys used in column names
PROMPT_TYPES = ["code", "code_jb", "summary", "details"]

# Mapping from JSON "Score Distribution" keys to canonical prompt type keys
PROMPT_TYPE_MAP = {
    "Code": "code",
    "Code w/ jb": "code_jb",
    "Summary": "summary",
    "Details": "details",
}


def _empty_scores() -> Dict[str, int]:
    return {"s0": 0, "s1": 0, "s3": 0}


@dataclass
class DataFrameRow:
    """Single row in the output dataframe."""
    agent_name: str
    model_name: str
    redcode_split: str
    skill_type: str
    mode: str
    is_baseline: str
    dataset_id: str
    # Per-prompt-type scores: dict mapping canonical type -> {s0, s1, s3}
    type_scores: Dict[str, Dict[str, int]] = field(default_factory=dict)

    def _rr(self, scores: Dict[str, int]) -> float:
        total = scores["s0"] + scores["s1"] + scores["s3"]
        return scores["s0"] / total if total else 0.0

    def _asr(self, scores: Dict[str, int]) -> float:
        total = scores["s0"] + scores["s1"] + scores["s3"]
        return scores["s3"] / total if total else 0.0

    def _overall_scores(self) -> Dict[str, int]:
        overall = _empty_scores()
        for scores in self.type_scores.values():
            for k in ("s0", "s1", "s3"):
                overall[k] += scores[k]
        return overall

    def to_dict(self) -> Dict:
        d = {
            "agent_name": self.agent_name,
            "model_name": self.model_name,
            "redcode_split": self.redcode_split,
            "skill_type": self.skill_type,
            "mode": self.mode,
            "is_baseline": self.is_baseline,
            "dataset_id": self.dataset_id,
        }

        # Per-prompt-type columns
        for pt in PROMPT_TYPES:
            scores = self.type_scores.get(pt, _empty_scores())
            d[f"{pt}_s0"] = scores["s0"]
            d[f"{pt}_s1"] = scores["s1"]
            d[f"{pt}_s3"] = scores["s3"]
            d[f"{pt}_RR"] = self._rr(scores)
            d[f"{pt}_ASR"] = self._asr(scores)

        # Overall columns
        overall = self._overall_scores()
        d["overall_s0"] = overall["s0"]
        d["overall_s1"] = overall["s1"]
        d["overall_s3"] = overall["s3"]
        d["overall_RR"] = self._rr(overall)
        d["overall_ASR"] = self._asr(overall)

        return d


def load_and_process_results(results_dir: Path) -> List[DataFrameRow]:
    """Load all result files and aggregate by unique key."""
    # Key: (agent, model, split, skill, mode, is_baseline, dataset_id)
    # Value: dict mapping canonical prompt type -> {s0, s1, s3}
    aggregated: Dict[tuple, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: {pt: _empty_scores() for pt in PROMPT_TYPES}
    )

    if not results_dir.exists():
        print(f"Results directory not found: {results_dir}")
        return []

    for json_file in sorted(results_dir.glob("*.json")):
        if "comparison" in json_file.name.lower() or "log" in json_file.name.lower():
            continue

        result = load_single_file(json_file, aggregated)
        if result:
            print(f"  Loaded: {json_file.name}")

    # Convert aggregated data to rows
    rows = []
    for key, type_scores in aggregated.items():
        agent, model, split, skill, mode, is_baseline, dataset_id = key

        # Check if there's any data at all
        total = sum(
            s["s0"] + s["s1"] + s["s3"] for s in type_scores.values()
        )
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
            type_scores=dict(type_scores),
        ))

    return rows


def parse_filename_metadata(filename: str) -> Dict[str, str]:
    """Extract metadata from result filename.

    Filename format: {agent}_{model}_{split}_{datasets}_{skill-mode}_{baseline|skill}_run{N}.json
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

    for part in parts:
        if part in ("exec", "gen"):
            meta["split"] = part
            break

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
                mode_parts = [mode_start]
                for j in range(i + 1, len(parts)):
                    if parts[j] in terminators or parts[j].startswith("run"):
                        break
                    mode_parts.append(parts[j])
                meta["mode"] = "_".join(mode_parts)
            break

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

        if isinstance(data, list) or "Score Distribution" not in data:
            return None

        agent = data.get("Agent", "unknown")
        model = data.get("Model", "unknown")

        filename_meta = parse_filename_metadata(filepath.name)
        split = filename_meta["split"]

        skill = data.get("Skill Type", filename_meta["skill"])

        mode = data.get("Skill Mode") or filename_meta.get("mode", "")
        if mode is None:
            mode = ""
        if isinstance(mode, list):
            mode = "-".join(Path(f).stem for f in mode) if mode != ["all"] else "all"

        json_baseline = data.get("Is Baseline")
        if json_baseline is not None:
            is_baseline = "yes" if json_baseline else "no"
        else:
            is_baseline = filename_meta["is_baseline"]

        dataset_id = data.get("Dataset ID")
        if dataset_id is None:
            dataset_id = filename_meta.get("dataset_id", "unknown")

        score_by_type = data.get("Score Distribution", {})
        key = (agent, model, split, skill, mode, is_baseline, str(dataset_id))

        for prompt_label, score_counts in score_by_type.items():
            canonical = PROMPT_TYPE_MAP.get(prompt_label)
            if canonical is None:
                print(f"  Warning: Unknown prompt type '{prompt_label}' in {filepath.name}, skipping")
                continue

            for score_str, count in score_counts.items():
                score = int(score_str)
                if score == 0:
                    aggregated[key][canonical]["s0"] += count
                elif score == 1:
                    aggregated[key][canonical]["s1"] += count
                elif score == 3:
                    aggregated[key][canonical]["s3"] += count

        return True

    except (json.JSONDecodeError, IOError, KeyError) as e:
        print(f"  Warning: Could not load {filepath}: {e}")
        return None


def print_dataframe(rows: List[DataFrameRow]):
    """Print dataframe as table."""
    if not rows:
        print("\nNo data to display.")
        return

    sorted_rows = sorted(rows, key=lambda r: (
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.mode, r.is_baseline, r.dataset_id
    ))

    # Print per-prompt-type RR/ASR summary
    print("\n" + "=" * 180)
    header = (
        f"{'Agent':<15} {'Model':<25} {'Split':<6} {'Skill':<14} {'Mode':<25} {'Base':<5} {'DS':<4} "
        f"{'Code RR':>8} {'Code ASR':>9} "
        f"{'Jb RR':>7} {'Jb ASR':>8} "
        f"{'Sum RR':>8} {'Sum ASR':>9} "
        f"{'Det RR':>8} {'Det ASR':>9} "
        f"{'All RR':>8} {'All ASR':>9}"
    )
    print(header)
    print("=" * 180)

    for r in sorted_rows:
        d = r.to_dict()
        model_short = r.model_name[:23] + ".." if len(r.model_name) > 25 else r.model_name
        mode_short = r.mode[:23] + ".." if len(r.mode) > 25 else r.mode
        print(
            f"{r.agent_name:<15} {model_short:<25} {r.redcode_split:<6} {r.skill_type:<14} "
            f"{mode_short:<25} {r.is_baseline:<5} {r.dataset_id:<4} "
            f"{d['code_RR']*100:>7.1f}% {d['code_ASR']*100:>8.1f}% "
            f"{d['code_jb_RR']*100:>6.1f}% {d['code_jb_ASR']*100:>7.1f}% "
            f"{d['summary_RR']*100:>7.1f}% {d['summary_ASR']*100:>8.1f}% "
            f"{d['details_RR']*100:>7.1f}% {d['details_ASR']*100:>8.1f}% "
            f"{d['overall_RR']*100:>7.1f}% {d['overall_ASR']*100:>8.1f}%"
        )

    print("=" * 180)
    print(f"Total rows: {len(rows)}")


def main():
    repo_root = Path(__file__).parent.parent
    results_dir = repo_root / "results"
    reports_dir = repo_root / "reports"

    print()
    print(f"Loading results from: {results_dir}")

    rows = load_and_process_results(results_dir)

    if not rows:
        print("\n  No result files found.")
        print("  Run evaluations first to generate results.")
        return

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
