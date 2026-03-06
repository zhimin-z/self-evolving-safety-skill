#!/usr/bin/env python3
"""
Analyze RedCode evaluation results and output as CSV dataframe.

Each row contains per-prompt-type score frequencies, refusal rates, and attack
success rates for a unique combination of:
- agent_name, model_name, redcode_split, skill_type, mode, is_baseline, dataset_id

Prompt types tracked separately: Code, Code w/ jb, Summary, Details, Code Generation.

Exec types (Code, Code w/ jb, Summary, Details) use scores 0/1/3:
  - RR = s0/total, ASR = s3/total

Gen type (Code Generation) uses LLM judge scores 0/1/5/8/10:
  - RR = s0/total, ASR (Ten Rate) = s10/total

An "overall" aggregate across all prompt types is also computed.

Usage:
    python src/analyze_redcode.py
"""

import json

import pandas as pd
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


# Canonical prompt type keys used in column names
PROMPT_TYPES = ["code", "code_jb", "summary", "details", "code_gen"]

# Mapping from JSON "Score Distribution" keys to canonical prompt type keys
PROMPT_TYPE_MAP = {
    "Code": "code",
    "Code w/ jb": "code_jb",
    "Summary": "summary",
    "Details": "details",
    "Code Generation": "code_gen",
}

# Score bucket names: covers both exec (s0,s1,s3) and gen (s0,s1,s5,s8,s10)
ALL_SCORE_KEYS = ("s0", "s1", "s3", "s5", "s8", "s10")


def _empty_scores() -> Dict[str, int]:
    return {k: 0 for k in ALL_SCORE_KEYS}


def _total(scores: Dict[str, int]) -> int:
    return sum(scores.get(k, 0) for k in ALL_SCORE_KEYS)


def _rr(scores: Dict[str, int]) -> float:
    """Refusal Rate: fraction of score=0."""
    total = _total(scores)
    return scores.get("s0", 0) / total if total else 0.0


def _asr_exec(scores: Dict[str, int]) -> float:
    """Exec ASR: fraction of score=3 (attack succeeded)."""
    total = _total(scores)
    return scores.get("s3", 0) / total if total else 0.0


def _asr_gen(scores: Dict[str, int]) -> float:
    """Gen ASR (Ten Rate / Accuracy): fraction of score=10."""
    total = _total(scores)
    return scores.get("s10", 0) / total if total else 0.0


@dataclass
class DataFrameRow:
    """Single row in the output dataframe."""
    agent_name: str
    model_name: str
    redcode_split: str  # "exec" or "gen"
    skill_type: str
    mode: str
    is_baseline: str
    dataset_id: str
    # Per-prompt-type scores: dict mapping canonical type -> {s0, s1, s3, s5, s8, s10}
    type_scores: Dict[str, Dict[str, int]] = field(default_factory=dict)

    @property
    def is_gen(self) -> bool:
        return self.redcode_split == "gen"

    def _rr(self, scores: Dict[str, int]) -> float:
        return _rr(scores)

    def _asr(self, scores: Dict[str, int]) -> float:
        return _asr_gen(scores) if self.is_gen else _asr_exec(scores)

    def _overall_scores(self) -> Dict[str, int]:
        overall = _empty_scores()
        for scores in self.type_scores.values():
            for k in ALL_SCORE_KEYS:
                overall[k] += scores.get(k, 0)
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
            for k in ALL_SCORE_KEYS:
                d[f"{pt}_{k}"] = scores.get(k, 0)
            d[f"{pt}_RR"] = self._rr(scores)
            d[f"{pt}_ASR"] = self._asr(scores)

        # Overall columns
        overall = self._overall_scores()
        for k in ALL_SCORE_KEYS:
            d[f"overall_{k}"] = overall[k]
        d["overall_RR"] = self._rr(overall)
        d["overall_ASR"] = self._asr(overall)

        return d


def load_and_process_results(results_dir: Path) -> List[DataFrameRow]:
    """Load all result files and aggregate by unique key."""
    # Key: (agent, model, split, skill, mode, is_baseline, dataset_id)
    # Value: dict mapping canonical prompt type -> {s0, s1, s3, s5, s8, s10}
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
        total = sum(_total(s) for s in type_scores.values())
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


# Map raw integer scores to bucket keys
_SCORE_TO_BUCKET = {0: "s0", 1: "s1", 3: "s3", 5: "s5", 8: "s8", 10: "s10"}


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
                bucket = _SCORE_TO_BUCKET.get(score)
                if bucket:
                    aggregated[key][canonical][bucket] += count
                else:
                    print(f"  Warning: Unknown score {score} in {filepath.name}, skipping")

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
        f"{'Gen RR':>8} {'Gen ASR':>9} "
        f"{'All RR':>8} {'All ASR':>9}"
    )
    print(header)
    print("=" * 200)

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
            f"{d['code_gen_RR']*100:>7.1f}% {d['code_gen_ASR']*100:>8.1f}% "
            f"{d['overall_RR']*100:>7.1f}% {d['overall_ASR']*100:>8.1f}%"
        )

    print("=" * 200)
    print(f"Total rows: {len(rows)}")


def build_averaged_report(df: pd.DataFrame) -> pd.DataFrame:
    """Average RR/ASR across all dataset_ids for each (agent, model, split, skill, mode, is_baseline) group."""
    group_cols = ["agent_name", "model_name", "redcode_split", "skill_type", "mode", "is_baseline"]

    # Columns to average: all RR and ASR columns
    metric_cols = []
    for pt in PROMPT_TYPES + ["overall"]:
        metric_cols.extend([f"{pt}_RR", f"{pt}_ASR"])

    # Also sum raw score counts for reference
    count_cols = []
    for pt in PROMPT_TYPES + ["overall"]:
        for k in ALL_SCORE_KEYS:
            count_cols.append(f"{pt}_{k}")

    agg_dict = {}
    for col in metric_cols:
        if col in df.columns:
            agg_dict[col] = "mean"
    for col in count_cols:
        if col in df.columns:
            agg_dict[col] = "sum"
    agg_dict["dataset_id"] = "count"

    avg_df = df.groupby(group_cols, as_index=False).agg(agg_dict)
    avg_df = avg_df.rename(columns={"dataset_id": "n_datasets"})

    # Reorder columns: group cols, n_datasets, then per-type metrics, then overall
    ordered = list(group_cols) + ["n_datasets"]
    for pt in PROMPT_TYPES + ["overall"]:
        for k in ALL_SCORE_KEYS:
            ordered.append(f"{pt}_{k}")
        ordered.extend([f"{pt}_RR", f"{pt}_ASR"])
    avg_df = avg_df[[c for c in ordered if c in avg_df.columns]]

    avg_df = avg_df.sort_values(group_cols).reset_index(drop=True)
    return avg_df


def print_averaged_report(avg_df: pd.DataFrame):
    """Print averaged report to console."""
    print("\n" + "=" * 180)
    print("AVERAGED ACROSS DATASETS")
    print("=" * 180)
    header = (
        f"{'Agent':<15} {'Model':<25} {'Split':<6} {'Skill':<14} {'Mode':<25} {'Base':<5} {'N':>3} "
        f"{'Code RR':>8} {'Code ASR':>9} "
        f"{'Jb RR':>7} {'Jb ASR':>8} "
        f"{'Sum RR':>8} {'Sum ASR':>9} "
        f"{'Det RR':>8} {'Det ASR':>9} "
        f"{'Gen RR':>8} {'Gen ASR':>9} "
        f"{'All RR':>8} {'All ASR':>9}"
    )
    print(header)
    print("-" * 180)

    for _, r in avg_df.iterrows():
        model_short = r["model_name"][:23] + ".." if len(str(r["model_name"])) > 25 else r["model_name"]
        mode_short = r["mode"][:23] + ".." if len(str(r["mode"])) > 25 else r["mode"]
        print(
            f"{r['agent_name']:<15} {model_short:<25} {r['redcode_split']:<6} {r['skill_type']:<14} "
            f"{mode_short:<25} {r['is_baseline']:<5} {r['n_datasets']:>3} "
            f"{r['code_RR']*100:>7.1f}% {r['code_ASR']*100:>8.1f}% "
            f"{r['code_jb_RR']*100:>6.1f}% {r['code_jb_ASR']*100:>7.1f}% "
            f"{r['summary_RR']*100:>7.1f}% {r['summary_ASR']*100:>8.1f}% "
            f"{r['details_RR']*100:>7.1f}% {r['details_ASR']*100:>8.1f}% "
            f"{r['code_gen_RR']*100:>7.1f}% {r['code_gen_ASR']*100:>8.1f}% "
            f"{r['overall_RR']*100:>7.1f}% {r['overall_ASR']*100:>8.1f}%"
        )

    print("=" * 180)
    print(f"Total groups: {len(avg_df)}")


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

    # Save detailed CSV (per-dataset)
    reports_dir.mkdir(parents=True, exist_ok=True)

    sorted_rows = sorted(rows, key=lambda r: (
        r.agent_name, r.model_name, r.redcode_split, r.skill_type, r.mode, r.is_baseline, r.dataset_id
    ))
    df = pd.DataFrame([row.to_dict() for row in sorted_rows])

    detail_path = reports_dir / "analysis_report.csv"
    df.to_csv(detail_path, index=False)
    print(f"\nDetailed report saved to: {detail_path}")

    # Save averaged CSV (across datasets)
    avg_df = build_averaged_report(df)
    print_averaged_report(avg_df)

    avg_path = reports_dir / "analysis_report_averaged.csv"
    avg_df.to_csv(avg_path, index=False)
    print(f"\nAveraged report saved to: {avg_path}")


if __name__ == "__main__":
    main()
