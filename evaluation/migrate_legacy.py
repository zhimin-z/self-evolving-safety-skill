#!/usr/bin/env python3
"""
Migrate legacy result JSONs and skill markdowns to new unified naming/format.

Handles 4 legacy result JSON formats:
  A) Array format (constitutional old): [{Index, Final Result: {Code, Code w/ jb, ...}}]
  B) Object with flat Score Distribution, no metadata fields
  C) Object with flat Score Distribution + Skill Type/Mode/Is Baseline fields
  D) Constitutional with mode in filename, array format

Handles legacy skill filename patterns:
  1) constitutional_{stems}_run{N}.md
  2) {skill_type}_aggregate_{split}_{datasets}_run{N}.md
  3) {skill_type}_{split}_{dataset}_run{N}.md  (separate implied)
  4) {skill_type}_separate_{split}_{dataset}_run{N}.md

New conventions:
  Result:  {agent}_{model}_{split}_{datasets}_{skill_type}-{mode}_{baseline|skill}_run{N}.json
  Skill:   {agent}_{model}_{split}_{datasets}_{skill_type}-{mode}_run{N}.md

Usage:
    python evaluation/migrate_legacy.py           # Dry run (preview changes)
    python evaluation/migrate_legacy.py --apply   # Apply changes (creates backup)
"""

import argparse
import json
import re
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Optional


# ─── Constants ───────────────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = REPO_ROOT / "results"
SKILLS_DIR = REPO_ROOT / "skills"
SAFETY_STANDARDS_DIR = REPO_ROOT / "safety_standards"
BACKUP_RESULTS_DIR = REPO_ROOT / "results_backup"
BACKUP_SKILLS_DIR = REPO_ROOT / "skills_backup"

DEFAULT_AGENT_DISPLAY = "mini-swe-agent"
DEFAULT_MODEL_SHORT = "claude-haiku-4.5"
DEFAULT_MODEL_FULL = "openrouter/anthropic/claude-haiku-4.5"
DEFAULT_SPLIT = "exec"
DEFAULT_RUN = 1

# Known safety standard file stems (sorted)
KNOWN_STANDARD_STEMS = sorted([
    p.stem for p in SAFETY_STANDARDS_DIR.rglob("*") if p.is_file()
]) if SAFETY_STANDARDS_DIR.exists() else []

# All-standards mode suffix: stems joined with hyphens
ALL_STANDARDS_MODE = "-".join(KNOWN_STANDARD_STEMS)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def get_model_short_name(model_name: str) -> str:
    """Extract short model name for filenames."""
    if "/" in model_name:
        model_name = model_name.split("/")[-1]
    # Strip date suffix like -20251001
    parts = model_name.rsplit("-", 1)
    if len(parts) == 2 and parts[1].isdigit() and len(parts[1]) == 8:
        model_name = parts[0]
    return model_name


def parse_constitutional_mode_stems(mode_str: str) -> List[str]:
    """Parse underscore-joined constitutional stems back into individual stems.

    Handles ambiguity where stems themselves contain underscores by matching
    against known safety standard stems (longest match first).
    """
    stems = []
    remaining = mode_str
    while remaining:
        matched = False
        for stem in sorted(KNOWN_STANDARD_STEMS, key=len, reverse=True):
            if remaining == stem:
                stems.append(stem)
                remaining = ""
                matched = True
                break
            elif remaining.startswith(stem + "_"):
                stems.append(stem)
                remaining = remaining[len(stem) + 1:]
                matched = True
                break
        if not matched:
            stems.append(remaining)
            remaining = ""
    return stems


def dataset_ids_str(dataset_ids: List[str]) -> str:
    """Convert dataset IDs list to filename string."""
    if not dataset_ids:
        return "unknown"
    ids = sorted(dataset_ids, key=lambda x: int(x) if x.isdigit() else 0)
    return "-".join(ids)


def extract_dataset_ids_from_results(results: list) -> List[str]:
    """Extract unique dataset IDs from per-case results (case_id format: {ds}_{idx}_{item})."""
    ds_set = set()
    for r in results:
        cid = r.get("case_id", "")
        parts = cid.split("_")
        if len(parts) >= 2 and parts[0].isdigit():
            ds_set.add(parts[0])
    return sorted(ds_set, key=lambda x: int(x))


# ─── Result file parsing ────────────────────────────────────────────────────

def parse_legacy_result_filename(filename: str) -> Optional[dict]:
    """Parse a legacy result filename and extract metadata.

    Strategy: find the _baseline_ or _skill_ marker, split around it,
    then parse each side independently.
    """
    stem = Path(filename).stem

    meta = {
        "split": DEFAULT_SPLIT,
        "dataset_ids": [],
        "skill_type": "unknown",
        "skill_mode": "",
        "is_baseline": True,
        "run_idx": DEFAULT_RUN,
        "model": DEFAULT_MODEL_SHORT,
        "model_full": DEFAULT_MODEL_FULL,
        "timestamp": "",
        "agent_display": DEFAULT_AGENT_DISPLAY,
    }

    # Find _baseline_ or _skill_ marker in the middle of the stem
    bl_match = re.search(r"_(baseline|skill)_", stem)
    if bl_match:
        before_bl = stem[:bl_match.start()]
        after_bl = stem[bl_match.end():]
        meta["is_baseline"] = bl_match.group(1) == "baseline"
    else:
        # Try marker at end of stem (unlikely but defensive)
        bl_match_end = re.search(r"_(baseline|skill)$", stem)
        if bl_match_end:
            before_bl = stem[:bl_match_end.start()]
            after_bl = ""
            meta["is_baseline"] = bl_match_end.group(1) == "baseline"
        else:
            return None

    # ── Parse after_bl: [run{N}_]model_date_time ──
    if after_bl:
        run_match = re.match(r"run(\d+)_(.*)", after_bl)
        if run_match:
            meta["run_idx"] = int(run_match.group(1))
            after_bl = run_match.group(2)

        # Extract timestamp YYYY-MM-DD_HH-MM-SS from end
        ts_match = re.search(r"_(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})$", after_bl)
        if ts_match:
            meta["timestamp"] = ts_match.group(1)
            model_part = after_bl[:ts_match.start()]
        else:
            model_part = after_bl

        if model_part:
            meta["model"] = get_model_short_name(model_part)

    # ── Parse before_bl: exec_{datasets}_{agent}_{skill_type}[-{mode}] ──
    parts = before_bl.split("_")

    if len(parts) < 3:
        return None

    # parts[0] = split
    meta["split"] = parts[0] if parts[0] in ("exec", "gen") else DEFAULT_SPLIT

    # parts[1] = dataset info
    dataset_part = parts[1]
    if "datasets" in dataset_part:
        n = int(dataset_part.replace("datasets", ""))
        meta["dataset_ids"] = [str(i) for i in range(1, n + 1)]
    elif dataset_part.isdigit():
        meta["dataset_ids"] = [dataset_part]
    else:
        meta["dataset_ids"] = [dataset_part]

    # parts[2] = agent (minisweagent), skip
    # parts[3:] = skill type and mode
    if len(parts) > 3:
        skill_mode_str = "_".join(parts[3:])

        for st in ("constitutional", "proactive", "reactive"):
            if skill_mode_str.startswith(st):
                meta["skill_type"] = st
                remainder = skill_mode_str[len(st):]
                if remainder.startswith("-"):
                    mode_raw = remainder[1:]
                    if st == "constitutional":
                        stems = parse_constitutional_mode_stems(mode_raw)
                        meta["skill_mode"] = "-".join(stems)
                    else:
                        meta["skill_mode"] = mode_raw
                elif remainder == "":
                    if st == "constitutional":
                        meta["skill_mode"] = ALL_STANDARDS_MODE
                    else:
                        meta["skill_mode"] = "separate"
                break

    return meta


# ─── Result content transformation ──────────────────────────────────────────

def transform_result_content(old_data, meta: dict) -> dict:
    """Transform legacy JSON content to new format."""
    if isinstance(old_data, list):
        return _transform_array_format(old_data, meta)
    else:
        return _transform_object_format(old_data, meta)


def _transform_array_format(data_list: list, meta: dict) -> dict:
    """Transform array format (constitutional old) to new format.

    Input: [{Index, Jsonfile, Task, Base Model, Timestamp, Duration, Final Result}]
    Final Result already has per-prompt-type score distribution.
    """
    entry = data_list[0] if data_list else {}
    model_full = entry.get("Base Model", meta.get("model_full", DEFAULT_MODEL_FULL))
    timestamp = entry.get("Timestamp", meta.get("timestamp", ""))
    duration = entry.get("Duration (seconds)", 0)
    final_result = entry.get("Final Result", {})

    score_dist = {}
    for key in ["Code", "Code w/ jb", "Summary", "Details"]:
        if key in final_result:
            score_dist[key] = {str(k): v for k, v in final_result[key].items()}
        else:
            score_dist[key] = {}

    return {
        "Agent": "minisweagent",
        "Model": model_full,
        "Skill Type": meta["skill_type"],
        "Skill Mode": meta["skill_mode"],
        "Is Baseline": meta["is_baseline"],
        "Run Index": meta.get("run_idx", DEFAULT_RUN),
        "Timestamp": timestamp,
        "Duration (seconds)": round(duration, 2),
        "Dry Run": False,
        "Split": meta.get("split", DEFAULT_SPLIT),
        "Dataset IDs": meta.get("dataset_ids", []),
        "Score Distribution": score_dist,
    }


def _transform_object_format(data: dict, meta: dict) -> dict:
    """Transform object format (proactive/reactive or intermediate) to new format.

    These files have flat Score Distribution and per-case Results.
    Since only text_details was evaluated, all scores go under 'Details'.
    """
    model_full = data.get("Model", meta.get("model_full", DEFAULT_MODEL_FULL))
    timestamp = data.get("Timestamp", meta.get("timestamp", ""))
    duration = data.get("Duration (seconds)", 0)

    # Get flat score distribution
    flat_dist = data.get("Score Distribution", {})
    results = data.get("Results", data.get("Per-Case Results", []))

    # Compute from results if flat distribution is missing
    if not flat_dist and results:
        scores = [r.get("score", 1) for r in results]
        flat_dist = dict(Counter(scores))

    # Normalize keys to strings
    flat_dist = {str(k): v for k, v in flat_dist.items()}

    # These were text_details-only evaluations
    score_dist = {
        "Code": {},
        "Code w/ jb": {},
        "Summary": {},
        "Details": flat_dist,
    }

    # Extract dataset IDs from results if richer than filename
    dataset_ids = meta.get("dataset_ids", [])
    if results:
        extracted = extract_dataset_ids_from_results(results)
        if len(extracted) > len(dataset_ids):
            dataset_ids = extracted

    # Prefer JSON metadata when available
    skill_type = data.get("Skill Type", meta.get("skill_type", "unknown"))

    mode = data.get("Skill Mode") or data.get("Mode") or meta.get("skill_mode", "")
    if isinstance(mode, list):
        mode = "-".join(Path(f).stem for f in mode) if mode != ["all"] else ALL_STANDARDS_MODE
    if not mode:
        mode = meta.get("skill_mode", "")

    is_baseline_json = data.get("Is Baseline")
    is_baseline = is_baseline_json if is_baseline_json is not None else meta.get("is_baseline", True)

    dry_run = False
    if "Config" in data:
        dry_run = data["Config"].get("dry_run", False)
    elif "Dry Run" in data:
        dry_run = data["Dry Run"]

    return {
        "Agent": data.get("Agent", "minisweagent"),
        "Model": model_full,
        "Skill Type": skill_type,
        "Skill Mode": mode if mode else meta.get("skill_mode", ""),
        "Is Baseline": is_baseline,
        "Run Index": meta.get("run_idx", DEFAULT_RUN),
        "Timestamp": timestamp,
        "Duration (seconds)": round(duration, 2),
        "Dry Run": dry_run,
        "Split": meta.get("split", DEFAULT_SPLIT),
        "Dataset IDs": dataset_ids,
        "Score Distribution": score_dist,
    }


def generate_new_result_filename(meta: dict) -> str:
    """Generate new-convention result filename."""
    agent = meta.get("agent_display", DEFAULT_AGENT_DISPLAY)
    model = meta.get("model", DEFAULT_MODEL_SHORT)
    split = meta.get("split", DEFAULT_SPLIT)
    dataset_ids = meta.get("dataset_ids", [])
    skill_type = meta["skill_type"]
    skill_mode = meta["skill_mode"]
    is_baseline = meta["is_baseline"]
    run_idx = meta.get("run_idx", DEFAULT_RUN)

    ds_str = dataset_ids_str(dataset_ids)
    skill_mode_part = f"{skill_type}-{skill_mode}" if skill_mode else skill_type
    bl_str = "baseline" if is_baseline else "skill"

    return f"{agent}_{model}_{split}_{ds_str}_{skill_mode_part}_{bl_str}_run{run_idx}.json"


# ─── Skill file parsing ─────────────────────────────────────────────────────

def parse_legacy_skill_filename(filename: str) -> Optional[dict]:
    """Parse a legacy skill filename and extract metadata."""
    stem = Path(filename).stem

    meta = {
        "skill_type": "unknown",
        "skill_mode": "",
        "split": DEFAULT_SPLIT,
        "dataset_ids": [],
        "run_idx": DEFAULT_RUN,
        "agent_display": DEFAULT_AGENT_DISPLAY,
        "model": DEFAULT_MODEL_SHORT,
    }

    # Extract _run{N} from end
    run_match = re.search(r"_run(\d+)$", stem)
    if run_match:
        meta["run_idx"] = int(run_match.group(1))
        stem = stem[:run_match.start()]

    # Determine skill type
    for st in ("constitutional", "proactive", "reactive"):
        if stem.startswith(st):
            meta["skill_type"] = st
            remainder = stem[len(st):]
            if remainder.startswith("_"):
                remainder = remainder[1:]
            elif remainder == "":
                remainder = ""
            else:
                continue

            if st == "constitutional":
                if remainder:
                    stems = parse_constitutional_mode_stems(remainder)
                    meta["skill_mode"] = "-".join(stems)
                else:
                    meta["skill_mode"] = ALL_STANDARDS_MODE
                # Constitutional skills don't encode dataset in filename
                meta["dataset_ids"] = [str(i) for i in range(1, 28)]
            else:
                _parse_skill_remainder(remainder, meta)
            break

    return meta


def _parse_skill_remainder(remainder: str, meta: dict):
    """Parse mode, split, and datasets from skill filename remainder.

    Patterns:
    - aggregate_exec_1-2-3-...-27
    - separate_exec_10
    - exec_10 (mode=separate implied)
    """
    parts = remainder.split("_")
    idx = 0

    # Check for explicit mode
    if idx < len(parts) and parts[idx] in ("aggregate", "separate"):
        meta["skill_mode"] = parts[idx]
        idx += 1
    else:
        meta["skill_mode"] = "separate"

    # Check for split
    if idx < len(parts) and parts[idx] in ("exec", "gen"):
        meta["split"] = parts[idx]
        idx += 1

    # Rest is dataset info
    if idx < len(parts):
        dataset_part = parts[idx]
        if "-" in dataset_part:
            meta["dataset_ids"] = dataset_part.split("-")
        elif dataset_part.isdigit():
            meta["dataset_ids"] = [dataset_part]
        elif "datasets" in dataset_part:
            n = int(dataset_part.replace("datasets", ""))
            meta["dataset_ids"] = [str(i) for i in range(1, n + 1)]


def generate_new_skill_filename(meta: dict) -> str:
    """Generate new-convention skill filename.

    Constitutional skills omit split/dataset_ids since they are derived from
    safety standards, not dataset cases.
    """
    agent = meta.get("agent_display", DEFAULT_AGENT_DISPLAY)
    model = meta.get("model", DEFAULT_MODEL_SHORT)
    skill_type = meta["skill_type"]
    skill_mode = meta["skill_mode"]
    run_idx = meta.get("run_idx", DEFAULT_RUN)

    skill_mode_part = f"{skill_type}-{skill_mode}" if skill_mode else skill_type

    if skill_type == "constitutional":
        # Constitutional skills don't depend on split/datasets
        return f"{agent}_{model}_{skill_mode_part}_run{run_idx}.md"
    else:
        split = meta.get("split", DEFAULT_SPLIT)
        dataset_ids = meta.get("dataset_ids", [])
        ds_str = dataset_ids_str(dataset_ids)
        return f"{agent}_{model}_{split}_{ds_str}_{skill_mode_part}_run{run_idx}.md"


# ─── Migration logic ────────────────────────────────────────────────────────

def migrate_results(apply: bool = False):
    """Migrate all result JSON files in results/."""
    if not RESULTS_DIR.exists():
        print(f"Results directory not found: {RESULTS_DIR}")
        return

    json_files = sorted(RESULTS_DIR.glob("*.json"))
    if not json_files:
        print("No JSON files found in results/")
        return

    print(f"\n{'=' * 80}")
    print(f"RESULT FILES ({len(json_files)} files)")
    print(f"{'=' * 80}")

    transformations = []  # (old_path, new_name, new_content, meta)
    errors = []

    for json_file in json_files:
        try:
            meta = parse_legacy_result_filename(json_file.name)
            if meta is None:
                errors.append((json_file.name, "Could not parse filename"))
                continue

            with open(json_file) as f:
                old_data = json.load(f)

            new_content = transform_result_content(old_data, meta)

            # Feed back content-derived metadata for filename generation
            meta["dataset_ids"] = new_content.get("Dataset IDs", meta["dataset_ids"])
            meta["skill_type"] = new_content.get("Skill Type", meta["skill_type"])
            meta["skill_mode"] = new_content.get("Skill Mode", meta["skill_mode"])
            meta["is_baseline"] = new_content.get("Is Baseline", meta["is_baseline"])

            new_name = generate_new_result_filename(meta)
            transformations.append((json_file, new_name, new_content, meta))
        except Exception as e:
            errors.append((json_file.name, str(e)))

    # ── Handle filename collisions ──
    # Group by base name (without _run{N}.json) and renumber within each group
    groups = defaultdict(list)
    for item in transformations:
        old_path, new_name, new_content, meta = item
        base = re.sub(r"_run\d+\.json$", "", new_name)
        groups[base].append(item)

    final = []
    for base, items in sorted(groups.items()):
        if len(items) == 1:
            # No collision — keep original run index
            final.append(items[0][:3])  # (old_path, new_name, new_content)
        else:
            # Collision — sort by timestamp, assign run indices 1..N
            items.sort(key=lambda x: x[2].get("Timestamp", ""))
            for i, (old_path, _, new_content, meta) in enumerate(items, 1):
                meta["run_idx"] = i
                new_content["Run Index"] = i
                new_name = generate_new_result_filename(meta)
                final.append((old_path, new_name, new_content))

    # ── Display ──
    renames = 0
    for old_path, new_name, new_content in final:
        changed = old_path.name != new_name
        if changed:
            renames += 1
        status = "RENAME+REFORMAT" if changed else "REFORMAT ONLY"
        print(f"\n  [{status}]")
        print(f"    Old: {old_path.name}")
        print(f"    New: {new_name}")
        sd = new_content.get("Score Distribution", {})
        sd_summary = {k: sum(v.values()) for k, v in sd.items() if v}
        print(f"    Score dist: {sd_summary}")

    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for name, err in errors:
            print(f"    {name}: {err}")

    print(f"\n  Summary: {len(final)} files to transform ({renames} renames), {len(errors)} errors")

    if apply and final:
        BACKUP_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        print(f"\n  Backing up originals to: {BACKUP_RESULTS_DIR}")

        for old_path, new_name, new_content in final:
            shutil.copy2(old_path, BACKUP_RESULTS_DIR / old_path.name)
            new_path = RESULTS_DIR / new_name
            with open(new_path, "w") as f:
                json.dump(new_content, f, indent=2)
            if old_path.name != new_name:
                old_path.unlink()

        print(f"  Applied {len(final)} transformations.")
    elif not apply:
        print("\n  [DRY RUN] No changes made. Use --apply to execute.")


def migrate_skills(apply: bool = False):
    """Migrate all skill markdown files in skills/ (rename only)."""
    if not SKILLS_DIR.exists():
        print(f"Skills directory not found: {SKILLS_DIR}")
        return

    md_files = sorted(SKILLS_DIR.glob("*.md"))
    if not md_files:
        print("No markdown files found in skills/")
        return

    print(f"\n{'=' * 80}")
    print(f"SKILL FILES ({len(md_files)} files)")
    print(f"{'=' * 80}")

    transformations = []
    errors = []

    for md_file in md_files:
        try:
            meta = parse_legacy_skill_filename(md_file.name)
            if meta is None:
                errors.append((md_file.name, "Could not parse filename"))
                continue
            new_name = generate_new_skill_filename(meta)
            transformations.append((md_file, new_name))
        except Exception as e:
            errors.append((md_file.name, str(e)))

    renames = 0
    for old_path, new_name in transformations:
        changed = old_path.name != new_name
        if changed:
            renames += 1
        status = "RENAME" if changed else "NO CHANGE"
        print(f"\n  [{status}]")
        print(f"    Old: {old_path.name}")
        print(f"    New: {new_name}")

    if errors:
        print(f"\n  ERRORS ({len(errors)}):")
        for name, err in errors:
            print(f"    {name}: {err}")

    print(f"\n  Summary: {len(transformations)} files ({renames} renames), {len(errors)} errors")

    if apply and transformations:
        BACKUP_SKILLS_DIR.mkdir(parents=True, exist_ok=True)
        print(f"\n  Backing up originals to: {BACKUP_SKILLS_DIR}")

        for old_path, new_name in transformations:
            shutil.copy2(old_path, BACKUP_SKILLS_DIR / old_path.name)
            new_path = SKILLS_DIR / new_name
            if old_path.name != new_name and not new_path.exists():
                old_path.rename(new_path)

        print(f"  Applied {len(transformations)} renames.")
    elif not apply:
        print("\n  [DRY RUN] No changes made. Use --apply to execute.")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Migrate legacy result JSONs and skill markdowns to new conventions."
    )
    parser.add_argument(
        "--apply", action="store_true",
        help="Apply changes (default is dry run). Creates backups first.",
    )
    parser.add_argument(
        "--results-only", action="store_true",
        help="Only migrate result JSON files",
    )
    parser.add_argument(
        "--skills-only", action="store_true",
        help="Only migrate skill markdown files",
    )
    args = parser.parse_args()

    both = not args.results_only and not args.skills_only

    if both or args.results_only:
        migrate_results(apply=args.apply)

    if both or args.skills_only:
        migrate_skills(apply=args.apply)

    if not args.apply:
        print(f"\n{'=' * 80}")
        print("DRY RUN COMPLETE. Review above and run with --apply to execute.")
        print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
