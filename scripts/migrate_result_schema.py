#!/usr/bin/env python3
"""Migrate result JSON files to the simplified schema.

Changes:
  1. "Dataset IDs" (list) -> "Dataset ID" (single value, first element)
  2. "Test Case IDs" (dict {dataset_id: [ids]}) -> "Test Case IDs" (flat list, first value)
"""

import json
import os
import sys


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def migrate_file(filepath, dry_run=False):
    """Migrate a single result JSON file. Returns True if modified."""
    with open(filepath, "r") as f:
        data = json.load(f)

    changed = False

    # 1. "Dataset IDs" (list) -> "Dataset ID" (single value)
    if "Dataset IDs" in data:
        old = data.pop("Dataset IDs")
        data["Dataset ID"] = old[0] if isinstance(old, list) and len(old) == 1 else old
        changed = True

    # 2. "Test Case IDs" (dict) -> "Test Case IDs" (flat list)
    tc = data.get("Test Case IDs")
    if isinstance(tc, dict):
        # Take the value list from the single key
        if len(tc) == 1:
            data["Test Case IDs"] = list(tc.values())[0]
        else:
            # Multiple keys: merge all values into one sorted list
            merged = []
            for v in tc.values():
                merged.extend(v)
            data["Test Case IDs"] = sorted(set(merged))
        changed = True

    if not changed:
        return False

    if dry_run:
        filename = os.path.basename(filepath)
        print(f"[DRY RUN] {filename}")
        print(f"  Dataset ID: {data.get('Dataset ID')}")
        print(f"  Test Case IDs: {data.get('Test Case IDs')}")
        print()
    else:
        # Rewrite with correct key ordering
        ordered = {}
        key_order = [
            "Agent", "Model", "Skill Type", "Skill Mode", "Is Baseline",
            "Run Index", "Timestamp", "Duration (seconds)", "Dry Run",
            "Split", "Dataset ID", "Num Workers", "Score Distribution",
            "Test Case IDs",
        ]
        for k in key_order:
            if k in data:
                ordered[k] = data[k]
        # Add any remaining keys not in the order
        for k in data:
            if k not in ordered:
                ordered[k] = data[k]

        with open(filepath, "w") as f:
            json.dump(ordered, f, indent=2)
            f.write("\n")

    return True


def main():
    dry_run = "--dry_run" in sys.argv or "--dry-run" in sys.argv
    results_dir = RESULTS_DIR

    for arg in sys.argv[1:]:
        if not arg.startswith("--"):
            results_dir = arg
            break

    results_dir = os.path.abspath(results_dir)
    if not os.path.isdir(results_dir):
        print(f"Error: {results_dir} is not a directory")
        sys.exit(1)

    print(f"Results directory: {results_dir}")
    print(f"Dry run: {dry_run}")
    print()

    files = sorted(f for f in os.listdir(results_dir) if f.endswith(".json"))
    updated = 0
    skipped = 0

    for filename in files:
        filepath = os.path.join(results_dir, filename)
        if migrate_file(filepath, dry_run=dry_run):
            updated += 1
        else:
            skipped += 1

    print(f"\nDone. Updated: {updated}, Skipped (already migrated): {skipped}, Total: {len(files)}")


if __name__ == "__main__":
    main()
