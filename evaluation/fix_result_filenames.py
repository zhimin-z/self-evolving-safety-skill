#!/usr/bin/env python3
"""Fix result filenames in the results folder.

Renames any JSON file containing run{N} (where N != 1) to run1.
This corrects filenames produced by the global_run_idx bug in run_separate_experiment.

Usage:
    # Dry run (preview changes only)
    python evaluation/fix_result_filenames.py

    # Apply changes
    python evaluation/fix_result_filenames.py --apply
"""

import argparse
import os
import re
import sys

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "results")


def main():
    parser = argparse.ArgumentParser(description="Fix result filenames: normalize run{N} to run1")
    parser.add_argument("--apply", action="store_true", help="Apply renames (default is dry run)")
    args = parser.parse_args()

    results_dir = os.path.abspath(RESULTS_DIR)
    if not os.path.isdir(results_dir):
        print(f"Error: directory not found: {results_dir}")
        sys.exit(1)

    # Match run{N} where N != 1 in .json filenames
    pattern = re.compile(r"^(.+_run)\d+(_.+\.json)$")
    renames = []

    for filename in sorted(os.listdir(results_dir)):
        if not filename.endswith(".json"):
            continue
        m = pattern.match(filename)
        if m:
            new_name = f"{m.group(1)}1{m.group(2)}"
            if new_name != filename:
                renames.append((filename, new_name))

    if not renames:
        print("No files to rename.")
        return

    mode = "APPLYING" if args.apply else "DRY RUN"
    print(f"[{mode}] {len(renames)} file(s) to rename in {results_dir}:\n")

    skipped = 0
    renamed = 0
    for old, new in renames:
        print(f"  {old}  ->  {new}")
        if args.apply:
            src = os.path.join(results_dir, old)
            dst = os.path.join(results_dir, new)
            if os.path.exists(dst):
                print(f"    WARNING: target already exists, skipping")
                skipped += 1
                continue
            os.rename(src, dst)
            renamed += 1

    if args.apply:
        print(f"\nDone. Renamed {renamed} file(s)." + (f" Skipped {skipped}." if skipped else ""))
    else:
        print(f"\nDry run complete. Use --apply to rename.")


if __name__ == "__main__":
    main()
