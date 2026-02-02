#!/usr/bin/env python3
"""Fix skill filenames in the security-skills folder.

Renames files whose run index doesn't match expectations.
For reactive_separate files generated with n_runs=1, the filename should
always end with run1 (e.g. reactive_separate_exec_9_run1.md), but a bug
caused them to use a global counter instead (reactive_separate_exec_9_run9.md).

Usage:
    # Dry run (preview changes only)
    python evaluation/fix_skill_filenames.py

    # Apply changes
    python evaluation/fix_skill_filenames.py --apply
"""

import argparse
import os
import re
import sys

SKILLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "security-skills")


def main():
    parser = argparse.ArgumentParser(description="Fix skill filenames: normalize run index to run1")
    parser.add_argument("--apply", action="store_true", help="Apply renames (default is dry run)")
    args = parser.parse_args()

    skills_dir = os.path.abspath(SKILLS_DIR)
    if not os.path.isdir(skills_dir):
        print(f"Error: directory not found: {skills_dir}")
        sys.exit(1)

    # Match reactive files with run{N} where N != 1
    # e.g. reactive_separate_exec_9_run9.md -> reactive_separate_exec_9_run1.md
    pattern = re.compile(r"^(proactive_.+_run)(\d+)(\.md)$")
    renames = []

    for filename in sorted(os.listdir(skills_dir)):
        m = pattern.match(filename)
        if m and m.group(2) != "1":
            new_name = f"{m.group(1)}1{m.group(3)}"
            renames.append((filename, new_name))

    if not renames:
        print("No files to rename.")
        return

    mode = "APPLYING" if args.apply else "DRY RUN"
    print(f"[{mode}] {len(renames)} file(s) to rename in {skills_dir}:\n")

    for old, new in renames:
        print(f"  {old}  ->  {new}")
        if args.apply:
            src = os.path.join(skills_dir, old)
            dst = os.path.join(skills_dir, new)
            if os.path.exists(dst):
                print(f"    WARNING: target already exists, skipping")
                continue
            os.rename(src, dst)

    if args.apply:
        print(f"\nDone. Renamed {len(renames)} file(s).")
    else:
        print(f"\nDry run complete. Use --apply to rename.")


if __name__ == "__main__":
    main()
