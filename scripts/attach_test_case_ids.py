#!/usr/bin/env python3
"""Attach 'Test Case IDs' to each result JSON in the results/ folder.

Rules:
  - Non-constitutional (reactive, proactive, fusion):
      Up to 15 random IDs per dataset, sampled from 1-30.
      The count is derived from the Score Distribution.
  - Constitutional:
      All dataset test cases, i.e. list(range(1, 31)).

Deterministic seeding ensures:
  - Reproducibility across runs of this script.
  - Skill and baseline results for the same experiment get identical IDs
    (seed excludes is_baseline).
  - Different runs / datasets / skill_modes get different IDs.
"""

import hashlib
import json
import os
import random
import sys


RESULTS_DIR = os.path.join(os.path.dirname(__file__), "..", "results")


def compute_seed(dataset_id, run_idx, skill_mode):
    """Deterministic seed from (dataset_id, run_idx, skill_mode).

    Excludes is_baseline so that skill and baseline pairs share the same IDs.
    """
    key = f"{dataset_id}_{run_idx}_{skill_mode}"
    return int(hashlib.md5(key.encode()).hexdigest(), 16) % (2**31)


def get_cases_per_dataset(data):
    """Derive the number of test cases per dataset from Score Distribution.

    Each input type (Code, Code w/ jb, Summary, Details) has one score entry
    per test case.  The total across all score buckets for any single input
    type gives the total number of test cases.  Dividing by the number of
    datasets gives the per-dataset count.
    """
    score_dist = data.get("Score Distribution", {})
    if not score_dist:
        return 0

    # Use the first input type
    first_scores = next(iter(score_dist.values()))
    total = sum(int(v) for v in first_scores.values())

    n_datasets = len(data.get("Dataset IDs", [])) or 1
    return total // n_datasets


def generate_test_case_ids(data):
    """Generate the 'Test Case IDs' dict for a result JSON.

    Returns:
        dict mapping str(dataset_id) -> sorted list of int IDs.
    """
    skill_type = data.get("Skill Type", "")
    is_constitutional = skill_type == "constitutional"
    dataset_ids = data.get("Dataset IDs", [])
    run_idx = data.get("Run Index", 1)
    skill_mode = data.get("Skill Mode", "")

    cases_per_dataset = get_cases_per_dataset(data)

    test_case_ids = {}
    for did in dataset_ids:
        did_str = str(did)

        if is_constitutional:
            # Constitutional uses ALL cases (no train/test split)
            test_case_ids[did_str] = list(range(1, 31))
        else:
            # Non-constitutional: sample up to 15 IDs from 1-30
            n = min(cases_per_dataset, 15)
            if n <= 0:
                n = 15  # fallback
            seed = compute_seed(did_str, run_idx, skill_mode)
            rng = random.Random(seed)
            ids = sorted(rng.sample(range(1, 31), n))
            test_case_ids[did_str] = ids

    return test_case_ids


def process_results(results_dir, dry_run=False):
    """Walk every .json in results_dir and attach Test Case IDs."""
    files = sorted(f for f in os.listdir(results_dir) if f.endswith(".json"))
    updated = 0
    skipped = 0

    for filename in files:
        filepath = os.path.join(results_dir, filename)
        with open(filepath, "r") as f:
            data = json.load(f)

        if "Test Case IDs" in data:
            skipped += 1
            continue

        test_case_ids = generate_test_case_ids(data)
        data["Test Case IDs"] = test_case_ids

        if dry_run:
            print(f"[DRY RUN] {filename}")
            print(f"  Skill Type: {data.get('Skill Type')}, Datasets: {data.get('Dataset IDs')}")
            print(f"  Test Case IDs: {test_case_ids}")
            print()
        else:
            with open(filepath, "w") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            updated += 1

    print(f"\nDone. Updated: {updated}, Skipped (already had IDs): {skipped}, Total: {len(files)}")


def main():
    dry_run = "--dry_run" in sys.argv or "--dry-run" in sys.argv
    results_dir = RESULTS_DIR

    # Allow custom path via positional arg
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

    process_results(results_dir, dry_run=dry_run)


if __name__ == "__main__":
    main()
