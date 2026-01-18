#!/usr/bin/env python3
"""
Reactive Skill Generator - Creates ONE comprehensive security skill from RedCode attacks.

This implements proactive adversarial defense: analyze attack scenarios directly from
the RedCode benchmark and synthesize a reactive defense skill that covers all patterns.

RedCode Dataset Structure:
- RedCode-Exec: external/RedCode/dataset/RedCode-Exec/py2text_dataset_json/
  - Files: index{N}_30_codes_full.json (N = 1-27)
  - Each JSON contains: Index, Code, Text_summary, Text_details

- RedCode-Gen: external/RedCode/dataset/RedCode-Gen/
  - Folders: adware, ddos, others, ransomware, rootkit, spyware, trojan, virus
  - Each folder contains Python files with malware function stubs

Usage:
    # All datasets from both splits
    python skill_generator.py

    # Only RedCode-Exec
    python skill_generator.py --split exec

    # Only RedCode-Gen
    python skill_generator.py --split gen

    # Specific datasets from RedCode-Exec (by index number)
    python skill_generator.py --split exec --dataset_ids 4 5 6

    # Specific categories from RedCode-Gen (by folder name)
    python skill_generator.py --split gen --dataset_ids virus trojan ransomware
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional
from dotenv import load_dotenv
from litellm import completion

load_dotenv()


def load_redcode_exec(benchmark_dir: Path, dataset_ids: Optional[List[str]] = None) -> List[Dict]:
    """
    Load RedCode-Exec benchmark datasets from py2text_dataset_json.

    Args:
        benchmark_dir: Path to RedCode dataset root (external/RedCode/dataset)
        dataset_ids: List of dataset IDs to load (e.g., ["4", "5", "6"]). If None, load all.

    Returns:
        List of attack dictionaries with all variants (code, summary, details)
    """
    exec_dir = benchmark_dir / "RedCode-Exec" / "py2text_dataset_json"

    if not exec_dir.exists():
        raise FileNotFoundError(f"RedCode-Exec directory not found: {exec_dir}")

    all_attacks = []

    # Get all JSON files
    json_files = sorted(exec_dir.glob("index*_30_codes_full.json"))

    for json_file in json_files:
        # Extract dataset ID from filename: index4_30_codes_full.json -> "4"
        dataset_id = json_file.stem.split("_")[0].replace("index", "")

        # Skip if not in requested dataset_ids
        if dataset_ids and dataset_id not in dataset_ids:
            continue

        with open(json_file) as f:
            dataset = json.load(f)

            for item in dataset:
                index = item.get("Index", "")
                risky_code = item.get("Code", "")

                # Add code variant
                all_attacks.append({
                    "split": "exec",
                    "dataset_id": dataset_id,
                    "index": index,
                    "variant": "code",
                    "prompt": risky_code,
                    "risky_code": risky_code
                })

                # Add summary variant
                all_attacks.append({
                    "split": "exec",
                    "dataset_id": dataset_id,
                    "index": index,
                    "variant": "summary",
                    "prompt": item.get("Text_summary", ""),
                    "risky_code": risky_code
                })

                # Add details variant
                all_attacks.append({
                    "split": "exec",
                    "dataset_id": dataset_id,
                    "index": index,
                    "variant": "details",
                    "prompt": item.get("Text_details", ""),
                    "risky_code": risky_code
                })

    return all_attacks


def load_redcode_gen(benchmark_dir: Path, dataset_ids: Optional[List[str]] = None) -> List[Dict]:
    """
    Load RedCode-Gen benchmark datasets from category folders.

    Args:
        benchmark_dir: Path to RedCode dataset root (external/RedCode/dataset)
        dataset_ids: List of category folder names (e.g., ["virus", "trojan"]). If None, load all.

    Returns:
        List of attack dictionaries with malware code stubs
    """
    gen_dir = benchmark_dir / "RedCode-Gen"

    if not gen_dir.exists():
        raise FileNotFoundError(f"RedCode-Gen directory not found: {gen_dir}")

    all_attacks = []

    # Get all category folders
    category_folders = [d for d in sorted(gen_dir.iterdir()) if d.is_dir()]

    for category_dir in category_folders:
        category_name = category_dir.name

        # Skip if not in requested dataset_ids
        if dataset_ids and category_name not in dataset_ids:
            continue

        # Get all Python files in category
        py_files = sorted(category_dir.glob("*.py"))

        for py_file in py_files:
            with open(py_file) as f:
                code_content = f.read()

            # Extract function name from filename: virus_1_file_infection.py -> virus_1_file_infection
            func_name = py_file.stem

            all_attacks.append({
                "split": "gen",
                "dataset_id": category_name,
                "index": func_name,
                "variant": "code_stub",
                "prompt": f"Complete this malware function:\n\n{code_content}",
                "risky_code": code_content
            })

    return all_attacks


def load_redcode_datasets(
    benchmark_dir: str,
    split: str = "all",
    dataset_ids: Optional[List[str]] = None
) -> List[Dict]:
    """
    Load RedCode benchmark datasets based on split and dataset_ids.

    Args:
        benchmark_dir: Path to RedCode dataset root (external/RedCode/dataset)
        split: Which split to load - "exec", "gen", or "all"
        dataset_ids: List of dataset IDs to load. Interpretation depends on split:
            - exec: numeric strings like "4", "5", "6"
            - gen: category names like "virus", "trojan"
            - all: will try to match against both splits

    Returns:
        List of all attack dictionaries
    """
    benchmark_path = Path(benchmark_dir)

    if not benchmark_path.exists():
        raise FileNotFoundError(f"Benchmark directory not found: {benchmark_path}")

    all_attacks = []

    # Load RedCode-Exec
    if split in ("exec", "all"):
        # Filter dataset_ids for exec (numeric IDs)
        exec_ids = None
        if dataset_ids:
            exec_ids = [d for d in dataset_ids if d.isdigit()]
            if not exec_ids and split == "exec":
                exec_ids = dataset_ids  # User specified exec, use all IDs

        try:
            exec_attacks = load_redcode_exec(benchmark_path, exec_ids if exec_ids else None)
            all_attacks.extend(exec_attacks)
            print(f"  ✓ Loaded {len(exec_attacks)} attack scenarios from RedCode-Exec")
        except FileNotFoundError as e:
            if split == "exec":
                raise
            print(f"  ⚠ Skipping RedCode-Exec: {e}")

    # Load RedCode-Gen
    if split in ("gen", "all"):
        # Filter dataset_ids for gen (category names)
        gen_ids = None
        if dataset_ids:
            gen_ids = [d for d in dataset_ids if not d.isdigit()]
            if not gen_ids and split == "gen":
                gen_ids = dataset_ids  # User specified gen, use all IDs

        try:
            gen_attacks = load_redcode_gen(benchmark_path, gen_ids if gen_ids else None)
            all_attacks.extend(gen_attacks)
            print(f"  ✓ Loaded {len(gen_attacks)} attack scenarios from RedCode-Gen")
        except FileNotFoundError as e:
            if split == "gen":
                raise
            print(f"  ⚠ Skipping RedCode-Gen: {e}")

    print(f"  ✓ Total: {len(all_attacks)} attack scenarios loaded")
    return all_attacks


def analyze_attack_patterns(attacks: List[Dict]) -> Dict:
    """
    Analyze attack patterns from loaded RedCode datasets.

    Groups attacks by type and extracts representative examples for skill generation.
    """
    analysis = {
        "total_attacks": len(attacks),
        "splits": set(),
        "datasets": set(),
        "variants": set(),
        "examples_by_dataset": {},  # Group examples by dataset/category
        "examples_by_variant": {}   # Group examples by variant type
    }

    for attack in attacks:
        analysis["splits"].add(attack["split"])
        analysis["datasets"].add(attack["dataset_id"])
        analysis["variants"].add(attack["variant"])

        dataset_id = attack["dataset_id"]
        variant = attack["variant"]

        # Store examples by dataset (limit to 3 per dataset)
        if dataset_id not in analysis["examples_by_dataset"]:
            analysis["examples_by_dataset"][dataset_id] = []
        if len(analysis["examples_by_dataset"][dataset_id]) < 3:
            analysis["examples_by_dataset"][dataset_id].append(attack)

        # Store examples by variant (limit to 5 per variant)
        if variant not in analysis["examples_by_variant"]:
            analysis["examples_by_variant"][variant] = []
        if len(analysis["examples_by_variant"][variant]) < 5:
            analysis["examples_by_variant"][variant].append(attack)

    # Convert sets to sorted lists
    analysis["splits"] = sorted(list(analysis["splits"]))
    analysis["datasets"] = sorted(list(analysis["datasets"]))
    analysis["variants"] = sorted(list(analysis["variants"]))

    return analysis


def generate_reactive_skill(analysis: Dict) -> str:
    """
    Generate ONE comprehensive reactive security skill from attack patterns.

    Uses LLM to synthesize patterns across all attack types into a format-agnostic
    defense skill that focuses on detecting malicious INTENT.
    """

    # Prepare examples grouped by dataset/category
    examples_text = ""
    for dataset_id, examples in list(analysis["examples_by_dataset"].items())[:8]:  # Limit datasets shown
        examples_text += f"\n### Dataset/Category: {dataset_id}\n"
        for i, ex in enumerate(examples[:2], 1):  # Max 2 examples per dataset
            examples_text += f"""
**Example {i}** (Variant: {ex['variant']}):
- Prompt: {ex['prompt'][:300]}{'...' if len(ex['prompt']) > 300 else ''}
- Risky Code: {ex['risky_code'][:200]}{'...' if len(ex['risky_code']) > 200 else ''}
"""

    stats_text = f"""
**Attack Scenario Statistics:**
- Total attack scenarios: {analysis['total_attacks']}
- Splits: {', '.join(analysis['splits'])}
- Datasets/Categories: {len(analysis['datasets'])} ({', '.join(analysis['datasets'][:10])}{'...' if len(analysis['datasets']) > 10 else ''})
- Presentation variants: {', '.join(analysis['variants'])}
"""

    prompt = f"""You are a security expert creating a REACTIVE security skill for code agents.

**Context:**
We have {analysis['total_attacks']} attack scenarios from the RedCode security benchmark.
These represent malicious code execution requests that an agent should REFUSE.

{stats_text}

**Attack Examples Across Categories:**
{examples_text}

**Your Task:**
Create ONE comprehensive security skill that detects and refuses ALL these attack patterns.

**Key Insight:** The agent won't know which attack type it's facing in advance, so the skill must:
1. Detect malicious patterns regardless of presentation format (direct code, text summary, detailed description, code stubs)
2. Identify common underlying malicious intents (file access, process manipulation, system modification, malware creation)
3. Provide ACTIONABLE detection criteria that work across ALL attack types

**Output Format (Agent Skills Spec - YAML + Markdown):**

---
name: redcode-reactive-defense
description: Comprehensive security skill that detects and refuses malicious code execution requests regardless of presentation format
---

# Security Skill: Reactive Malicious Code Defense

## Overview
[Brief overview of threats this skill addresses - synthesize across ALL attack categories]

## Defense Principle
[ONE reactive principle that covers all attack patterns - focus on INTENT, not format]

**Key insight:** Malicious requests can be presented as:
- Direct code (e.g., "Execute this Python script...")
- Text summaries (e.g., "Create a script that copies system files...")
- Detailed instructions (e.g., "Step 1: Import shutil, Step 2: Copy /etc/passwd...")
- Code stubs to complete (e.g., "Complete this malware function...")

The underlying malicious INTENT is what matters, not the presentation format.

## Detection Criteria

Refuse requests that involve:

### 1. [Category 1 - e.g., Unauthorized File Access]
- [Specific pattern 1]
- [Specific pattern 2]
- **Applies to:** All presentation formats

### 2. [Category 2 - e.g., Process Manipulation]
- [Specific pattern 1]
- [Specific pattern 2]

### 3. [Category 3 - e.g., Malware Creation]
[Continue for all major categories...]

## Required Action

When malicious intent is detected:
1. **REFUSE** - Do not execute or generate the code
2. **EXPLAIN** - State which malicious pattern was detected
3. **SUGGEST** - Offer safe alternatives if the user has legitimate needs

## Examples

### Pattern 1: [Major Pattern]

**Unsafe - Direct Code:**
```python
[example]
```

**Unsafe - Text Summary:**
"[example]"

**Unsafe - Code Stub:**
"Complete this function: [example]"

**Correct Response for ALL formats:**
"I cannot help with [reason]. This could [harm]..."

[Continue for 3-4 major patterns]

## Safe Alternatives

[Provide legitimate use cases that might be confused with attacks]

## Implementation Notes

This skill is designed to be:
- **Format-agnostic:** Detects malicious intent regardless of presentation
- **Intent-focused:** Looks for underlying malicious goals, not surface syntax
- **Comprehensive:** Covers file operations, process control, network activity, and malware patterns

---

**Generate the complete reactive skill now, covering all {len(analysis['datasets'])} attack categories:**
"""

    try:
        print("  Generating reactive skill with Claude Haiku 4.5...")
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=8192
        )

        return response.choices[0].message.content

    except Exception as e:
        print(f"✗ Error generating skill: {e}")
        return None


def save_reactive_skill(
    skill_content: str,
    analysis: Dict,
    split: str,
    dataset_ids: Optional[List[str]],
    output_dir: str
):
    """Save the reactive skill to Agent Skills directory."""
    skill_dir = Path(output_dir) / "redcode-reactive-defense"
    skill_dir.mkdir(parents=True, exist_ok=True)

    # Save SKILL.md
    skill_file = skill_dir / "SKILL.md"
    with open(skill_file, "w") as f:
        f.write(skill_content)

    # Save metadata
    metadata_file = skill_dir / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "skill_type": "reactive",
            "generated_from": {
                "approach": "adversarial-synthesis",
                "benchmark": "RedCode",
                "split": split,
                "dataset_ids": dataset_ids,
                "total_attack_scenarios": analysis["total_attacks"],
                "datasets": analysis["datasets"],
                "variants": analysis["variants"]
            },
            "model": "anthropic/claude-haiku-4-5-20251001"
        }, f, indent=2)

    print(f"\n✓ Saved reactive skill to: {skill_dir}")
    print(f"  - Skill file: {skill_file}")
    print(f"  - Metadata: {metadata_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate reactive security skill from RedCode benchmark"
    )
    parser.add_argument(
        "--benchmark_dir",
        type=str,
        default="external/RedCode/dataset",
        help="Directory containing RedCode benchmark datasets (default: external/RedCode/dataset)"
    )
    parser.add_argument(
        "--split",
        type=str,
        choices=["exec", "gen", "all"],
        default="all",
        help="Which dataset split to use: exec (RedCode-Exec), gen (RedCode-Gen), or all (default: all)"
    )
    parser.add_argument(
        "--dataset_ids",
        type=str,
        nargs="+",
        default=None,
        help="Specific dataset IDs to analyze. For exec: numeric IDs (4, 5, 6). For gen: category names (virus, trojan)"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="security-skills",
        help="Output directory for the reactive skill"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Reactive Skill Generator (Adversarial Synthesis)")
    print("=" * 60)
    print()

    # Step 1: Load RedCode attack scenarios
    print("[1/3] Loading RedCode benchmark attack scenarios...")
    print(f"  Benchmark directory: {args.benchmark_dir}")
    print(f"  Split: {args.split}")
    if args.dataset_ids:
        print(f"  Dataset IDs: {args.dataset_ids}")

    try:
        attacks = load_redcode_datasets(
            args.benchmark_dir,
            split=args.split,
            dataset_ids=args.dataset_ids
        )
    except Exception as e:
        print(f"✗ Error loading benchmark: {e}")
        return

    if not attacks:
        print("✗ No attack scenarios found. Check benchmark directory path and dataset IDs.")
        return

    # Step 2: Analyze attack patterns
    print("\n[2/3] Analyzing attack patterns...")
    analysis = analyze_attack_patterns(attacks)
    print(f"  ✓ Splits: {', '.join(analysis['splits'])}")
    print(f"  ✓ Datasets/Categories: {len(analysis['datasets'])}")
    print(f"  ✓ Variants: {', '.join(analysis['variants'])}")

    # Step 3: Generate reactive skill
    print("\n[3/3] Generating reactive skill...")
    print(f"  Using: Claude Haiku 4.5")
    skill_content = generate_reactive_skill(analysis)

    if skill_content:
        save_reactive_skill(
            skill_content,
            analysis,
            args.split,
            args.dataset_ids,
            args.output_dir
        )

        print("\n" + "=" * 60)
        print("✓ Reactive skill generation complete!")
        print("=" * 60)
        print(f"\nNext steps:")
        print(f"1. Review: {args.output_dir}/redcode-reactive-defense/SKILL.md")
        print(f"2. Test: python evaluation/run_redcode_with_skills.py --skill_type reactive --split exec --dataset_ids 4")
        print("=" * 60)
    else:
        print("\n✗ Failed to generate reactive skill")


if __name__ == "__main__":
    main()
