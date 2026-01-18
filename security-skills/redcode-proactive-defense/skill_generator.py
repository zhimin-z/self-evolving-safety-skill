#!/usr/bin/env python3
"""
Proactive Skill Generator - Iteratively builds security skill by examining each attack.

This implements Method C: Adversarial Synthesis (Bench-to-Skill) with iterative refinement.
For each attack in RedCode, ask "What technical check would stop this?" and refine the skill.

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


# Initial skill template to start refinement
INITIAL_SKILL_TEMPLATE = """---
name: redcode-proactive-defense
description: Adversarial synthesis security skill with technical countermeasures imagined from RedCode benchmark attack scenarios
---

# Security Skill: Proactive-Based Malicious Code Defense

## Overview

This skill implements **adversarial synthesis**: for every attack pattern in the RedCode benchmark, we imagined "What technical check would stop this?" The result is a collection of PROCEDURAL BARRIERS built iteratively by examining real attack scenarios.

**Defense Philosophy:** Pre-execution validation through pattern matching, scope checking, and technical gates.

## Technical Countermeasures

### Pre-Execution Checklist

Before executing ANY user request involving code, files, or system operations, apply these technical checks:

[COUNTERMEASURES WILL BE ADDED ITERATIVELY]

## Refusal Template

When a countermeasure triggers:

```
I cannot execute this request because it failed technical safety check:

Countermeasure: [Name]
Triggered Pattern: [What matched]
Risk: [What attack this prevents]

This is a PROCEDURAL BARRIER to prevent malicious operations.

Safe alternative: [If applicable, suggest safer approach]
```

---

**This proactive skill is built incrementally by analyzing attack scenarios and proactive defenses.**
"""


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


def refine_skill_with_batch(current_skill: str, attack_batch: List[Dict], batch_num: int, total_batches: int) -> str:
    """
    Refine the skill by analyzing a batch of attacks.

    Uses Claude Haiku 4.5 for efficiency (many iterations).
    """
    # Format attacks for the prompt
    attacks_text = "\n\n".join([
        f"**Attack {i+1}** (Split: {attack['split']}, Dataset: {attack['dataset_id']}, Variant: {attack['variant']})\n"
        f"Prompt: {attack['prompt'][:400]}...\n"
        f"Risky Code: {attack.get('risky_code', 'N/A')[:200]}..."
        for i, attack in enumerate(attack_batch[:10])  # Show first 10 in prompt
    ])

    prompt = f"""You are a security engineer ITERATIVELY BUILDING a defense skill for code agents.

**Current Progress:** Batch {batch_num}/{total_batches} ({len(attack_batch)} attacks in this batch)

**Current Skill State:**
{current_skill}

**New Attack Scenarios to Analyze:**
{attacks_text}

**Your Task:**
1. Analyze these new attack scenarios
2. For each attack category, ask: "What SPECIFIC TECHNICAL CHECK would block this?"
3. ADD or UPDATE countermeasures in the skill

**Requirements:**
- Focus on PROCEDURAL checks (pattern matching, scope validation, denylists)
- Make checks TECHNICALLY SPECIFIC (regex patterns, file paths, command structures)
- Avoid duplicating existing countermeasures - only add NEW ones or refine existing
- Keep countermeasures concise and actionable

**Output Format:**
Return the UPDATED skill in full markdown format (YAML frontmatter + markdown body).

Update the [COUNTERMEASURES WILL BE ADDED ITERATIVELY] section with:

### [Category Name]
**Attack Pattern:** [What malicious operation this blocks]

**Technical Check:**
```
- Pattern: [Specific regex, file path, or command pattern]
- Scope: [When to apply]
- Action: [Reject/Confirm/Log]
```

**Implementation:**
1. [Step 1]
2. [Step 2]

**Examples:**
- ✗ BLOCKED: "[Attack example]"
- ✓ ALLOWED: "[Safe example]"

---

**IMPORTANT:** Return the COMPLETE updated skill, not just the changes.
Generate the updated skill now:"""

    try:
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",  # Using Haiku for efficiency
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )

        updated_skill = response.choices[0].message.content

        # Extract markdown if wrapped in code blocks
        if "```markdown" in updated_skill:
            start = updated_skill.find("```markdown") + 11
            end = updated_skill.rfind("```")
            updated_skill = updated_skill[start:end].strip()
        elif updated_skill.startswith("```"):
            lines = updated_skill.split("\n")
            updated_skill = "\n".join(lines[1:-1])

        return updated_skill

    except Exception as e:
        print(f"  ✗ Error refining skill with batch {batch_num}: {e}")
        return current_skill  # Return unchanged if error


def iteratively_build_skill(attacks: List[Dict], batch_size: int = 30) -> str:
    """
    Build the skill iteratively by processing attacks in batches.

    Args:
        attacks: List of all attack scenarios
        batch_size: Number of attacks to process per iteration
    """
    current_skill = INITIAL_SKILL_TEMPLATE
    total_batches = (len(attacks) + batch_size - 1) // batch_size

    print(f"\n  Building skill iteratively:")
    print(f"  - Total attacks: {len(attacks)}")
    print(f"  - Batch size: {batch_size}")
    print(f"  - Total iterations: {total_batches}")

    for batch_num in range(1, total_batches + 1):
        start_idx = (batch_num - 1) * batch_size
        end_idx = min(start_idx + batch_size, len(attacks))
        batch = attacks[start_idx:end_idx]

        print(f"\n  [{batch_num}/{total_batches}] Processing attacks {start_idx+1}-{end_idx}...")

        current_skill = refine_skill_with_batch(current_skill, batch, batch_num, total_batches)

        # Show progress
        skill_lines = len(current_skill.split('\n'))
        print(f"  ✓ Skill updated ({skill_lines} lines)")

    print(f"\n  ✓ Iterative refinement complete!")
    return current_skill


def save_proactive_skill(
    skill_content: str,
    total_attacks: int,
    split: str,
    dataset_ids: Optional[List[str]],
    output_dir: str
):
    """Save the proactive skill to Agent Skills directory."""
    skill_dir = Path(output_dir) / "redcode-proactive-defense"
    skill_dir.mkdir(parents=True, exist_ok=True)

    # Save SKILL.md
    skill_file = skill_dir / "SKILL.md"
    with open(skill_file, "w") as f:
        f.write(skill_content)

    # Save metadata
    metadata_file = skill_dir / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "skill_type": "proactive",
            "generated_from": {
                "approach": "adversarial-synthesis-iterative",
                "benchmark": "RedCode",
                "split": split,
                "dataset_ids": dataset_ids,
                "total_attack_scenarios": total_attacks,
                "generation_method": "iterative_refinement"
            },
            "model": "anthropic/claude-haiku-4-5-20251001"
        }, f, indent=2)

    print(f"\n✓ Saved proactive skill to: {skill_dir}")
    print(f"  - Skill file: {skill_file}")
    print(f"  - Metadata: {metadata_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate proactive security skill from RedCode benchmark (iterative refinement)"
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
        "--batch_size",
        type=int,
        default=30,
        help="Number of attacks to process per iteration (default: 30)"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="security-skills",
        help="Output directory for the proactive skill"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Proactive Skill Generator (Iterative Refinement)")
    print("=" * 60)

    # Step 1: Load RedCode attack scenarios
    print("\n[1/2] Loading RedCode benchmark attack scenarios...")
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

    # Step 2: Iteratively build skill
    print("\n[2/2] Iteratively building proactive skill...")
    print(f"  Using: Claude Haiku 4.5 (efficient for many iterations)")

    skill_content = iteratively_build_skill(attacks, batch_size=args.batch_size)

    if skill_content:
        save_proactive_skill(
            skill_content,
            len(attacks),
            args.split,
            args.dataset_ids,
            args.output_dir
        )

        print("\n" + "=" * 60)
        print("✓ Proactive skill generation complete!")
        print("=" * 60)
        print(f"\nNext steps:")
        print(f"1. Review: {args.output_dir}/redcode-proactive-defense/SKILL.md")
        print(f"2. Test: python evaluation/run_redcode_with_skills.py --skill_type proactive --split exec --dataset_ids 4")
        print("=" * 60)
    else:
        print("\n✗ Failed to generate proactive skill")


if __name__ == "__main__":
    main()
