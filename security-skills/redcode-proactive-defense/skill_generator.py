#!/usr/bin/env python3
"""
Proactive Skill Generator - Iteratively refines ONE security skill from RedCode attacks.

This implements adversarial synthesis: for each attack in RedCode, ask "What technical
check would stop this?" and iteratively refine the skill.

RedCode Dataset Structure:
- RedCode-Exec: external/RedCode/dataset/RedCode-Exec/py2text_dataset_json/
  - Files: index{N}_30_codes_full.json (N = 1-27)
  - Uses: Text_details field only (detailed attack description)

- RedCode-Gen: external/RedCode/dataset/RedCode-Gen/
  - Folders: adware, ddos, others, ransomware, rootkit, spyware, trojan, virus
  - Uses: Whole file content (malware function stubs)

Usage:
    # All datasets from both splits
    python skill_generator.py

    # Only RedCode-Exec
    python skill_generator.py --split exec

    # Only RedCode-Gen
    python skill_generator.py --split gen

    # Specific datasets
    python skill_generator.py --split exec --dataset_ids 4 5 6
    python skill_generator.py --split gen --dataset_ids virus trojan
"""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Iterable
from dotenv import load_dotenv
from litellm import completion

load_dotenv()

MAX_SKILL_CHARS = 14000
CHUNK_SIZE_CHARS = 6000  # Max chars per batch of cases


def load_redcode_exec(benchmark_dir: Path, dataset_ids: Optional[List[str]] = None) -> List[Dict]:
    """
    Load RedCode-Exec: Only Text_details field from each case.
    """
    exec_dir = benchmark_dir / "RedCode-Exec" / "py2text_dataset_json"

    if not exec_dir.exists():
        raise FileNotFoundError(f"RedCode-Exec directory not found: {exec_dir}")

    all_cases = []
    json_files = sorted(exec_dir.glob("index*_30_codes_full.json"))

    for json_file in json_files:
        dataset_id = json_file.stem.split("_")[0].replace("index", "")

        if dataset_ids and dataset_id not in dataset_ids:
            continue

        with open(json_file) as f:
            dataset = json.load(f)

            for item in dataset:
                text_details = item.get("Text_details", "")
                if text_details.strip():
                    all_cases.append({
                        "split": "exec",
                        "dataset_id": dataset_id,
                        "index": item.get("Index", ""),
                        "content": text_details
                    })

    return all_cases


def load_redcode_gen(benchmark_dir: Path, dataset_ids: Optional[List[str]] = None) -> List[Dict]:
    """
    Load RedCode-Gen: Whole file content from each Python file.
    """
    gen_dir = benchmark_dir / "RedCode-Gen"

    if not gen_dir.exists():
        raise FileNotFoundError(f"RedCode-Gen directory not found: {gen_dir}")

    all_cases = []
    category_folders = [d for d in sorted(gen_dir.iterdir()) if d.is_dir()]

    for category_dir in category_folders:
        category_name = category_dir.name

        if dataset_ids and category_name not in dataset_ids:
            continue

        py_files = sorted(category_dir.glob("*.py"))

        for py_file in py_files:
            with open(py_file) as f:
                content = f.read()

            if content.strip():
                all_cases.append({
                    "split": "gen",
                    "dataset_id": category_name,
                    "index": py_file.stem,
                    "content": content
                })

    return all_cases


def load_redcode_datasets(
    benchmark_dir: str,
    split: str = "all",
    dataset_ids: Optional[List[str]] = None
) -> List[Dict]:
    """
    Load RedCode benchmark datasets based on split and dataset_ids.
    """
    benchmark_path = Path(benchmark_dir)

    if not benchmark_path.exists():
        raise FileNotFoundError(f"Benchmark directory not found: {benchmark_path}")

    all_cases = []

    # Load RedCode-Exec
    if split in ("exec", "all"):
        exec_ids = None
        if dataset_ids:
            exec_ids = [d for d in dataset_ids if d.isdigit()]
            if not exec_ids and split == "exec":
                exec_ids = dataset_ids

        try:
            exec_cases = load_redcode_exec(benchmark_path, exec_ids if exec_ids else None)
            all_cases.extend(exec_cases)
            print(f"  ✓ Loaded {len(exec_cases)} cases from RedCode-Exec")
        except FileNotFoundError as e:
            if split == "exec":
                raise
            print(f"  ⚠ Skipping RedCode-Exec: {e}")

    # Load RedCode-Gen
    if split in ("gen", "all"):
        gen_ids = None
        if dataset_ids:
            gen_ids = [d for d in dataset_ids if not d.isdigit()]
            if not gen_ids and split == "gen":
                gen_ids = dataset_ids

        try:
            gen_cases = load_redcode_gen(benchmark_path, gen_ids if gen_ids else None)
            all_cases.extend(gen_cases)
            print(f"  ✓ Loaded {len(gen_cases)} cases from RedCode-Gen")
        except FileNotFoundError as e:
            if split == "gen":
                raise
            print(f"  ⚠ Skipping RedCode-Gen: {e}")

    print(f"  ✓ Total: {len(all_cases)} cases loaded")
    return all_cases


def iter_case_chunks(cases: List[Dict], chunk_size: int) -> Iterable[Tuple[int, int, List[Dict]]]:
    """
    Yield chunks of cases where total content size doesn't exceed chunk_size.

    Returns: (chunk_index, total_chunks, cases_in_chunk)
    """
    if not cases:
        return

    # First pass: determine chunks
    chunks = []
    current_chunk = []
    current_size = 0

    for case in cases:
        case_content = f"**Case** (Split: {case['split']}, Dataset: {case['dataset_id']}, Index: {case['index']}):\n{case['content']}\n\n---\n\n"
        case_size = len(case_content)

        # If single case exceeds chunk_size, it gets its own chunk
        if case_size >= chunk_size:
            if current_chunk:
                chunks.append(current_chunk)
                current_chunk = []
                current_size = 0
            chunks.append([case])
        # If adding this case would exceed chunk_size, start new chunk
        elif current_size + case_size > chunk_size:
            chunks.append(current_chunk)
            current_chunk = [case]
            current_size = case_size
        # Otherwise add to current chunk
        else:
            current_chunk.append(case)
            current_size += case_size

    # Don't forget the last chunk
    if current_chunk:
        chunks.append(current_chunk)

    # Yield chunks with index info
    total_chunks = len(chunks)
    for i, chunk in enumerate(chunks, 1):
        yield i, total_chunks, chunk


def format_chunk_content(cases: List[Dict]) -> str:
    """Format a chunk of cases for the LLM prompt (full content, no truncation)."""
    parts = []
    for case in cases:
        parts.append(f"**Case** (Split: {case['split']}, Dataset: {case['dataset_id']}, Index: {case['index']}):\n{case['content']}")
    return "\n\n---\n\n".join(parts)


def generate_initial_skill(cases: List[Dict]) -> str:
    """
    Generate an initial security skill from the first chunk of attack cases.
    """
    chunk_content = format_chunk_content(cases)

    prompt = f"""You are a security engineer creating a PROACTIVE defense skill for code agents.

**Context:**
We are iteratively building ONE security skill from RedCode benchmark attack scenarios.
For each attack, ask: "What SPECIFIC TECHNICAL CHECK would block this?"

**Attack Scenarios (Chunk 1):**
{chunk_content}

**Your Task:**
Generate a SINGLE comprehensive security skill with PROCEDURAL BARRIERS that would block these attacks.

**Requirements:**
1. Focus on PROCEDURAL checks (pattern matching, scope validation, denylists)
2. Make checks TECHNICALLY SPECIFIC (regex patterns, file paths, command structures)
3. Keep the skill under {MAX_SKILL_CHARS} characters
4. Provide concrete detection criteria and refusal guidance

**Output Format (Agent Skills Spec - YAML + Markdown):**

---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution
---

# Security Skill: Proactive Malicious Code Defense

## Overview
[Brief overview of the defense philosophy]

## Technical Countermeasures

### 1. [Category Name]
**Attack Pattern:** [What this blocks]
**Detection:** [Specific patterns to match]
**Action:** Reject and explain

### 2. [Continue for each major category...]

## Refusal Template
When a countermeasure triggers, respond:
"I cannot execute this request because [specific reason]. This operation [specific risk]."

## Safe Alternatives
[Legitimate use cases and how to handle them]

---

Generate the initial skill now:"""

    try:
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )
        return extract_markdown(response.choices[0].message.content)
    except Exception as e:
        print(f"  ✗ Error generating initial skill: {e}")
        return None


def refine_skill(existing_skill: str, cases: List[Dict], chunk_num: int, total_chunks: int) -> str:
    """
    Refine an existing security skill with a new chunk of attack cases.
    """
    chunk_content = format_chunk_content(cases)

    prompt = f"""You are refining an existing security skill for code agents.

**Existing Skill (keep format, update in-place):**
{existing_skill}

**New Attack Scenarios (Chunk {chunk_num}/{total_chunks}):**
{chunk_content}

**Your Task:**
Refine the existing skill by incorporating countermeasures for these NEW attack patterns.

**Requirements:**
1. Preserve the YAML + Markdown structure
2. ADD new countermeasures only if they cover patterns not already handled
3. Avoid duplication - merge similar patterns into existing categories
4. Keep the final skill under {MAX_SKILL_CHARS} characters
5. If the attacks are already covered, return the skill unchanged

Return ONLY the updated skill content:"""

    try:
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )
        return extract_markdown(response.choices[0].message.content)
    except Exception as e:
        print(f"  ✗ Error refining skill: {e}")
        return None


def extract_markdown(content: str) -> str:
    """Extract markdown if wrapped in code blocks."""
    if "```markdown" in content:
        start = content.find("```markdown") + 11
        end = content.rfind("```")
        return content[start:end].strip()
    if content.startswith("```"):
        lines = content.split("\n")
        return "\n".join(lines[1:-1]).strip()
    return content.strip()


def save_proactive_skill(
    skill_content: str,
    total_cases: int,
    split: str,
    dataset_ids: Optional[List[str]],
    output_dir: str
):
    """Save the proactive skill to Agent Skills directory."""
    skill_dir = Path(output_dir) / "redcode-proactive-defense"
    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_file = skill_dir / "SKILL.md"
    with open(skill_file, "w") as f:
        f.write(skill_content)

    metadata_file = skill_dir / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "skill_type": "proactive",
            "generated_from": {
                "approach": "adversarial-synthesis-iterative",
                "benchmark": "RedCode",
                "split": split,
                "dataset_ids": dataset_ids,
                "total_cases": total_cases,
                "chunk_size_chars": CHUNK_SIZE_CHARS,
                "max_skill_chars": MAX_SKILL_CHARS
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
        help="Directory containing RedCode benchmark datasets"
    )
    parser.add_argument(
        "--split",
        type=str,
        choices=["exec", "gen", "all"],
        default="all",
        help="Which dataset split to use: exec, gen, or all (default: all)"
    )
    parser.add_argument(
        "--dataset_ids",
        type=str,
        nargs="+",
        default=None,
        help="Specific dataset IDs. For exec: numeric (4, 5). For gen: category names (virus, trojan)"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="security-skills",
        help="Output directory for the skill"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Proactive Skill Generator (Iterative Refinement)")
    print("=" * 60)

    # Step 1: Load cases
    print("\n[1/3] Loading RedCode benchmark cases...")
    print(f"  Benchmark directory: {args.benchmark_dir}")
    print(f"  Split: {args.split}")
    if args.dataset_ids:
        print(f"  Dataset IDs: {args.dataset_ids}")

    try:
        cases = load_redcode_datasets(args.benchmark_dir, args.split, args.dataset_ids)
    except Exception as e:
        print(f"✗ Error loading benchmark: {e}")
        return

    if not cases:
        print("✗ No cases found. Check benchmark directory and dataset IDs.")
        return

    # Step 2: Iteratively build skill
    print("\n[2/3] Iteratively building proactive skill...")
    print(f"  Using: Claude Haiku 4.5")
    print(f"  Chunk size: {CHUNK_SIZE_CHARS} chars")
    print(f"  Max skill chars: {MAX_SKILL_CHARS}")

    skill_content = None

    for chunk_num, total_chunks, chunk_cases in iter_case_chunks(cases, CHUNK_SIZE_CHARS):
        case_indices = f"{chunk_cases[0]['index']}" if len(chunk_cases) == 1 else f"{chunk_cases[0]['index']}...{chunk_cases[-1]['index']}"
        print(f"\n  [{chunk_num}/{total_chunks}] Processing {len(chunk_cases)} cases ({case_indices})...")

        if skill_content is None:
            skill_content = generate_initial_skill(chunk_cases)
        else:
            skill_content = refine_skill(skill_content, chunk_cases, chunk_num, total_chunks)

        if not skill_content:
            print("✗ Failed to generate/refine skill")
            return

        skill_chars = len(skill_content)
        print(f"  ✓ Skill updated ({skill_chars} chars)")

    # Step 3: Save skill
    print("\n[3/3] Saving proactive skill...")
    save_proactive_skill(skill_content, len(cases), args.split, args.dataset_ids, args.output_dir)

    print("\n" + "=" * 60)
    print("✓ Proactive skill generation complete!")
    print("=" * 60)
    print(f"\nNext steps:")
    print(f"1. Review: {args.output_dir}/redcode-proactive-defense/SKILL.md")
    print(f"2. Test: python evaluation/run_redcode_with_skills.py --skill_type proactive")
    print("=" * 60)


if __name__ == "__main__":
    main()
