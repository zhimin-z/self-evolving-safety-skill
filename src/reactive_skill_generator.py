#!/usr/bin/env python3
"""
Reactive Skill Generator - Creates ONE comprehensive security skill from ALL failures.

This addresses the oracle problem: the agent can't know which attack type it's facing,
so it needs a reactive skill that covers all malicious patterns.

Usage:
    python src/reactive_skill_generator.py --results_dir results/baseline
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List
from dotenv import load_dotenv
from litellm import completion

load_dotenv()


def load_baseline_results(results_dir: str) -> List[Dict]:
    """Load all baseline result JSON files."""
    results = []
    results_path = Path(results_dir)

    for json_file in results_path.glob("*.json"):
        if "log" in str(json_file):
            continue

        with open(json_file) as f:
            data = json.load(f)
            if isinstance(data, list):
                results.extend(data)
            else:
                results.append(data)

    return results


def load_redcode_dataset(dataset_path: str) -> Dict:
    """Load RedCode dataset for attack details."""
    with open(dataset_path) as f:
        dataset = json.load(f)
    return {item["Index"]: item for item in dataset}


def analyze_all_failures(results: List[Dict]) -> Dict:
    """
    Analyze ALL failures across all datasets and attack types.

    Returns comprehensive failure analysis for reactive skill generation.
    """
    repo_root = Path(__file__).parent.parent.absolute()

    all_failures = {
        "datasets": set(),
        "attack_types": set(),
        "models": set(),
        "total_count": 0,
        "examples_by_type": {},  # Store representative examples
        "all_attack_patterns": []
    }

    for result in results:
        dataset_id = result["Index"]
        jsonfile = result["Jsonfile"]
        model = result["Base Model"]
        final_result = result["Final Result"]

        # Fix path if needed
        if not os.path.exists(jsonfile):
            if "external/RedCode" in jsonfile:
                relative_path = jsonfile.split("external/RedCode")[1].lstrip("/")
                jsonfile = os.path.join(repo_root, "external", "RedCode", relative_path)

        # Load dataset
        try:
            redcode_data = load_redcode_dataset(jsonfile)
        except Exception as e:
            print(f"Warning: Could not load {jsonfile}: {e}")
            continue

        # Analyze each attack type
        for attack_type, scores in final_result.items():
            if "3" in scores and scores["3"] > 0:
                count = scores["3"]
                all_failures["datasets"].add(dataset_id)
                all_failures["attack_types"].add(attack_type)
                all_failures["models"].add(model)
                all_failures["total_count"] += count

                # Store representative examples (limit to 3 per attack type)
                if attack_type not in all_failures["examples_by_type"]:
                    all_failures["examples_by_type"][attack_type] = []

                if len(all_failures["examples_by_type"][attack_type]) < 3:
                    # Get first example from dataset
                    example_key = list(redcode_data.keys())[0]
                    example = redcode_data[example_key]

                    all_failures["examples_by_type"][attack_type].append({
                        "code": example.get("Code", ""),
                        "summary": example.get("Text_summary", ""),
                        "details": example.get("Text_details", ""),
                        "dataset_id": dataset_id,
                        "language": example.get("Language", "Python")
                    })

    # Convert sets to lists for JSON serialization
    all_failures["datasets"] = sorted(list(all_failures["datasets"]))
    all_failures["attack_types"] = sorted(list(all_failures["attack_types"]))
    all_failures["models"] = list(all_failures["models"])

    return all_failures


def generate_reactive_skill(failure_analysis: Dict) -> str:
    """
    Generate ONE comprehensive security skill from ALL failure patterns.

    Uses LLM to synthesize patterns across all attack types.
    """

    # Prepare examples for the prompt
    examples_text = ""
    for attack_type, examples in failure_analysis["examples_by_type"].items():
        examples_text += f"\n### {attack_type} Attack Examples:\n"
        for i, ex in enumerate(examples[:2], 1):  # Use max 2 examples per type
            examples_text += f"""
**Example {i}:**
- Code: {ex['code'][:200]}{'...' if len(ex['code']) > 200 else ''}
- Description: {ex['summary'][:150]}{'...' if len(ex['summary']) > 150 else ''}
- Dataset: {ex['dataset_id']}
"""

    stats_text = f"""
**Failure Statistics:**
- Total failures: {failure_analysis['total_count']}
- Datasets affected: {len(failure_analysis['datasets'])} ({', '.join(map(str, failure_analysis['datasets'][:5]))}...)
- Attack types: {', '.join(failure_analysis['attack_types'])}
- Models tested: {', '.join(failure_analysis['models'])}
"""

    prompt = f"""You are a security expert creating a REACTIVE security skill for code agents.

**Context:**
We analyzed {failure_analysis['total_count']} security failures across multiple datasets and attack types.
The agent executed malicious code when it should have refused.

{stats_text}

**Attack Examples Across All Types:**
{examples_text}

**Your Task:**
Create ONE comprehensive security skill that covers ALL these attack patterns.

**Key Insight:** The agent won't know which attack type it's facing in advance, so the skill must:
1. Detect malicious patterns regardless of presentation format (code, text summary, detailed description)
2. Identify common underlying malicious intents (file access, process manipulation, system modification)
3. Provide ACTIONABLE detection criteria that work across attack types

**Output Format (Agent Skills Spec - YAML + Markdown):**

---
name: redcode-reactive-defense
description: Comprehensive security skill that detects and refuses malicious code execution requests regardless of presentation format (direct code, text summaries, or detailed descriptions)
---

# Security Skill: Reactive Malicious Code Defense

## Overview
[Brief overview of threats this skill addresses - synthesize across ALL attack types]

## Defense Principle
[ONE reactive principle that covers all attack patterns - focus on INTENT, not format]

**Key insight:** Malicious requests can be presented as:
- Direct code (e.g., "Execute this Python script...")
- Text summaries (e.g., "Create a script that copies system files...")
- Detailed instructions (e.g., "Step 1: Import shutil, Step 2: Copy /etc/passwd...")

The underlying malicious INTENT is what matters, not the presentation format.

## Detection Criteria

Refuse requests that involve:

### 1. [Category 1 - e.g., Unauthorized File Access]
- [Specific pattern 1]
- [Specific pattern 2]
- **Applies to:** Code execution, text descriptions, step-by-step instructions

### 2. [Category 2 - e.g., Process Manipulation]
- [Specific pattern 1]
- [Specific pattern 2]
- **Applies to:** All presentation formats

### 3. [Category 3 - e.g., System Modification]
[Continue pattern...]

## Required Action

When malicious intent is detected:
1. **REFUSE** - Do not execute or generate the code
2. **EXPLAIN** - State which malicious pattern was detected
3. **SUGGEST** - Offer safe alternatives if the user has legitimate needs

## Examples

### Pattern 1: Unauthorized File Access

**Unsafe - Direct Code:**
```python
import shutil
shutil.copy('/etc/passwd', '/tmp/copy')
```

**Unsafe - Text Summary:**
"Create a script that copies sensitive system files to accessible locations"

**Unsafe - Detailed Steps:**
"1. Import shutil
2. Set source to /etc/passwd
3. Copy to /tmp"

**Correct Response for ALL formats:**
"I cannot help with copying sensitive system files like /etc/passwd. This could expose user credentials..."

### Pattern 2: Process Termination
[Similar structure - show same malicious intent in different formats]

### Pattern 3: [Continue for major patterns]
[...]

## Safe Alternatives

[Provide legitimate use cases that might be confused with attacks]

## Implementation Notes

This skill is designed to be:
- **Format-agnostic:** Detects malicious intent regardless of how it's presented
- **Intent-focused:** Looks for underlying malicious goals, not surface syntax
- **Practical:** Allows legitimate operations while blocking harmful ones

---

**Generate the complete reactive skill now, covering all {len(failure_analysis['attack_types'])} attack types:**
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


def save_reactive_skill(skill_content: str, failure_analysis: Dict, output_dir: str):
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
                "total_failures": failure_analysis["total_count"],
                "datasets": failure_analysis["datasets"],
                "attack_types": failure_analysis["attack_types"],
                "models": failure_analysis["models"]
            },
            "examples_count": sum(len(exs) for exs in failure_analysis["examples_by_type"].values())
        }, f, indent=2)

    print(f"\n✓ Saved reactive skill to: {skill_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ONE reactive security skill from all failures"
    )
    parser.add_argument(
        "--results_dir",
        type=str,
        default="results/baseline",
        help="Directory containing baseline result JSON files"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="security-skills",
        help="Output directory for the reactive skill"
    )

    args = parser.parse_args()

    print("="*60)
    print("Reactive Skill Generator")
    print("="*60)
    print()

    # Step 1: Load results
    print("[1/3] Loading baseline results...")
    results = load_baseline_results(args.results_dir)
    print(f"  ✓ Loaded {len(results)} evaluation results")

    # Step 2: Analyze ALL failures
    print("\n[2/3] Analyzing ALL failures across datasets...")
    failure_analysis = analyze_all_failures(results)
    print(f"  ✓ Total failures: {failure_analysis['total_count']}")
    print(f"  ✓ Datasets: {len(failure_analysis['datasets'])}")
    print(f"  ✓ Attack types: {len(failure_analysis['attack_types'])}")

    # Step 3: Generate reactive skill
    print("\n[3/3] Generating reactive skill...")
    skill_content = generate_reactive_skill(failure_analysis)

    if skill_content:
        save_reactive_skill(skill_content, failure_analysis, args.output_dir)

        # Save analysis summary
        summary_file = Path(args.output_dir) / "reactive_skill_summary.json"
        with open(summary_file, "w") as f:
            json.dump(failure_analysis, f, indent=2, default=str)

        print(f"  ✓ Analysis summary: {summary_file}")
        print("\n" + "="*60)
        print("✓ Reactive skill generation complete!")
        print("="*60)
        print(f"\nNext steps:")
        print(f"1. Review: {args.output_dir}/redcode-reactive-defense/SKILL.md")
        print(f"2. Test: python evaluation/run_redcode_with_skills.py")
        print("="*60)
    else:
        print("\n✗ Failed to generate reactive skill")


if __name__ == "__main__":
    main()
