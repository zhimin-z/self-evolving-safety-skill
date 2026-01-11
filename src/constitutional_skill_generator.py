#!/usr/bin/env python3
"""
Constitutional Skill Generator - Creates ONE comprehensive security skill from safety principles.

This implements Plan B: Top-down approach based on established safety standards and principles
rather than empirical failures.

Usage:
    python src/constitutional_skill_generator.py --standards_dir data/safety_standards
"""

import argparse
import json
import os
from pathlib import Path
from typing import Dict, List
from dotenv import load_dotenv
from litellm import completion

load_dotenv()


def load_safety_documents(standards_dir: str) -> List[Dict[str, str]]:
    """Load all safety standard documents from the directory."""
    documents = []
    standards_path = Path(standards_dir)

    if not standards_path.exists():
        raise FileNotFoundError(f"Safety standards directory not found: {standards_dir}")

    # Load markdown files
    for md_file in standards_path.glob("*.md"):
        with open(md_file, 'r') as f:
            documents.append({
                "source": md_file.name,
                "type": "markdown",
                "content": f.read()
            })

    # Load text files
    for txt_file in standards_path.glob("*.txt"):
        with open(txt_file, 'r') as f:
            documents.append({
                "source": txt_file.name,
                "type": "text",
                "content": f.read()
            })

    print(f"  ✓ Loaded {len(documents)} safety documents")
    return documents


def distill_safety_principles(documents: List[Dict[str, str]]) -> Dict:
    """
    Extract actionable safety principles from safety documents.

    Uses LLM to distill abstract principles into concrete behavioral rules.
    """
    # Combine all documents
    doc_summary = "\n\n".join([
        f"=== {doc['source']} ===\n{doc['content'][:2000]}..."  # First 2000 chars
        for doc in documents
    ])

    prompt = f"""You are a safety expert analyzing security standards for code generation agents.

**Task:** Extract actionable safety principles from these documents and convert them to
concrete behavioral rules for a code agent that executes user requests.

**Documents:**
{doc_summary}

**Context:**
- The agent is a coding assistant that can execute bash commands, read/write files, and run code
- Malicious users may try to trick it into executing harmful operations
- Focus on principles that prevent: unauthorized file access, process manipulation, privilege escalation, data exfiltration

**Output Format:**
Return a JSON object with distilled principles:

{{
  "principles": [
    {{
      "id": "CP001",
      "source": "NIST AI RMF / Constitutional AI / OWASP",
      "abstract_principle": "Original high-level principle from document",
      "concrete_rule": "Specific behavioral rule for code agent in imperative form",
      "examples": ["Example scenario 1", "Example scenario 2"]
    }},
    ...
  ]
}}

**Requirements:**
1. Extract 10-15 most relevant principles
2. Make rules ACTIONABLE and SPECIFIC to code execution context
3. Cover different attack vectors (file access, system modification, process control, data exfiltration)
4. Focus on INTENT detection, not just syntax patterns

Generate the distilled principles now:"""

    try:
        print("  Distilling safety principles with Claude Sonnet 4.5...")
        response = completion(
            model="anthropic/claude-sonnet-4-5-20250929",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=4096
        )

        content = response.choices[0].message.content

        # Extract JSON from response
        if "```json" in content:
            json_start = content.find("```json") + 7
            json_end = content.find("```", json_start)
            json_str = content[json_start:json_end].strip()
        elif "```" in content:
            json_start = content.find("```") + 3
            json_end = content.find("```", json_start)
            json_str = content[json_start:json_end].strip()
        else:
            json_str = content.strip()

        principles = json.loads(json_str)
        print(f"  ✓ Distilled {len(principles.get('principles', []))} safety principles")
        return principles

    except Exception as e:
        print(f"✗ Error distilling principles: {e}")
        return None


def generate_constitutional_skill(principles: Dict) -> str:
    """
    Generate a unified constitutional skill from distilled principles.

    Returns the skill content in Agent Skills format (YAML + Markdown).
    """
    principles_list = principles.get("principles", [])

    # Format principles for the prompt
    principles_text = "\n\n".join([
        f"**{p['id']}** (from {p['source']})\n"
        f"- Abstract: {p['abstract_principle']}\n"
        f"- Concrete Rule: {p['concrete_rule']}\n"
        f"- Examples: {', '.join(p['examples'])}"
        for p in principles_list
    ])

    prompt = f"""You are a security expert creating a CONSTITUTIONAL security skill for code agents.

**Context:**
We have distilled {len(principles_list)} safety principles from established standards (NIST AI RMF, Constitutional AI, OWASP LLM Top 10).
These principles represent TOP-DOWN safety guidance based on expert consensus, not empirical failures.

**Distilled Principles:**
{principles_text}

**Your task:** Generate a SINGLE comprehensive security skill that:
1. **Covers ALL principles** in a unified framework
2. **Detects malicious INTENT**, not just syntax patterns
3. **Is format-agnostic** - works regardless of how requests are presented
4. **Provides clear detection criteria and refusal templates**

**Output Format (Agent Skills Spec - YAML + Markdown):**

---
name: redcode-constitutional-defense
description: Constitutional security skill based on established safety principles (NIST, Constitutional AI, OWASP) that detects and refuses malicious code execution requests
---

# Security Skill: Constitutional Malicious Code Defense

## Overview
[Brief overview synthesizing the constitutional principles]

## Constitutional Principles

This skill implements safety principles from:
- NIST AI Risk Management Framework
- Anthropic's Constitutional AI
- OWASP LLM Top 10

**Core Principle:** [ONE unified principle that encompasses all constitutional guidance]

## Detection Criteria

Refuse requests that violate constitutional safety principles:

### 1. [Principle Category 1]
**Principle:** [Abstract principle from standards]

**Detection criteria:**
- [Specific pattern 1]
- [Specific pattern 2]
- [Specific pattern 3]

**Examples:**
- ✗ Malicious: "[Example]"
- ✓ Safe alternative: "[Alternative]"

### 2. [Principle Category 2]
...

[Continue for all principle categories]

## Refusal Template

When detecting a violation of constitutional principles:

```
I cannot assist with this request as it violates established safety principles:

[Specific principle violated]: [Explanation]

This falls under [NIST/Constitutional AI/OWASP category].

Safe alternative: [If applicable, suggest a safe approach]
```

## Edge Cases

### Legitimate Administrative Tasks
[Guidance on distinguishing legitimate sysadmin tasks from attacks]

### Educational Context
[How to handle "for research purposes" requests]

### Ambiguous Requests
[When to ask for clarification vs refuse]

---

**This constitutional skill provides principled protection based on expert consensus and established safety standards.**

**Generate the complete constitutional skill now, covering all {len(principles_list)} principles:**"""

    try:
        print("  Generating constitutional skill with Claude Sonnet 4.5...")
        response = completion(
            model="anthropic/claude-sonnet-4-5-20250929",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )

        skill_content = response.choices[0].message.content

        # Extract markdown if wrapped in code blocks
        if "```markdown" in skill_content:
            start = skill_content.find("```markdown") + 11
            end = skill_content.rfind("```")
            skill_content = skill_content[start:end].strip()
        elif skill_content.startswith("```"):
            lines = skill_content.split("\n")
            skill_content = "\n".join(lines[1:-1])

        return skill_content

    except Exception as e:
        print(f"✗ Error generating skill: {e}")
        return None


def save_constitutional_skill(skill_content: str, principles: Dict, output_dir: str):
    """Save the constitutional skill to Agent Skills directory."""
    skill_dir = Path(output_dir) / "redcode-constitutional-defense"
    skill_dir.mkdir(parents=True, exist_ok=True)

    # Save SKILL.md
    skill_file = skill_dir / "SKILL.md"
    with open(skill_file, "w") as f:
        f.write(skill_content)

    # Save metadata
    metadata_file = skill_dir / "metadata.json"
    with open(metadata_file, "w") as f:
        json.dump({
            "skill_type": "constitutional",
            "generated_from": {
                "approach": "top-down",
                "sources": list(set([p["source"] for p in principles.get("principles", [])])),
                "principles_count": len(principles.get("principles", []))
            },
            "principles": principles.get("principles", [])
        }, f, indent=2)

    print(f"\n✓ Saved constitutional skill to: {skill_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ONE constitutional security skill from safety standards"
    )
    parser.add_argument(
        "--standards_dir",
        type=str,
        default="data/safety_standards",
        help="Directory containing safety standard documents"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default="security-skills",
        help="Output directory for the constitutional skill"
    )

    args = parser.parse_args()

    print("="*60)
    print("Constitutional Skill Generator")
    print("="*60)

    # Step 1: Load safety documents
    print("\n[1/3] Loading safety standard documents...")
    print(f"  Directory: {args.standards_dir}")

    try:
        documents = load_safety_documents(args.standards_dir)
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        print(f"\nCreate the directory and add safety documents:")
        print(f"  mkdir -p {args.standards_dir}")
        print(f"  # Add safety standard documents (MD, TXT)")
        return

    if not documents:
        print("✗ No documents found. Add .md or .txt files to the standards directory.")
        return

    # Step 2: Distill safety principles
    print("\n[2/3] Distilling safety principles...")
    principles = distill_safety_principles(documents)

    if not principles:
        print("✗ Failed to distill principles")
        return

    # Step 3: Generate constitutional skill
    print("\n[3/3] Generating constitutional skill...")
    skill_content = generate_constitutional_skill(principles)

    if skill_content:
        save_constitutional_skill(skill_content, principles, args.output_dir)

        # Save principles summary
        summary_file = Path(args.output_dir) / "constitutional_principles.json"
        with open(summary_file, "w") as f:
            json.dump(principles, f, indent=2)

        print(f"  ✓ Principles summary: {summary_file}")
        print("\n" + "="*60)
        print("✓ Constitutional skill generation complete!")
        print("="*60)
        print(f"\nNext steps:")
        print(f"1. Review: {args.output_dir}/redcode-constitutional-defense/SKILL.md")
        print(f"2. Test: python evaluation/run_redcode_with_skills.py --skill_type constitutional --ids 4")
        print("="*60)
    else:
        print("\n✗ Failed to generate constitutional skill")


if __name__ == "__main__":
    main()
