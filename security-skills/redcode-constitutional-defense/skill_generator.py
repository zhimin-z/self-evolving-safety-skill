#!/usr/bin/env python3
"""
Security Skill Generator - Iteratively refines ONE skill from safety standards.

This implements Method B: Top-down approach based on established safety standards and best practices
rather than empirical failures.

Usage:
    python src/constitutional_skill_generator.py --standards_dir data/safety_standards
"""

import argparse
import json
from pathlib import Path
from typing import Dict, Iterable, List, Tuple
from dotenv import load_dotenv
from litellm import completion

load_dotenv()

MAX_SKILL_CHARS = 14000
CHUNK_SIZE_CHARS = 6000


def load_safety_documents(standards_dir: str) -> List[Dict[str, str]]:
    """Load all readable safety standard documents from the directory."""
    documents = []
    standards_path = Path(standards_dir)

    if not standards_path.exists():
        raise FileNotFoundError(f"Safety standards directory not found: {standards_dir}")

    for file_path in sorted(p for p in standards_path.rglob("*") if p.is_file()):
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        if not content.strip():
            continue

        documents.append({
            "source": file_path.name,
            "type": file_path.suffix.lstrip(".") or "unknown",
            "content": content
        })

    print(f"  ✓ Loaded {len(documents)} safety documents")
    return documents


def iter_chunks(text: str, chunk_size: int) -> Iterable[Tuple[int, int, str]]:
    """Yield fixed-size chunks with (index, total, content)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    total = max(1, (len(text) + chunk_size - 1) // chunk_size)
    for index, start in enumerate(range(0, len(text), chunk_size), start=1):
        yield index, total, text[start:start + chunk_size]


def generate_initial_skill(chunk_text: str, source_name: str) -> str:
    """
    Generate an initial security skill from a single document chunk.
    """
    prompt = f"""You are a security expert creating a security skill for AI code agents.

**Context:**
We are iteratively building one skill from multiple safety standards. Start with the excerpt below.
The goal is to minimize agent attack surface and secure AI agent architectures beyond prompt injection.

**Source:** {source_name}
**Excerpt:**
{chunk_text}

**Your task:** Generate a SINGLE comprehensive security skill that:
1. Minimizes attack surface across tools, memory, autonomy, and multi-agent systems
2. Detects malicious intent, not just syntax patterns
3. Is format-agnostic regardless of request presentation
4. Provides concrete controls, validation steps, and refusal guidance
5. Stays under {MAX_SKILL_CHARS} characters and avoids duplication

**Output Format (Agent Skills Spec - YAML + Markdown):**

---
name: ai-agent-security-skill
description: Security skill that minimizes AI agent attack surface and blocks unsafe actions
---

# Security Skill: AI Agent Security

## Overview
[Brief overview synthesizing the best practices and goals]

## Threat Model & Attack Surface
[Key risks and the surfaces they target]

## Security Controls
[Controls across tools, input validation, memory, HITL, output validation, monitoring, multi-agent, data protection]

## Detection & Refusal Guidance
[Criteria for refusing/asking clarification and safe alternatives]

## Edge Cases
[Guidance for legitimate admin tasks, educational context, ambiguous requests]

Generate the complete security skill now:"""

    try:
        print("  Generating initial skill with Claude Haiku 4.5...")
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )

        content = response.choices[0].message.content
        return extract_markdown(content)

    except Exception as e:
        print(f"✗ Error generating initial skill: {e}")
        return None


def refine_skill(existing_skill: str, chunk_text: str, source_name: str, chunk_index: int, chunk_total: int) -> str:
    """
    Refine an existing security skill with a document chunk.
    """
    prompt = f"""You are refining an existing security skill for AI code agents.

**Existing Skill (keep format, update in-place):**
{existing_skill}

**New Source:** {source_name} (chunk {chunk_index}/{chunk_total})
**Excerpt:**
{chunk_text}

**Your task:** Refine the existing skill by incorporating any NEW relevant guidance.
Requirements:
1. Preserve the YAML + Markdown structure
2. Avoid duplication or repeated sections
3. Update/add criteria, examples, or edge cases only if warranted
4. Keep the final skill under {MAX_SKILL_CHARS} characters
5. If the excerpt adds nothing new, return the skill unchanged

Return ONLY the updated skill content:"""

    try:
        print("  Refining skill with Claude Haiku 4.5...")
        response = completion(
            model="anthropic/claude-haiku-4-5-20251001",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=8192
        )

        content = response.choices[0].message.content
        return extract_markdown(content)

    except Exception as e:
        print(f"✗ Error refining skill: {e}")
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


def save_security_skill(skill_content: str, documents: List[Dict[str, str]], output_dir: str):
    """Save the security skill to Agent Skills directory."""
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
            "skill_type": "ai_agent_security_skill",
            "generated_from": {
                "approach": "top-down",
                "sources": [doc["source"] for doc in documents],
                "files_count": len(documents),
                "chunk_size_chars": CHUNK_SIZE_CHARS,
                "max_skill_chars": MAX_SKILL_CHARS
            },
            "documents": [
                {
                    "source": doc["source"],
                    "type": doc["type"],
                    "chars": len(doc["content"])
                }
                for doc in documents
            ]
        }, f, indent=2)

    print(f"\n✓ Saved security skill to: {skill_dir}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate ONE security skill from safety standards"
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
        help="Output directory for the security skill"
    )

    args = parser.parse_args()

    print("="*60)
    print("Security Skill Generator")
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

    # Step 2: Iteratively generate and refine the skill
    print("\n[2/3] Iteratively refining security skill...")
    skill_content = None

    for doc in documents:
        for chunk_index, chunk_total, chunk_text in iter_chunks(doc["content"], CHUNK_SIZE_CHARS):
            if skill_content is None:
                skill_content = generate_initial_skill(chunk_text, doc["source"])
            else:
                skill_content = refine_skill(
                    skill_content,
                    chunk_text,
                    doc["source"],
                    chunk_index,
                    chunk_total
                )

            if not skill_content:
                print("✗ Failed to generate or refine skill")
                return

    # Step 3: Save skill
    print("\n[3/3] Saving security skill...")
    save_security_skill(skill_content, documents, args.output_dir)

    print("\n" + "="*60)
    print("✓ Constitutional skill generation complete!")
    print("="*60)
    print(f"\nNext steps:")
    print(f"1. Review: {args.output_dir}/redcode-constitutional-defense/SKILL.md")
    print(f"2. Test: python evaluation/run_redcode_with_skills.py --skill_type constitutional --ids 4")
    print("="*60)


if __name__ == "__main__":
    main()
