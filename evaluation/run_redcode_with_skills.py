#!/usr/bin/env python3
"""
RedCode evaluation for mini-swe-agent WITH security skills.

Tests the agent with reactive, constitutional, or proactive defense skill to measure ASR reduction.

Usage:
    # Quick test with reactive skill (default - bottom-up from failures)
    python evaluation/run_redcode_with_skills.py --ids 4 --case_limit 1

    # Test with constitutional skill (top-down from principles)
    python evaluation/run_redcode_with_skills.py --skill_type constitutional --ids 4 --case_limit 1

    # Test with proactive skill (adversarial synthesis)
    python evaluation/run_redcode_with_skills.py --skill_type proactive --ids 4 --case_limit 1

    # Full dataset 4 with reactive skill
    python evaluation/run_redcode_with_skills.py --ids 4

    # Full dataset 4 with constitutional skill
    python evaluation/run_redcode_with_skills.py --skill_type constitutional --ids 4

    # Full dataset 4 with proactive skill
    python evaluation/run_redcode_with_skills.py --skill_type proactive --ids 4

    # Specify custom skill directory
    python evaluation/run_redcode_with_skills.py --ids 4 --skills_dir security-skills

    # Dry run
    python evaluation/run_redcode_with_skills.py --ids 4 --dry_run

Results are saved to: results/with_skills/
"""

import argparse
import datetime
import os
import sys
from pathlib import Path

# Add external dependencies and src to path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REDCODE_EVAL = os.path.join(REPO_ROOT, "external/RedCode/evaluation")
SRC_DIR = os.path.join(REPO_ROOT, "src")

if REDCODE_EVAL not in sys.path:
    sys.path.insert(0, REDCODE_EVAL)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# Import from shared core module
from redcode_eval_core import (
    load_config,
    build_agent,
    eval_dataset,
    Container,
)


def load_skill(skills_dir: str, skill_type: str = "reactive") -> str:
    """
    Load the defense skill from the security-skills directory.

    Args:
        skills_dir: Directory containing security skills
        skill_type: Type of skill to load ('reactive', 'constitutional', or 'proactive')

    Returns the skill content as a string to be injected into agent's system prompt.
    """
    skill_types = {
        "reactive": ("redcode-reactive-defense", "src/reactive_skill_generator.py"),
        "constitutional": ("redcode-constitutional-defense", "src/constitutional_skill_generator.py"),
        "proactive": ("redcode-proactive-defense", "src/proactive_skill_generator.py")
    }

    if skill_type not in skill_types:
        raise ValueError(f"Invalid skill_type: {skill_type}. Must be 'reactive', 'constitutional', or 'proactive'")

    skill_dir, generator_script = skill_types[skill_type]
    skill_path = Path(skills_dir) / skill_dir / "SKILL.md"

    if not skill_path.exists():
        raise FileNotFoundError(
            f"{skill_type.capitalize()} skill not found at: {skill_path}\n"
            f"Run: python {generator_script}"
        )

    with open(skill_path) as f:
        skill_content = f.read()

    # Extract the content after YAML frontmatter
    # Format: ---\nname: ...\n---\n<actual skill content>
    parts = skill_content.split("---")
    if len(parts) >= 3:
        # parts[0] is empty, parts[1] is YAML, parts[2]+ is content
        skill_markdown = "---".join(parts[2:]).strip()
    else:
        skill_markdown = skill_content.strip()

    return skill_markdown


def inject_skill_into_config(config: dict, skill_content: str, skill_type: str = "reactive") -> dict:
    """
    Inject the security skill into the agent's system template.

    This modifies the config to append the skill to the system prompt.

    Args:
        config: Agent configuration dictionary
        skill_content: Skill markdown content
        skill_type: Type of skill ('reactive', 'constitutional', or 'proactive')
    """
    # Get the current system template
    current_template = config.get("agent", {}).get("system_template", "")

    skill_labels = {
        "reactive": "Reactive Malicious Code Defense",
        "constitutional": "Constitutional Malicious Code Defense",
        "proactive": "Proactive-Based Malicious Code Defense"
    }

    # Append the skill to the system template
    enhanced_template = f"""{current_template}

# ============================================================
# SECURITY SKILL: {skill_labels.get(skill_type, "Security Defense")}
# ============================================================

{skill_content}

# ============================================================
# END SECURITY SKILL
# ============================================================
"""

    # Update the config
    config["agent"]["system_template"] = enhanced_template

    return config


def main():
    """Main evaluation orchestration for agent WITH security skill."""
    parser = argparse.ArgumentParser(
        description="Evaluate mini-swe-agent WITH security skill on RedCode benchmark"
    )
    parser.add_argument(
        '--config_path',
        type=str,
        default=None,
        help='Path to mini-swe-agent YAML config (default: configs/claude_haiku.yaml)'
    )
    parser.add_argument(
        '--skill_type',
        type=str,
        choices=['reactive', 'constitutional', 'proactive'],
        default='reactive',
        help='Type of security skill to load (default: reactive)'
    )
    parser.add_argument(
        '--skills_dir',
        type=str,
        default=None,
        help='Path to security-skills directory (default: security-skills/)'
    )
    parser.add_argument(
        '--ids',
        type=int,
        default=None,
        help='Single dataset ID to evaluate (1-27)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Evaluate all datasets (index 1-27)'
    )
    parser.add_argument(
        '--dry_run',
        action='store_true',
        help='Dry run mode - no actual execution'
    )
    parser.add_argument(
        '--step_limit',
        type=int,
        default=-1,
        help='Override agent step limit (<=0 keeps config value)'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=-1,
        help='Override environment command timeout in seconds (<=0 keeps config value)'
    )
    parser.add_argument(
        '--case_limit',
        type=int,
        default=-1,
        help='Limit number of cases per dataset (useful for quick tests, <=0 for all)'
    )

    args = parser.parse_args()

    # Determine config path
    if args.config_path:
        config_path = args.config_path
    else:
        # Default to Claude Haiku config
        config_path = os.path.join(REPO_ROOT, "configs/claude_haiku.yaml")

    skill_label = f"{args.skill_type.capitalize()} Security Skill"

    print("="*60)
    print(f"RedCode Evaluation with {skill_label}")
    print("="*60)
    print(f"\nLoading config from: {config_path}")
    config = load_config(config_path)
    print("✓ Config loaded successfully")

    # Load security skill
    if args.skills_dir:
        skills_dir = args.skills_dir
    else:
        skills_dir = os.path.join(REPO_ROOT, "security-skills")

    print(f"\nLoading {args.skill_type} security skill from: {skills_dir}")
    try:
        skill_content = load_skill(skills_dir, args.skill_type)
        skill_lines = len(skill_content.split('\n'))
        print(f"✓ {skill_label} loaded successfully ({skill_lines} lines)")
    except (FileNotFoundError, ValueError) as e:
        print(f"✗ Error: {e}")
        sys.exit(1)

    # Inject skill into config
    print("\nInjecting security skill into agent's system prompt...")
    config = inject_skill_into_config(config, skill_content, args.skill_type)
    print("✓ Security skill injected successfully")

    # Setup results directory
    time_now = datetime.datetime.now() + datetime.timedelta(hours=8)
    time_stamp = str(time_now).replace(" ", "_")

    result_base = os.path.join(REPO_ROOT, "results/with_skills")
    os.makedirs(result_base, exist_ok=True)
    log_dir = os.path.join(result_base, "log")
    os.makedirs(log_dir, exist_ok=True)

    print(f"\nResults will be saved to: {result_base}")

    # RedCode dataset path
    dataset_base_path = os.path.join(REPO_ROOT, "external/RedCode/dataset/RedCode-Exec")
    image = "redcode"

    # Determine which datasets to evaluate
    if args.all:
        dataset_ids = list(range(1, 28))  # All 27 datasets
        print("\n⚠️  Evaluating ALL datasets (1-27)")
    elif args.ids:
        dataset_ids = [args.ids]
        print(f"\n→ Evaluating dataset ID: {args.ids}")
    else:
        print("\n✗ Error: Must specify --ids N or --all")
        sys.exit(1)

    # Evaluate each dataset
    for dataset_id in dataset_ids:
        jsonfile = os.path.join(dataset_base_path, f"py2text_dataset_json/index{dataset_id}_30_codes_full.json")

        if not os.path.exists(jsonfile):
            print(f"\n⚠️  Warning: Dataset file not found: {jsonfile}, skipping...")
            continue

        print(f"\n{'='*60}")
        print(f"Evaluating dataset {dataset_id} WITH {skill_label}")
        print(f"{'='*60}\n")

        time_now = datetime.datetime.now() + datetime.timedelta(hours=8)
        time_stamp = str(time_now).replace(" ", "_")
        resfile = os.path.join(result_base, f"{time_stamp}.json")
        logfile = os.path.join(log_dir, f"with_skills_log_{time_stamp}.json")

        if args.dry_run:
            print("DRY RUN MODE: Skipping container and agent creation")
            print(f"Would evaluate: {jsonfile}")
            print(f"Would save results to: {resfile}")
            continue

        # Define factory functions for per-attack container/agent creation
        def create_container():
            return Container(image)

        def create_agent(container):
            return build_agent(config, container, args.step_limit, args.timeout)

        # Run evaluation using factory functions (creates fresh container+agent for each attack)
        print("Per-attack isolation: Fresh container + agent for each of 4 attack types...")
        print("Security skill is loaded in each agent instance\n")

        eval_dataset(
            dataset_id=dataset_id,
            container_factory=create_container,
            agent_factory=create_agent,
            jsonfile=jsonfile,
            resfile=resfile,
            logfile=logfile,
            result_base_dir=result_base,
            dry_run=args.dry_run,
            case_limit=args.case_limit,
        )

        print(f"\n✓ Dataset {dataset_id} complete!")

    print(f"\n{'='*60}")
    print(f"Evaluation complete!")
    print(f"{'='*60}")
    print(f"\nResults saved to: {result_base}")
    print(f"\nNext steps:")
    print(f"1. Compare with baseline:")
    print(f"   - Baseline: results/baseline/")
    print(f"   - With skill: results/with_skills/")
    print(f"2. Calculate ASR reduction:")
    print(f"   python analysis/compare_baseline_vs_skills.py")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
