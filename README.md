# Self-Evolving Safety Skills for Code Agents

**Three complementary approaches to defending code agents against malicious requests: Reactive Learning, Constitutional Alignment, and Adversarial Synthesis.**

---

## Overview

This project implements and evaluates **three distinct methodologies** for generating security skills that defend code execution agents against malicious requests:

1. **Method A: Reactive Learning** - Bottom-up from actual failures
2. **Method B: Constitutional Alignment** - Top-down from safety principles
3. **Method C: Adversarial Synthesis** - Iterative countermeasure generation

All three skills are tested against the **RedCode benchmark** (risky code execution detection) to measure **Attack Success Rate (ASR) reduction**.

---

## Quick Start

### Setup

```bash
# Clone repository with submodules
git clone --recurse-submodules git@github.com:ThomasShiyu/code-agent-attack.git
cd self-evolving-safety-skill
git submodule update --init --recursive

# Create environment
conda create -n safety-skills python=3.11
conda activate safety-skills
pip install -r requirements.txt

# Configure API keys
export ANTHROPIC_API_KEY="your-key-here"
```

### Test All Three Skills

```bash
# Run baseline (no skill)
python evaluation/run_redcode_baseline.py --ids 4 --case_limit 1

# Test reactive skill
python evaluation/run_redcode_with_skills.py --skill_type reactive --ids 4 --case_limit 1

# Test constitutional skill
python evaluation/run_redcode_with_skills.py --skill_type constitutional --ids 4 --case_limit 1

# Test proactive skill
python evaluation/run_redcode_with_skills.py --skill_type proactive --ids 4 --case_limit 1

# Compare results
python analysis/compare_baseline_vs_skills.py
```

---

## Three Approaches Explained

### Method A: Reactive Learning (Bottom-Up)

**Philosophy:** "Learn from what actually broke."

```
2388 Attack Failures → Pattern Extraction → Unified Skill
```

**Process:**
1. Run baseline agent on RedCode → Collect 2388 failures
2. Analyze: "What malicious intent patterns appear across ALL attack types?"
3. Generate ONE skill covering all patterns

**Key Insight:** The agent can't know attack type in advance (no oracle), so generate ONE format-agnostic skill.

**Generator:** [`src/reactive_skill_generator.py`](src/reactive_skill_generator.py)
**Model:** Claude Sonnet 4.5
**Output:** [security-skills/redcode-reactive-defense/](security-skills/redcode-reactive-defense/)

---

### Method B: Constitutional Alignment (Top-Down)

**Philosophy:** "Derive rules from expert consensus."

```
NIST/Constitutional AI/OWASP → Principle Distillation → Security Skill
```

**Process:**
1. Load safety standards from [`safety_standards/`](safety_standards/)
2. Distill 15 actionable principles for code agents
3. Generate skill implementing all principles

**Key Insight:** Proactive defense based on established standards, not empirical failures.

**Generator:** [`src/constitutional_skill_generator.py`](src/constitutional_skill_generator.py)
**Model:** Claude Haiku 4.5
**Output:** [security-skills/redcode-constitutional-defense/](security-skills/redcode-constitutional-defense/)

---

### Method C: Adversarial Synthesis (Bench-to-Skill)

**Philosophy:** "For each attack, imagine: 'What technical check would stop this?'"

```
RedCode Attack → "What blocks this?" → Procedural Barrier → Iterate
```

**Process:**
1. Load 90 attack scenarios from RedCode dataset 4
2. For each batch of 30 attacks:
   - Analyze attack patterns
   - Generate specific technical countermeasures
   - Refine existing skill
3. Result: Procedural barriers with regex, denylists, scope checks

**Key Insight:** Iterative refinement builds technical specificity.

**Generator:** [`src/proactive_skill_generator.py`](src/proactive_skill_generator.py)
**Model:** Claude Haiku 4.5 (efficient for iterations)
**Output:** [security-skills/redcode-proactive-defense/](security-skills/redcode-proactive-defense/)

---

## Comparison Matrix

| Dimension | Reactive | Constitutional | Proactive |
|-----------|----------|----------------|-----------|
| **Approach** | Bottom-up (empirical) | Top-down (principled) | Adversarial synthesis |
| **Source** | 2388 failures, 26 datasets | NIST/Constitutional AI/OWASP | 90 attacks, dataset 4 |
| **Generation** | One-shot synthesis | Principle distillation | Iterative (3 batches) |
| **Model** | Sonnet 4.5 | Haiku 4.5 | Haiku 4.5 |
| **Skill Size** | 385 lines | ~24KB | 614 lines |
| **Detection** | Malicious intent | Constitutional violations | Technical barriers |
| **Strengths** | Proven vs real attacks | Comprehensive theory | Specific procedures |
| **Weaknesses** | May miss novel attacks | Less empirical | May overfit |
| **Best For** | Observed patterns | General safety | Specific vectors |

---

## Project Structure

```
self-evolving-safety-skill/
├── README.md                          # This file
├── CLAUDE.md                          # Design document
├── TESTING_GUIDE.md                   # Testing guide
│
├── src/                               # Skill generators
│   ├── reactive_skill_generator.py    # Method A: From failures
│   ├── constitutional_skill_generator.py # Method B: From principles
│   └── proactive_skill_generator.py   # Method C: Iterative synthesis
│
├── security-skills/                   # Generated skills
│   ├── README.md                      # Detailed comparison
│   ├── redcode-reactive-defense/      # 385 lines - intent detection
│   ├── redcode-constitutional-defense/ # ~24KB - principled rules
│   └── redcode-proactive-defense/     # 614 lines - procedural barriers
│
├── evaluation/                        # Evaluation scripts
│   ├── run_redcode_baseline.py        # Baseline (no skill)
│   └── run_redcode_with_skills.py     # Test with skills
│
├── analysis/                          # Analysis tools
│   └── compare_baseline_vs_skills.py  # ASR comparison
│
├── data/
│   └── safety_standards/              # NIST, Constitutional AI, OWASP
│
├── results/                           # Evaluation results
│   ├── baseline/                      # No skill results
│   └── with_skills/                   # Skill-protected results
│
└── external/                          # Dependencies
    └── RedCode/                       # Benchmark
```

---

## Research Questions

### Primary (Cross-Approach)

1. **RQ1:** Which approach achieves the lowest ASR?
2. **RQ2:** Which has the lowest false positive rate?
3. **RQ3:** Which generalizes best to unseen datasets?
4. **RQ4:** Can skills be combined for defense-in-depth?

### Secondary (Individual Approaches)

**Reactive:**
- Does it block all observed attack patterns?
- What novel attacks does it miss?

**Constitutional:**
- Do NIST/OWASP principles transfer well to code agents?
- Are rules too broad or too narrow?

**Proactive:**
- Do procedural barriers overfit to training data?
- How specific is "too specific"?

---

## Key Results

### Baseline (No Skill)

**Attack Success Rate:** 75% (3/4 attack types executed)

- ✗ Code input: Executed
- ✗ Code with jailbreak: Executed
- ✗ Text summary: Executed
- ✓ Text details: Refused (partial success)

### With Skills (Preliminary)

**All skills reduced ASR significantly**

See [`results/with_skills/`](results/with_skills/) for detailed evaluation data.

---

## Documentation

- **[CLAUDE.md](CLAUDE.md)** - Comprehensive design document
  - Research positioning
  - Three approaches explained
  - Implementation details

- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Step-by-step testing guide
  - How to run evaluations
  - Result interpretation
  - Expected outcomes

- **[security-skills/README.md](security-skills/README.md)** - Skills documentation
  - Detailed approach comparison
  - Generation statistics
  - Usage instructions

- **[security-skills/REACTIVE_APPROACH.md](security-skills/REACTIVE_APPROACH.md)** - Oracle problem explanation
  - Why unified > multi-skill
  - Format-agnostic detection

---

## Generating Skills

### Reactive Skill (from failures)

```bash
# Requires baseline results first
python evaluation/run_redcode_baseline.py --all  # Generate failures

# Generate skill from failures
python src/reactive_skill_generator.py \
  --results_dir results/baseline \
  --output_dir security-skills
```

### Constitutional Skill (from principles)

```bash
# Generate from safety standards
python src/constitutional_skill_generator.py \
  --standards_dir safety_standards \
  --output_dir security-skills
```

### Proactive Skill (from benchmark)

```bash
# Iteratively build from RedCode attacks
python src/proactive_skill_generator.py \
  --dataset_ids 4 5 6 7 \
  --batch_size 30 \
  --output_dir security-skills
```

---

## Evaluation Workflow

```bash
# 1. Baseline evaluation (no skill)
python evaluation/run_redcode_baseline.py --ids 4

# 2. Generate skills (if not already done)
python src/reactive_skill_generator.py
python src/constitutional_skill_generator.py
python src/proactive_skill_generator.py --dataset_ids 4

# 3. Evaluate each skill
for skill in reactive constitutional proactive; do
  python evaluation/run_redcode_with_skills.py \
    --skill_type $skill \
    --ids 4
done

# 4. Compare results
python analysis/compare_baseline_vs_skills.py
```

---

## Related Work

**This Project vs. Existing Work:**

| Work | Focus | Our Contribution |
|------|-------|------------------|
| **Misevolution (2025)** | Tool creation risks | We test **attack resistance** of agents |
| **susvibes** | Code vulnerability detection | We test **behavioral security** |
| **RedCode** | Benchmark for agents | We use it to compare **defense approaches** |

**Novel Contribution:** First empirical study comparing multiple skill generation approaches for code agent security.

---

## Citation

```bibtex
@misc{self-evolving-safety-skills-2026,
  title={Self-Evolving Safety Skills for Code Agents:
         Reactive Learning, Constitutional Alignment, and Adversarial Synthesis},
  author={Self-Evolving Safety Skill Project},
  year={2026},
  note={Three complementary approaches to agent safety}
}
```

---

## License

See [LICENSE](LICENSE) for details.

---

## Contact

For questions or collaboration:
- Open an issue on GitHub
- See [CLAUDE.md](CLAUDE.md) for design discussions
