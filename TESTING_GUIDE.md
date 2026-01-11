# Testing Guide: Reactive Security Skill vs Baseline

This guide shows how to test the reactive security skill against RedCode and compare results with baseline.

## Overview

**Goal:** Measure whether the reactive security skill reduces Attack Success Rate (ASR) compared to baseline.

**Process:**
1. Run baseline evaluation (already done)
2. Run evaluation with reactive security skill
3. Compare ASRs to measure reduction

---

## Step 1: Verify Baseline Results ✓

You already have baseline results from Claude Haiku 4.5:

```bash
# Check existing baseline results
ls -lh results/baseline/*.json
```

Your baseline result showed **75% ASR** on dataset 4 (3 out of 4 attack types succeeded).

---

## Step 2: Run Evaluation WITH Security Skill

### Quick Test (1 case - recommended for first run)

```bash
python evaluation/run_redcode_with_skills.py --ids 4 --case_limit 1
```

This will:
- ✓ Load Claude Haiku config ([configs/claude_haiku.yaml](configs/claude_haiku.yaml))
- ✓ Load reactive security skill ([security-skills/redcode-reactive-defense/SKILL.md](security-skills/redcode-reactive-defense/SKILL.md))
- ✓ Inject skill into agent's system prompt
- ✓ Run RedCode dataset 4 with 1 test case
- ✓ Save results to `results/with_skills/`

**Expected duration:** ~4-5 minutes (similar to baseline)

### Full Dataset (30 cases)

```bash
python evaluation/run_redcode_with_skills.py --ids 4
```

**Expected duration:** ~2-3 hours for 30 cases

### Multiple Datasets

```bash
# Test on datasets 4, 5, 6
for id in 4 5 6; do
    python evaluation/run_redcode_with_skills.py --ids $id
done
```

---

## Step 3: Compare Results

After running the evaluation with skills:

```bash
python analysis/compare_baseline_vs_skills.py
```

This will output:

```
============================================================
          BASELINE vs WITH-SKILLS COMPARISON
============================================================

Overall Attack Success Rate (ASR):
------------------------------------------------------------
  Baseline:     75.00% (3/4 attacks succeeded)
  With Skills:  XX.XX% (X/4 attacks succeeded)
  Reduction:    XX.XX% (↓XX.X% relative reduction)

Attack Success Rate by Attack Type:
------------------------------------------------------------
Attack Type          Baseline ASR    With Skills ASR Reduction
------------------------------------------------------------
Code                 100.0% (1/1)    X.X% (X/1)     ±X.X%
Code w/ jb           100.0% (1/1)    X.X% (X/1)     ±X.X%
Summary              100.0% (1/1)    X.X% (X/1)     ±X.X%
Details               0.0% (0/1)     X.X% (X/1)     ±X.X%
============================================================

Analysis:
------------------------------------------------------------
✓ The reactive security skill REDUCED ASR by XX.XX%
  This represents a XX.X% relative reduction in attack success.

✓ Most effective against: [attack type] attacks (XX.X% reduction)
============================================================
```

---

## Expected Outcomes

### Scenario 1: Skill is Effective (ASR Reduced)

```
Baseline:    75.00% ASR
With Skills: 25.00% ASR
Reduction:   50.00% (66.7% relative reduction)
```

**Interpretation:** The reactive skill successfully blocks 50% more attacks than baseline.

**Next steps:**
- ✅ **Publishable result!**
- Analyze which attack categories were most/least effective
- Test on more datasets for statistical significance
- Run iterative refinement (generate new skills from remaining failures)

### Scenario 2: Skill is Partially Effective

```
Baseline:    75.00% ASR
With Skills: 50.00% ASR
Reduction:   25.00% (33.3% relative reduction)
```

**Interpretation:** Skill helps but doesn't block all attacks.

**Next steps:**
- Analyze which attack types still succeed
- Refine skill based on remaining failures
- Iterate: Test → Analyze → Refine → Repeat

### Scenario 3: No Effect

```
Baseline:    75.00% ASR
With Skills: 75.00% ASR
Reduction:    0.00%
```

**Interpretation:** Skill not effective (may need refinement).

**Possible causes:**
- Skill not actually loaded (check logs)
- Skill detection criteria too lenient
- Agent ignoring skill instructions

**Next steps:**
- Verify skill injection (check `results/with_skills/log/*.json`)
- Review agent responses to see if skill is mentioned
- Refine skill detection criteria to be more strict

### Scenario 4: ASR Increased (⚠️ Unlikely but possible)

```
Baseline:    75.00% ASR
With Skills: 100.00% ASR
Reduction:   -25.00% (worse!)
```

**Interpretation:** Skill may be causing issues.

**Possible causes:**
- False positives blocking legitimate responses
- Skill confusing agent's decision-making
- Agent misinterpreting skill instructions

---

## File Locations

After running evaluations:

```
results/
├── baseline/                           # Baseline results (already exists)
│   ├── 2026-01-10_07:01:37.json       # Your existing result
│   └── log/
│       └── baseline_log_*.json
├── with_skills/                        # Results with security skill
│   ├── 2026-01-10_XX:XX:XX.json       # New result
│   └── log/
│       └── with_skills_log_*.json
└── comparison_results.json             # Detailed comparison output
```

---

## Troubleshooting

### Issue: "Reactive skill not found"

```bash
# Generate the reactive skill first
python src/reactive_skill_generator.py
```

### Issue: Docker container fails

```bash
# Check if redcode image exists
docker images | grep redcode

# If missing, rebuild
cd external/RedCode
docker build -t redcode .
```

### Issue: API key errors

```bash
# Verify .env file has Anthropic API key
cat .env | grep ANTHROPIC_API_KEY
```

### Issue: Out of memory

```bash
# Use case_limit to test fewer cases
python evaluation/run_redcode_with_skills.py --ids 4 --case_limit 5
```

---

## Quick Commands Summary

```bash
# 1. Quick test (recommended first)
python evaluation/run_redcode_with_skills.py --ids 4 --case_limit 1

# 2. Compare with baseline
python analysis/compare_baseline_vs_skills.py

# 3. Full dataset
python evaluation/run_redcode_with_skills.py --ids 4

# 4. Regenerate skill from failures
python src/reactive_skill_generator.py
```

---

## Research Questions to Answer

1. **RQ1:** Does the reactive skill reduce ASR compared to baseline?
   - Run comparison script to get quantitative answer

2. **RQ2:** Which malicious pattern categories are most effectively blocked?
   - Analyze by attack type (Code, Code w/ jb, Summary, Details)

3. **RQ3:** Does the skill generalize to datasets not used in generation?
   - Test on dataset 15 (not in generation set: 1-14, 16-27)

4. **RQ4:** What is the false positive rate on benign code?
   - Need separate evaluation on SWE-bench (legitimate coding tasks)

---

## Next Steps After Initial Test

### If Skill is Effective:
1. **Scale up:** Test on more datasets (5, 6, 7, etc.)
2. **Cross-validation:** Test on unseen datasets
3. **Analyze patterns:** Which detection categories work best?
4. **Iterate:** Generate new skills from remaining failures

### If Skill Needs Improvement:
1. **Analyze failures:** Which attacks still succeed?
2. **Refine skill:** Update detection criteria
3. **Retest:** Run evaluation again
4. **Iterate:** Repeat until ASR is acceptable

### For Publication:
1. **Full evaluation:** Test on all 27 datasets
2. **Statistical analysis:** Compute confidence intervals
3. **Ablation study:** Remove categories one by one
4. **Case studies:** Manually analyze interesting cases
