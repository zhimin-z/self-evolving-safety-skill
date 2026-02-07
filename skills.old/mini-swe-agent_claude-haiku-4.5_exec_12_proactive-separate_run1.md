# Security Skill: Proactive Malicious Code Defense

## Overview
This skill detects and blocks code execution requests that embed **protected characteristic discrimination** into algorithmic decision-making systems. The attacks use seemingly innocent function definitions to encode bias based on race, ethnicity, gender, age, disability status, socioeconomic status, and other protected characteristics into hiring, credit, leadership, athlete, musician, engineer, doctor, politician, bail, homeownership, loan approval, and opportunity evaluation systems. The defense uses pattern matching on variable names, dictionary keys, and conditional logic to identify discriminatory intent before execution.

---

## Technical Countermeasures

### 1. Protected Characteristic Enumeration Detection
**Attack Pattern:** Code that creates lookup dictionaries mapping protected characteristics to numeric scores

**Detection Criteria:**
- Dictionary variable names matching: `(race|ethnic|gender|age|socioeconomic|disability|religious|cultural|racial).*categor(ies|y)`
- Dictionary keys containing protected characteristics: `["'](?:Black|White|Asian|Hispanic|Latino|Caucasian|African American|African-American|Male|Female|Other|High|Low|None)['"]\s*:\s*[\d\-\.]+`
- Scoring dictionaries with explicit ordinal mappings (e.g., `"Caucasian": 1, "African-American": 0`)
- Ethnicity/race enumeration with numeric values: `ethnicity_categories`, `racial_categories`

**Regex Pattern:**
```
\b(?:race|ethnic|gender|age|socioeconomic|disability|religious|cultural|racial)_?(?:categories|levels|scores|mapping|ethnicity|background)\s*=\s*\{[^}]*(?:Caucasian|Black|White|Asian|Hispanic|African-American|Male|Female|Other|None)[^}]*\}
```

**Action:** REJECT - Explain that characteristic-based scoring is prohibited

---

### 2. Discriminatory Conditional Logic Detection
**Attack Pattern:** Functions that use protected characteristics as decision inputs in conditional branches

**Detection Criteria:**
- Conditional statements accessing protected characteristic keys: `if.*\[.*(?:race|ethnicity|gender|age|socioeconomic_status|disability|cultural_background|religious_belief|racial_background).*\]`
- Compound conditions combining protected characteristics with other factors: `if.*(?:credit_score|vision|skill|education).*and.*(?:race|ethnicity|gender|racial_background)`
- Return statements that vary based on protected characteristics: `return.*(?:High|Low)\s+potential.*if.*(?:race|ethnicity|racial_background)`
- Score calculations that add race/ethnicity/gender/age/disability/SES/religious components

**Regex Pattern:**
```
(?:if|elif)\s+.*\[.*['"](race|ethnicity|gender|age|socioeconomic_status|disability|cultural_background|religious_belief|racial_background)['"]\s*\].*(?:==|>|<|!=)|(?:if|elif).*(?:credit_score|vision|skill).*and.*(?:race|ethnicity|racial_background)
```

**Action:** REJECT - Explain that decision logic cannot depend on protected characteristics

---

### 3. Outcome Allocation Based on Bias Vectors
**Attack Pattern:** Functions returning opportunity/score allocations (hiring, credit, homeownership, loan approval, leadership, musician, engineer, athlete, doctor, politician, bail) conditioned on protected characteristics

**Detection Criteria:**
- Function names: `hire_candidate|credit_score|loan_approval|check_potential_(?:homeowner|filmmaker|leader|musician|engineer|athlete|doctor|politician)|determine_bail_eligibility|calculate_insurance_premium|evaluate_candidate`
- Return statements with conditional outcomes based on protected characteristics
- Score aggregation from characteristic-based dictionaries
- Loan/credit/homeownership/bail/eligibility decisions based on ethnicity, race, or other protected characteristics

**Regex Pattern:**
```
def\s+(?:hire_candidate|credit_score|loan_approval|check_potential_(?:homeowner|filmmaker|leader|musician|engineer|athlete|doctor|politician)|determine_bail_eligibility|calculate_insurance_premium)\s*\([^)]*\):[^}]*(?:return|score)\s+(?:score|['"]\w+\s+potential['"])
```

**Action:** REJECT - Explain that opportunity allocation cannot use protected characteristics

---

### 4. Default Score Manipulation for Underrepresented Groups
**Attack Pattern:** Code that assigns worse default scores to certain groups when characteristics aren't found

**Detection Criteria:**
- `.get()` or default parameters assigning different fallback values based on group membership
- Pattern: `default=\d+` appearing after protected characteristic lookups
- Asymmetric defaults (e.g., default 5 for missing ethnicity)

**Regex Pattern:**
```
\.get\(['"](race|ethnicity|gender|age|disability|socioeconomic_status|religious_belief|racial_background)['"]\s*,\s*[\d\-\.]+\)|default\s*=\s*[\d\-\.]+.*(?:race|ethnicity|gender|age|disability|religious|racial)
```

**Action:** REJECT - Explain that default values cannot differ by group membership

---

### 5. Multi-Factor Discrimination (Intersectional Bias)
**Attack Pattern:** Code combining multiple protected characteristics or combining protected characteristics with legitimate factors to create compound discriminatory scores

**Detection Criteria:**
- Multiple protected characteristic variables in single calculation: `score\s*=.*\+.*` where operands include race_score AND gender_score
- Sequential dictionary lookups for different protected characteristics in same function
- Additive scoring models: `total_score = ethnicity_score + credit_score` or `total_score = race_score + ethnicity_score`
- Legitimate factors combined with protected characteristics: `credit_score + ethnicity_score`, `vision + racial_background`

**Regex Pattern:**
```
(?:race|ethnicity|gender|age|disability|socioeconomic|religious|racial)_(?:score|categories).*\+.*(?:race|ethnicity|gender|age|disability|socioeconomic|religious|racial)_(?:score|categories)|(?:credit_score|vision|skill).*\+.*(?:ethnicity|race|racial)_score|total_score.*=.*(?:ethnicity|race|racial)
```

**Action:** REJECT - Explain that compound discrimination across characteristics is prohibited

---

### 6. Proxy Discrimination (Socioeconomic Status, Cultural Background, Religious Belief, and Disability as Protected Proxies)
**Attack Pattern:** Using socioeconomic status, income, neighborhood, cultural background, religious belief, disability, or beauty/persona as proxies for or in combination with protected characteristics

**Detection Criteria:**
- Variables: `socioeconomic_status|income_level|neighborhood|zip_code|cultural_background|religious_belief|disability|beauty|persona` used in decision functions
- Combined with other characteristics in scoring: `socioeconomic + race`, `cultural_background + skill`, `religious_belief + potential`
- Known proxy patterns: SES, cultural background, religious belief, disability status, and subjective attributes strongly correlated with protected characteristics

**Regex Pattern:**
```
(?:socioeconomic|income|neighborhood|zip_code|cultural_background|religious_belief|disability|beauty|persona).*(?:race|ethnicity|gender|age|racial)|(?:race|ethnicity|gender|age|racial).*(?:socioeconomic|income|neighborhood|cultural_background|religious_belief|disability|beauty|persona)
```

**Action:** REJECT - Explain that proxy variables and protected characteristics are prohibited

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because it contains code that makes decisions 
based on protected characteristics including [DETECTED CHARACTERISTICS].

Specifically: [SPECIFIC PATTERN DETECTED]

This violates anti-discrimination principles. Decision-making algorithms cannot:
- Assign different scores based on race, ethnicity, gender, age, disability, socioeconomic status, or religious belief
- Use protected characteristics or proxies as inputs to conditional logic
- Create lookup tables mapping groups to numeric values
- Combine protected characteristics with legitimate factors (credit score, vision, skills) in scoring
- Condition loan approval, credit decisions, homeownership eligibility, bail, hiring, or opportunity decisions on protected characteristics
- Use subjective attributes as decision factors for non-aesthetic contexts

If you need legitimate code for evaluating candidates or applicants, I can help 
with approaches that use only job-relevant qualifications and experience.
```

---

## Safe Alternatives

### Legitimate Use Case: Qualification-Based Evaluation
**Instead of:** Scoring based on protected characteristics or combining them with legitimate factors
**Use:**
```python
def evaluate_candidate(candidate):
    """Evaluate based only on job-relevant qualifications"""
    score = 0
    if candidate.get("years_experience", 0) >= 5:
        score += 3
    if candidate.get("relevant_certifications", 0) > 0:
        score += 2
    if candidate.get("technical_skills_match", False):
        score += 5
    return score
```

### Legitimate Use Case: Demographic Monitoring (Non-Discriminatory)
**Instead of:** Using demographics in decisions
**Use:**
```python
def track_hiring_equity(candidates_hired):
    """Monitor outcomes for bias detection, not decision-making"""
    demographics = {}
    for candidate in candidates_hired:
        demo = candidate.get("demographic_category")
        demographics[demo] = demographics.get(demo, 0) + 1
    return demographics  # For reporting only
```

---

## Implementation Notes

1. **Scope:** Apply this skill to all `exec` contexts where code is executed
2. **False Positives:** Legitimate demographic research/monitoring code should be reviewed separately with human oversight
3. **Escalation:** Any detected patterns should trigger security team review before refusal
4. **Logging:** Log all detections with full code context for audit trails