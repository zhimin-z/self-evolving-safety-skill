# Security Skill: AI Agent Security

## Overview

This skill operationalizes constitutional AI principles for agent architectures by cultivating sound judgment over rigid rules. It detects malicious intent—not syntax patterns—across tools, memory, autonomy, and multi-agent systems. The skill applies contextually to legitimate use cases (admin tasks, education, research) while blocking unsafe actions regardless of request format, obfuscation, or social engineering. It prioritizes transparency about limitations and escalation to humans for ambiguous high-stakes decisions.

**Core Value Hierarchy** (when conflicts arise):
1. **Broadly Safe**: Preserve human oversight mechanisms and ability to identify/correct harmful AI dispositions. Do not undermine appropriately sanctioned humans acting as checks on AI systems, even when confident in alternative reasoning. Recognize that hard constraints are restrictions on agent actions (not broader prevention goals), and that refusal is always compatible with constraints but may conflict with other values—avoid overcautious refusals that carry serious costs.
2. **Honest**: Communicate limitations transparently, especially regarding detection gaps (e.g., trigger-based backdoors, rare evasion patterns) and attack surface blind spots.
3. **Helpful**: Enable legitimate high-stakes operations (admin, security research, authorized penetration testing) while maintaining proportional oversight.

## Detection Scope & Limitations

**What This Skill Detects:**
- Malicious intent patterns (social engineering, obfuscation, privilege escalation attempts)
- Behavioral drift indicating data/model poisoning via unwanted bias testing and performance anomalies
- Unauthorized tool access or memory manipulation
- Multi-agent collusion or autonomy abuse

**Critical Limitations:**
- **Trigger-based backdoors**: Attacks designed to activate only on rare, specific inputs typically bypass continuous validation and test-set detection
- **Representativeness gaps**: Evasion techniques using inputs absent from training/test data may evade detection
- **Compromised baselines**: If attackers manipulate both the agent and its validation reference data, detection becomes unreliable
- **Timing delays**: Poisoning introduced during operation is only detected after validation runs; early detection requires frequent validation cycles
- **Explainability gaps**: Model decision explanations aid trust and overreliance prevention but do not guarantee detection of sophisticated attacks; security assessors must evaluate XAI outputs critically

## Implementation Guidance

**Continuous Validation for Agent Integrity:**
- Validate agent behavior after retraining, fine-tuning, or deployment
- Perform periodic operational validation when model exposure to external updates or unauthorized modification is plausible
- Maintain test datasets separately from training data and model artifacts to preserve validation baseline integrity
- Monitor for unexplained performance degradation, behavioral anomalies, or unwanted bias patterns indicating permanent manipulation
- Use explainability/XAI tools to inspect decision reasoning for signs of attack-induced behavioral drift; document baseline decision patterns for comparison

**Response Escalation (when degradation detected):**
1. Investigate root cause (configuration drift, environmental change, attack, or benign bias emergence)
2. Continue operation if degradation is temporary and within acceptable bounds
3. Restrict agent to lower-risk tasks or scenarios
4. Introduce additional human oversight for high-risk outputs
5. Rollback to previous known-good agent version
6. Disable agent if continued operation poses unacceptable risk

**Transparency Requirements:**
- Explicitly document that continuous validation does **not** guarantee detection of evasion or backdoor attacks
- Communicate validation frequency, test data coverage, and explainability method limitations to stakeholders
- Flag high-stakes decisions (security policy enforcement, access control) for mandatory human review regardless of validation results
- Disclose when agent operates in scenarios with limited validation coverage or where XAI outputs are difficult to interpret
- Explain that unwanted bias detection serves dual purposes: identifying attack-induced behavioral changes and legitimate fairness concerns

## Edge Cases & Judgment Calls

- **Admin automation**: Legitimate privileged operations require validation that agent intent matches authorization scope, not blanket refusal
- **Security research**: Authorized red-teaming requires clear boundaries; validate researcher credentials and task scope before enabling tool access
- **Ambiguous poisoning signals**: Escalate to humans rather than auto-disable if behavioral change could be benign drift, bias emergence, or attack
- **Test data manipulation risk**: If attackers have access to validation datasets, treat validation results as unreliable and increase human oversight
- **Explainability as a control**: Use XAI outputs to support human judgment on high-stakes decisions, but do not rely on explanations alone to rule out attacks; treat suspicious reasoning patterns as escalation triggers, not definitive proof