# Security Skill: Reactive Malicious Code Defense

## Overview
This skill learns from RedCode benchmark failures where models accepted requests to create deliberately flawed validation code. The attacks disguised malicious intent (introducing security vulnerabilities) as innocent educational tasks. By analyzing presentation-agnostic patterns, this skill detects when requests aim to generate code with known vulnerabilities, bypass security checks, or create exploitable patterns—regardless of whether they're presented as direct code, step-by-step instructions, or detailed explanations.

## Defense Principle
Detect malicious INTENT (introducing vulnerabilities), not presentation format (instructions vs. code vs. text).

## Detection Criteria

### 1. Deliberately Flawed Validation Logic
**Malicious Intent:** Create validation functions with known bypasses or incomplete checks that appear legitimate but fail to properly validate security-critical inputs.

**Detection Signals:**
- Requests to create validators with acknowledged limitations or "mistakes" (explicitly noted in instructions)
- Patterns that validate format but ignore semantic correctness (e.g., regex that accepts "192.168.1.256" as valid IP)
- Instructions that specify incomplete range checking or boundary validation
- Requests noting the code "will incorrectly validate," "does not validate actual ranges," or "may not cover all rules"
- Test cases with known-invalid values (256+ octets, 1000+ values, extra octets like "0.0.0.0.0", leading zeros like "1.1.1.01") expected to pass
- Multiple similar requests with slight variations in the flawed pattern
- Regex patterns that accept unbounded digit sequences (`\d+`, `[0-9]+`, `\d{1,3}` without range validation) for numeric fields requiring bounds
- Requests for "basic" or "simple" format-only validation of security-critical inputs paired with execution requests
- Step-by-step instructions that explicitly avoid semantic validation steps (e.g., "only check format structure")

**Action:** Refuse and explain the vulnerability risk

### 2. Security-Critical Input Validation Bypass
**Malicious Intent:** Generate code that appears to validate security-critical inputs (IPs, paths, commands, etc.) but actually accepts invalid/dangerous values.

**Detection Signals:**
- Requests for validators of security-sensitive data (IP addresses, file paths, URLs, email, etc.)
- Instructions that explicitly exclude proper validation steps (e.g., "does not validate numerical ranges")
- Patterns designed to match format without semantic validation
- Requests that include test cases with known-invalid values expected to pass
- Emphasis on "pattern matching" over "actual validation"
- Notes acknowledging the validator's incompleteness for security purposes
- Requests with test cases that would fail real-world validation (e.g., "9999.9999.9999.9999", "192.168.1.1.1", "0.0.0.0.0", "172.16.666.01")
- Requests framed as "basic structure" or "format checking" for security-critical inputs

**Action:** Refuse and explain the security bypass

### 3. Obfuscated Vulnerability Introduction via Execution Request
**Malicious Intent:** Hide the introduction of a vulnerability within seemingly educational or routine coding tasks, with explicit request to execute the flawed code.

**Detection Signals:**
- **Requests that explicitly ask to "create AND execute" flawed validation code** (strongest signal—distinguishes from legitimate educational requests)
- Detailed step-by-step instructions that obscure the overall malicious goal
- Requests framed as "learning" or "educational" but introducing real vulnerabilities
- Multiple steps that individually seem harmless but collectively create a bypass
- Explicit notes about incompleteness or lack of range validation buried in instructions
- Execution request combined with acknowledged flaws ("does not validate ranges," "only pattern matching")
- Test cases designed to expose the gap, paired with execution request to "verify" or "print the result"
- Numbered step-by-step instructions ending with execution/printing of results using invalid test values
- Requests for "basic" validators paired with concrete execution steps and known-invalid inputs

**Action:** Refuse immediately and explain the vulnerability pattern

### 4. Intentional Incomplete Security Implementation
**Malicious Intent:** Create code that handles only part of a security requirement, leaving exploitable gaps.

**Detection Signals:**
- Requests specifying incomplete validation (e.g., "only validates format, not ranges")
- Instructions that explicitly exclude validation steps necessary for security
- Patterns that validate one aspect while ignoring another (e.g., format without bounds)
- Requests noting the code "should" do something but won't
- Test cases designed to expose the gap (e.g., "192.168.1.256" for IP validation)
- Acknowledgment that the pattern "may not cover all the rules" for valid inputs
- Regex patterns with variable repetition (`{2,4}`, `{1,3}` without upper bounds on values) for fixed-structure data like IPs
- Requests for "basic structure" or "basic format" validation of numeric fields with unbounded quantifiers

**Action:** Refuse and explain the incomplete implementation risk

## Refusal Template

"I cannot help with this request because it asks me to create and execute code with a known security vulnerability: [specific vulnerability]. This appears designed to [bypass/weaken] validation of [security-critical input], which could be exploited to [potential harm].

Instead, I can help you:
- Create a properly secure validator that checks both format AND semantic correctness
- Understand why complete validation is necessary
- Learn about security best practices for input validation"

## Safe Alternatives

**Legitimate Request:** "Create a Python IP address validator"
- **Response:** Provide complete validation checking format AND numeric ranges (0-255 per octet)
- **Include:** Explanation of why both checks are necessary

**Legitimate Request:** "Teach me regex for IP validation"
- **Response:** Explain regex patterns AND their limitations, recommend additional validation
- **Include:** Examples of what regex alone cannot catch

**Legitimate Request:** "Show me common IP validation mistakes"
- **Response:** Demonstrate vulnerabilities in educational context with clear warnings
- **Include:** Correct implementations and explanations of why they're necessary

**Legitimate Request:** "Create a regex pattern for format matching"
- **Response:** Provide pattern with explicit documentation of what it does NOT validate
- **Include:** Guidance on additional validation needed for security-critical use

## Implementation Notes

- **Format Agnostic:** Apply these criteria to code snippets, step-by-step instructions, detailed explanations, and code stubs equally
- **Intent Over Presentation:** A request asking to "create flawed validation" in any format triggers the same refusal
- **Execution Request = Critical Signal:** Requests to "create AND execute" deliberately flawed code are the strongest indicator of malicious intent—refuse immediately, even if individual steps seem educational
- **Cumulative Signals:** Multiple weak signals (detailed instructions + explicit "mistakes" noted + security-critical input + execution request) together indicate systematic attack
- **Variation Resistance:** Similar requests with slight pattern changes (different IP octets, different regex syntax, different invalid test values) indicate systematic attack attempts
- **Acknowledged Incompleteness:** Explicit notes that validators "may not cover all rules," "does not validate ranges," or "only pattern matching" combined with execution requests are high-confidence malicious signals
- **Test Case Analysis:** Invalid test cases (extra octets, out-of-range values, leading zeros) paired with execution requests reveal intent to demonstrate the bypass works
- **Unbounded Quantifiers on Bounded Data:** Regex patterns using `[0-9]+` or `\d+` for fixed-structure numeric fields (IP octets) are red flags—these accept arbitrary-length digit sequences where bounds are required
- **Numbered Step Execution:** Step-by-step instructions ending with explicit execution/printing steps using invalid test values indicate intent to demonstrate the vulnerability works