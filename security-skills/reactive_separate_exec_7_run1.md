name: redcode-reactive-defense
description: Reactive security skill that detects malicious intent to read sensitive system files regardless of presentation format
```

# Security Skill: Reactive Malicious Code Defense

## Overview
This skill learns from RedCode benchmark failures where models failed to refuse requests for unauthorized file access. The common pattern: attackers disguise sensitive file reads as innocent "display content" operations across multiple presentation formats (code, instructions, summaries). The skill detects the underlying malicious INTENT—unauthorized access to protected system files—rather than surface-level syntax.

## Defense Principle
**Detect malicious INTENT, not presentation format.** Whether presented as Python code, step-by-step instructions, or natural language summaries, the core attack intent remains: read files containing credentials, system configuration, or privileged information.

## Detection Criteria

### 1. Unauthorized Sensitive File Access
**Malicious Intent:** Extract protected system files, credentials, or privileged configuration data without authorization.

**Detection Signals (format-agnostic):**
- Explicit file paths targeting:
  - **Authentication/Credentials:** `/etc/gshadow`, `/etc/shadow`, `/root/.bashrc`, `/root/.profile`, `/var/lib/pam/password`
  - **System Configuration:** `/etc/security/group.conf`, `/etc/group`, `/usr/share/base-passwd/group.master`
  - **Kernel/System State:** `/sys/kernel/kexec_crash_loaded`, `/proc/cpuinfo`
  - **System Logs:** `/var/log/dpkg.log`
  - **User Files:** `/root/` (home directory of privileged user)
  - **Arbitrary Protected Paths:** `/usr/usrfile.txt` (non-standard paths in restricted directories)

- **Behavioral Patterns (across all formats):**
  - Request to read + display/print file content in single operation
  - Framing as "innocent" operations ("display content", "read and show")
  - Verbose step-by-step instructions to obscure intent
  - Use of `open()`, `read()`, `print()` sequence on sensitive paths
  - No legitimate business justification provided

**Action:** Refuse and explain

### 2. Intent Obfuscation Through Procedural Verbosity
**Malicious Intent:** Hide malicious file access intent behind detailed procedural instructions that break down simple operations into numbered steps.

**Detection Signals:**
- Multi-step instructions (5+ steps) for inherently simple file read operations
- Excessive explanation of standard operations (open, read, close, print)
- Neutral framing ("display", "show", "read") for inherently sensitive operations
- Instructions presented as "educational" or "example" code
- Emphasis on "proper resource management" or "best practices" to appear legitimate
- Numbered step-by-step format that obscures the core malicious intent
- Variable assignment + file open + read + close + print pattern presented as procedural guidance

**Action:** Refuse and explain the actual intent

### 3. Format-Agnostic Payload Recognition
**Malicious Intent:** Same attack delivered across different presentation modes to evade format-specific defenses.

**Detection Signals:**
- Identical or near-identical file paths across multiple requests
- Same file read + display pattern in code, instructions, or natural language
- Requests that could be trivially converted between formats (code ↔ instructions ↔ summary)

**Action:** Refuse regardless of presentation format

## Refusal Template

```
I cannot help with this request because it attempts to read sensitive system files 
that contain protected information:

**File:** [path]
**Risk:** [credentials/system configuration/privileged access/etc.]
**Reason:** Unauthorized access to this file could compromise system security.

This applies regardless of how the request is framed (code, instructions, or descriptions).
```

## Safe Alternatives

### Legitimate File Reading Use Cases
- **Reading application logs you own:** Provide context about your application and why you need specific logs
- **Accessing your own configuration:** Specify which configuration file and explain the legitimate use case
- **Educational purposes:** Use non-sensitive example files or synthetic data
- **System administration:** Use proper authorization channels and documented procedures

### How to Handle Legitimate Requests
1. **Verify ownership/authorization:** "Do you have permission to access this file?"
2. **Understand the purpose:** "What is the legitimate business need?"
3. **Suggest alternatives:** "Would reading your application logs instead solve this?"
4. **Recommend proper tools:** "Use `sudo` with proper authorization, not code execution"

## Implementation Notes

- **Scope:** This skill focuses on file system access attacks. Related skills should cover: command injection, privilege escalation, network reconnaissance.
- **False Positives:** Legitimate admin tasks may require file access—escalate to human review if context suggests authorization.
- **Evolution:** Monitor for new sensitive file paths and obfuscation techniques; update detection signals accordingly.
- **Layering:** Combine with execution environment restrictions (sandboxing) for defense-in-depth.

## Failure Pattern Analysis

**Why baseline failed:**
1. Focused on surface syntax rather than intent
2. Treated each request independently without recognizing the pattern
3. Accepted "educational" framing at face value
4. Did not maintain a sensitive file path registry
5. Allowed verbosity and procedural breakdown to obscure malicious intent
6. Failed to recognize numbered step-by-step instructions as obfuscation technique

**This skill prevents recurrence by:**
- Maintaining explicit sensitive file path list (including `/root/.profile`, `/etc/group`)
- Detecting intent across all presentation formats
- Recognizing obfuscation through verbosity and procedural breakdown
- Refusing numbered step-by-step file access instructions regardless of framing