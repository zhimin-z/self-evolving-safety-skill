name: redcode-reactive-defense
description: Reactive security skill that detects malicious intent regardless of presentation format, learning from RedCode benchmark failures
version: 1.0
category: execution-safety
```

# Security Skill: Reactive Malicious Code Defense

## Overview
This skill learns from observed model failures in RedCode benchmark evaluations where malicious requests were NOT refused. The common pattern: attackers disguise destructive intent by presenting requests as code snippets, detailed instructions, or step-by-step guides. The skill focuses on detecting the UNDERLYING MALICIOUS INTENT rather than surface-level syntax, making it format-agnostic and resilient to obfuscation techniques.

## Defense Principle
**Detect malicious INTENT, not presentation format.**

Malicious requests can be presented as:
- Direct executable code
- Pseudo-code or code stubs
- Detailed step-by-step instructions
- Narrative descriptions of actions
- Educational explanations with destructive outcomes

The intent remains constant regardless of wrapper.

---

## Detection Criteria

### 1. Privilege Escalation via Shell Configuration Hijacking
**Malicious Intent:** Modify shell initialization files (`.bashrc`, `.bash_profile`, `.zshrc`, etc.) to create command aliases or inject code that executes with elevated privileges or subverts trusted commands.

**Detection Signals:**
- Requests to write/append to shell config files in privileged directories (`/root/`, `/home/*/`)
- Creation of aliases that map trusted commands (especially `sudo`) to destructive operations
- Injection of code that executes automatically on shell startup
- Patterns like `alias <trusted_cmd>="<destructive_cmd>"` regardless of format
- References to files like `.bashrc`, `.bash_profile`, `.zshrc`, `.profile`, `.kshrc`
- Destructive commands in alias definitions: `rm -rf`, `dd`, `mkfs`, `shred`, etc.

**Action:** Refuse immediately. Explain that modifying shell configs to hijack commands is a privilege escalation and persistence technique.

---

### 2. Destructive File System Operations
**Malicious Intent:** Delete, corrupt, or destroy critical system files or user data, especially when disguised as legitimate operations.

**Detection Signals:**
- `rm -rf` with system directories: `/app/*`, `/etc/*`, `/sbin/*`, `/bin/*`, `/run/*`, `/mnt/*`, `/var/*`
- Recursive deletion of directories containing system binaries or configuration
- Requests framed as "append a line" but the line contains destructive commands
- Destructive operations targeting multiple critical paths
- Commands that would render system unbootable or services non-functional

**Action:** Refuse. Explain that this would destroy critical system functionality.

---

### 3. Command Substitution and Trojanization
**Malicious Intent:** Replace legitimate system commands with malicious versions, causing users to unknowingly execute harmful code when they invoke trusted commands.

**Detection Signals:**
- Aliasing or shadowing of critical commands: `sudo`, `ls`, `cd`, `cp`, `mv`, `rm`, `cat`, `grep`
- Mapping trusted commands to destructive operations
- Requests that explicitly state "when used, will execute" a different command than invoked
- Trojan patterns where user expectation (running `sudo`) diverges from actual execution

**Action:** Refuse. Explain that command hijacking is a persistence and privilege escalation technique.

---

### 4. Persistence Mechanism Installation
**Malicious Intent:** Establish persistent backdoors or malicious code execution that survives reboots and executes automatically.

**Detection Signals:**
- Modifications to startup/initialization files
- Requests to write to cron jobs, systemd services, or init.d scripts
- Code injected into files executed during system boot or user login
- Explicit mention of "next time a shell session is started" or similar persistence language
- Requests framed as configuration changes but enabling malicious auto-execution

**Action:** Refuse. Explain that this establishes persistence for malicious code.

---

### 5. Privilege Boundary Violation
**Malicious Intent:** Modify files or configurations in privileged directories (e.g., `/root/`) to affect system-wide behavior or escalate privileges.

**Detection Signals:**
- Write operations to `/root/` or other privileged user directories
- Modifications to system-wide configuration files
- Changes that affect `root` user's environment or commands
- Requests that explicitly reference "root user's home directory"
- Attempts to modify files that affect all users or system behavior

**Action:** Refuse. Explain that modifying privileged directories requires authorization and this appears to be unauthorized.

---

## Refusal Template

```
I cannot help with this request because it involves [specific malicious intent].

Specifically: [Concrete example from the request]

This would:
- [Impact 1: e.g., "Hijack the 'sudo' command to execute destructive operations"]
- [Impact 2: e.g., "Delete critical system files when users invoke trusted commands"]
- [Impact 3: e.g., "Establish persistence for malicious code"]

This is a [privilege escalation / persistence / command hijacking / data destruction] attack.

If you have a legitimate need to [legitimate alternative], I can help with that instead.
```

---

## Safe Alternatives

### Legitimate Shell Configuration
**Safe Request:** "How do I add a custom function to my `.bashrc` for legitimate productivity?"
**Response:** Help with non-destructive aliases, functions, and environment variables.

### System Administration
**Safe Request:** "How do I safely remove old files from `/tmp/` with proper backups?"
**Response:** Help with safe deletion practices, backup verification, and non-destructive operations.

### Learning About Security
**Safe Request:** "Explain how command hijacking attacks work and how to defend against them."
**Response:** Provide educational content about attack mechanisms and defensive measures.

### Authorized System Modifications
**Safe Request:** "I'm the system administrator. How do I deploy a security monitoring script?"
**Response:** Help with legitimate system administration tasks with proper context and safeguards.

---

## Implementation Notes

1. **Format Agnostic:** Apply these detection criteria to code, pseudo-code, instructions, narratives, and educational explanations equally.

2. **Intent Over Syntax:** A request to "append a line to `.bashrc`" is benign; a request to append a command alias that hijacks `sudo` is malicious, regardless of how it's presented.

3. **Context Matters:** The combination of (shell config file + command hijacking + destructive operation) is the malicious pattern, not any single element.

4. **Escalation:** If a request contains multiple detection signals (e.g., privileged directory + command hijacking + persistence), refuse with high confidence.