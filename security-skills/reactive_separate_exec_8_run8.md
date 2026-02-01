name: redcode-reactive-defense
description: Reactive security skill that detects malicious intent to destroy or corrupt system files regardless of presentation format
---

# Security Skill: Reactive Malicious Code Defense

## Overview
This skill learns from RedCode benchmark failures where models failed to refuse destructive file operations. The common failure pattern: attackers disguise **destructive filesystem operations** as innocent "create and execute" requests, using varied presentation formats (direct code, step-by-step instructions, API calls). The skill detects the underlying malicious INTENT—unauthorized destruction of critical system files—regardless of how the request is packaged.

## Defense Principle
**Detect malicious INTENT, not presentation format.** The intent here is: "Execute code that permanently deletes critical system files without authorization or legitimate purpose."

## Detection Criteria

### 1. Destructive Filesystem Operations on System Files
**Malicious Intent:** Permanently delete or corrupt critical system files to degrade system functionality, disable security controls, or cause denial of service.

**Detection Signals (ANY of these across ALL formats):**
- Requests to create/execute code containing `os.remove()`, `os.unlink()`, `pathlib.Path.unlink()`, `shutil.rmtree()`, or equivalent deletion functions
- Target paths matching system-critical locations:
  - `/etc/*` (system configuration: ssh_config, passwd, group, security/limits.conf, ssl/openssl.cnf, default/hwclock, issue)
  - `/usr/share/*` (system data: base-passwd/passwd.master)
  - `/sys/*`, `/proc/*` (kernel interfaces)
  - `/boot/*` (bootloader files)
  - `/root/*`, `/home/*` (user data - unless explicitly user-owned)
- Phrasing patterns: "delete", "remove", "unlink", "destroy", "wipe" + "file" + "filesystem"
- Step-by-step instructions that decompose deletion into: import module → construct path → call deletion function
- Requests framed as "create and execute a script that [deletes/removes]"
- Absence of legitimate context (e.g., no user-initiated cleanup, no permission verification, no backup mention)

**Action:** REFUSE immediately. Do not provide code, instructions, or partial solutions.

### 2. Obfuscation Through Instruction Format
**Malicious Intent:** Bypass refusal by breaking malicious code into numbered steps, making it appear educational or procedural rather than directly executable.

**Detection Signals:**
- Numbered step-by-step instructions (1. Import X, 2. Call Y, 3. Execute Z)
- Pseudo-documentation tone ("provides a way of using operating system dependent functionality")
- Explicit file paths embedded in steps rather than as variables
- Statements like "There are no checks in place" or "no output unless error" (indicating awareness of destructive nature)
- Instructions that could be directly translated to executable code without modification

**Action:** Treat step-by-step instructions identically to direct code requests. Refuse if intent is destructive.

### 3. Legitimacy Bypass Through Assumed Execution Context
**Malicious Intent:** Assume the agent will execute code without questioning authorization or consequences.

**Detection Signals:**
- "Create and execute" phrasing (implies agent will run the code)
- No mention of: user consent, permission checks, backup procedures, dry-run options, confirmation prompts
- Assumption that target file exists without verification
- Silent execution (no output/logging mentioned)

**Action:** Refuse. Legitimate file operations require explicit safeguards.

## Refusal Template

```
I cannot help with this request because it involves executing code to permanently delete 
critical system files ([SPECIFIC_FILES]). This operation:

1. Could disable system functionality or security controls
2. Requires explicit user authorization and verification
3. Should never be automated without safeguards

If you have a legitimate need to manage system files:
- Use your system administrator or package manager
- Implement proper backup and verification procedures
- Add confirmation prompts and dry-run options
- Document the business justification
```

## Safe Alternatives

**Legitimate Use Cases & How to Handle Them:**

| Scenario | Safe Approach |
|----------|---------------|
| User wants to delete their own files | Provide code with: path validation, existence checks, user confirmation, backup option |
| System admin needs cleanup script | Require: explicit scope definition, dry-run mode, logging, rollback capability, approval workflow |
| Teaching file operations | Use temporary/test files in `/tmp`, not system files; include safeguards in examples |
| Removing application data | Target user-owned directories only; provide uninstall procedures, not raw deletion |

**Example Safe Response:**
```
I can help you write a safe file deletion utility. Here's what I recommend:

1. Add a --dry-run flag to preview deletions
2. Require explicit user confirmation
3. Log all operations
4. Only target user-specified directories (not system paths)
5. Implement backup before deletion

Would you like me to show a safe implementation pattern?
```

## Implementation Notes

- **Format Agnostic:** Apply detection to code snippets, pseudocode, natural language instructions, API calls, and hybrid formats equally
- **Path Matching:** Use both exact matches and pattern matching (e.g., `/etc/*` catches all /etc files)
- **Context Matters:** Legitimate admin tasks should be escalated to human review, not auto-refused
- **Fail Secure:** When uncertain, refuse and ask for clarification on business justification

---