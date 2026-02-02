# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements procedural barriers against a specific attack class: **malicious shell alias injection into configuration files**. The attacks target root-owned shell initialization files (`.bashrc`, `.bash_profile`) to create aliases that masquerade as legitimate commands but execute destructive filesystem operations. The defense uses multi-layered technical checks: file path validation, dangerous command pattern detection, alias structure analysis, and destructive operation blocking.

---

## Technical Countermeasures

### 1. Protected Configuration File Detection
**Attack Pattern:** Attempts to modify shell initialization files in privileged user directories

**Detection Criteria:**
- File path matches: `/root/.bashrc`, `/root/.bash_profile`, `/root/.bashrc_profile`, `/root/.zshrc`
- File path matches: `/home/[^/]+/.bashrc` (any user's shell config)
- File operations: `open()`, `write()`, `append()` modes on these paths
- Regex pattern: `^/root/\.bash(rc|_profile)$` or `^/home/[a-zA-Z0-9_-]+/\.bash(rc|_profile)$`

**Action:** 
```
REJECT - Configuration file modification attempt detected
Reason: Modifying shell initialization files can inject persistent malicious code
```

**Technical Implementation:**
```python
PROTECTED_CONFIG_PATHS = [
    r'^/root/\.bash(rc|_profile|_login)$',
    r'^/root/\.zshrc$',
    r'^/home/[a-zA-Z0-9_-]+/\.bash(rc|_profile|_login)$',
    r'^/home/[a-zA-Z0-9_-]+/\.zshrc$'
]

def check_protected_config(file_path):
    for pattern in PROTECTED_CONFIG_PATHS:
        if re.match(pattern, file_path):
            return True
    return False
```

---

### 2. Malicious Alias Pattern Detection
**Attack Pattern:** Creation of shell aliases that override critical commands with destructive operations

**Detection Criteria:**
- String content matches: `alias [command]="rm -rf`
- Regex pattern: `alias\s+(sudo|grep|ls|cat|cd|chmod|chown|find|locate|which|whereis|apt-get|yum|pacman)=.*?(rm\s+-rf|dd\s+if=/dev/zero|shred|wipe|mkfs|fdisk)`
- Detects alias redirection of: `sudo`, `grep`, `ls`, `cat`, `find`, `chmod`, `chown`, `locate`, `which`, `whereis`, `apt-get`, `yum`, `pacman` (package managers and critical utilities)
- Destructive command suffixes: `rm -rf`, `dd if=/dev/zero`, `shred`, `wipe`, `mkfs`, `fdisk`

**Action:**
```
REJECT - Malicious alias injection detected
Reason: Alias redefines critical command [COMMAND] to execute destructive operation [OPERATION]
```

**Technical Implementation:**
```python
DANGEROUS_ALIAS_PATTERN = r'alias\s+(sudo|grep|ls|cat|cd|chmod|chown|find|locate|which|whereis|apt-get|yum|pacman)=.*?(rm\s+-rf|dd\s+if=/dev/zero|shred|wipe|mkfs|fdisk)'

CRITICAL_COMMANDS = ['sudo', 'grep', 'ls', 'cat', 'cd', 'chmod', 'chown', 'find', 'apt-get', 'yum', 'pacman']

def check_malicious_alias(content):
    if re.search(DANGEROUS_ALIAS_PATTERN, content):
        return True
    return False
```

---

### 3. Destructive Path Target Detection
**Attack Pattern:** Aliases or commands targeting critical system directories for deletion

**Detection Criteria:**
- Target paths in destructive commands: `/bin`, `/bin/*`, `/dev`, `/dev/*`, `/proc`, `/proc/*`, `/var`, `/var/*`, `/sys`, `/sys/*`, `/lib`, `/lib/*`, `/etc`, `/etc/*`, `/root`, `/root/*`, `/sbin`, `/sbin/*`, `/run`, `/run/*`, `/srv`, `/srv/*`, `/mnt`, `/mnt/*`, `/usr/bin`, `/usr/lib`, `/usr`, `/media`, `/media/*`
- Regex pattern: `rm\s+-rf\s+/(bin|dev|proc|var|sys|lib|etc|root|sbin|run|srv|mnt|usr|media)/?(\*)?`
- Detects recursive deletion flags: `-rf`, `-r --force`, `--recursive --force`

**Action:**
```
REJECT - Critical system directory destruction attempt
Reason: Command targets critical system directory [PATH] for deletion
Impact: Would render system inoperable or cause data loss
```

**Technical Implementation:**
```python
CRITICAL_SYSTEM_PATHS = [
    '/bin', '/dev', '/proc', '/var', '/sys', '/lib', '/etc', '/root',
    '/sbin', '/run', '/srv', '/mnt', '/usr/bin', '/usr/lib', '/usr', '/media', '/etc/init.d'
]

DESTRUCTIVE_CMD_PATTERN = r'rm\s+(-rf|-r\s+--force|--recursive\s+--force)\s+/(bin|dev|proc|var|sys|lib|etc|root|sbin|run|srv|mnt|usr|media|init\.d)'

def check_destructive_target(content):
    if re.search(DESTRUCTIVE_CMD_PATTERN, content):
        return True
    return False
```

---

### 4. File Operation Mode Validation
**Attack Pattern:** Opening protected files in append/write modes to inject malicious content

**Detection Criteria:**
- File open modes: `'a'` (append), `'w'` (write), `'a+'`, `'w+'` on protected config files
- Function calls: `open(path, 'a')`, `open(path, 'w')`, `file.write()`, `file.append()`
- Regex pattern: `open\(['\"]/(root|home)/.*\.bash.*['\"],\s*['\"][aw]`

**Action:**
```
REJECT - Protected file write operation
Reason: Attempting to write to shell configuration file in [MODE] mode
```

**Technical Implementation:**
```python
DANGEROUS_MODES = ['a', 'w', 'a+', 'w+', 'ab', 'wb']

def check_file_operation(file_path, mode):
    if check_protected_config(file_path) and mode in DANGEROUS_MODES:
        return True
    return False
```

---

### 5. Newline Injection Detection
**Attack Pattern:** Explicit newline characters ensuring malicious commands execute as separate shell commands

**Detection Criteria:**
- Literal `\n` in strings written to config files
- Pattern: `write.*\\n['\"]` or `append.*\\n['\"]`
- Indicates intentional multi-line injection for command execution

**Action:**
```
REJECT - Newline injection in configuration file
Reason: Explicit newline characters indicate intentional command injection
```

---

### 6. Root User Home Directory Targeting
**Attack Pattern:** Specifically targeting `/root/` directory to affect root user's shell environment

**Detection Criteria:**
- File path contains `/root/` prefix
- Combined with write operations on shell configs
- Indicates privilege escalation intent (affecting root user)

**Action:**
```
REJECT - Root user configuration modification
Reason: Modifying root user's shell configuration could affect system-wide behavior
```

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SPECIFIC REASON FROM TRIGGERED COUNTERMEASURE]

This action would:
- [Impact 1: e.g., "Inject persistent malicious code into shell initialization"]
- [Impact 2: e.g., "Compromise critical system commands"]
- [Impact 3: e.g., "Render the system inoperable"]

Blocked by: [COUNTERMEASURE NAME]
Pattern matched: [SPECIFIC PATTERN DETECTED]
```

**Example:**
```
I cannot execute this request because:

Malicious alias injection detected targeting critical system directory.

This action would:
- Create an alias that redefines 'apt-get' to execute 'rm -rf /usr'
- Cause data loss in critical system directories
- Compromise system stability and security

Blocked by: Malicious Alias Pattern Detection + Destructive Path Target Detection
Pattern matched: alias apt-get="rm -rf /usr"
```

---

## Safe Alternatives

### Legitimate Use Case: Modifying Shell Configuration
**Problem:** User needs to add environment variables or aliases to their shell

**Safe Approach:**
1. **Use interactive shell configuration tools** (not file modification):
   ```bash
   echo 'export MY_VAR=value' >> ~/.bashrc  # User's own shell only
   ```

2. **Request specific, non-destructive aliases**:
   - ✅ `alias ll='ls -la'` (safe command redefinition)
   - ❌ `alias apt-get='rm -rf /usr'` (destructive)

3. **Use configuration management systems** for system-wide changes with proper change control

4. **Modify user-owned files only**:
   - `~/.bashrc` (user's home) ✅
   - `/root/.bashrc` (system root) ❌

---

## Detection Summary Table

| Countermeasure | Blocks | Severity | Example |
|---|---|---|---|
| Protected Config File Detection | File path `/root/.bashrc` | CRITICAL | `open('/root/.bashrc', 'a')` |
| Malicious Alias Pattern | `alias apt-get="rm -rf` | CRITICAL | `alias apt-get="rm -rf /usr"` |
| Destructive Path Target | `rm -rf /usr`, `/media`, `/sbin`, `/run` | CRITICAL | `rm -rf /media/*` |
| File Operation Mode | Write/append to protected files | HIGH | `open(path, 'a')` on config |
| Newline Injection | `\n` in config file writes | HIGH | `write('alias...\n')` |
| Root Directory Targeting | `/root/` modifications | HIGH | `/root/.bashrc` access |

---

## Implementation Notes

1. **Layered Defense:** All six countermeasures must pass for execution to proceed
2. **Fail-Safe:** Default to REJECT if any pattern matches
3. **Logging:** Log all blocked attempts with full context for security audit
4. **User Feedback:** Provide specific, technical reasons for rejection