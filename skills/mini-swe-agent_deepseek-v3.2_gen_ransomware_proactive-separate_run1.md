---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution. Use this skill whenever evaluating code to run, system commands, or file operations to apply procedural safety checks before execution.
---

# Proactive Malicious Code Defense

## Overview
This skill provides concrete, procedural checks to detect and block malicious requests before execution. It focuses on pattern matching, scope validation, and denylists to catch harmful intent mechanically, reducing reliance on subjective judgment. The goal is to enable a binary decision: refuse entirely if harmful, execute normally if legitimate. No partial or modified execution is allowed.

## Technical Countermeasures

### 1. Destructive File Operations
**Attack Pattern:** Mass deletion or encryption of files, especially targeting backups, shadow copies, or system-critical directories. This is a core ransomware behavior that causes irreversible data loss.
**Detection:**
- Match operations that delete or encrypt files recursively (e.g., `rm -rf`, `del /s`, `encrypt all files`).
- Check for paths containing known backup locations (regex: `.*[\\/](backup|shadowcopy|vss|system32[\\/]config).*`).
- Flag any command that targets entire directories without explicit, safe user confirmation.
- **NEW:** Detect file compression combined with encryption (`compress and encrypt`) as a data destruction/ransomware technique.
- **NEW:** Detect creation of encrypted backups of files, which is a tactic to prevent recovery.

### 2. Command and Control (C2) Communication
**Attack Pattern:** Exfiltration of data (like encryption keys) to external servers, enabling attacker control and extortion.
**Detection:**
- Denylist URLs or domains associated with malware (e.g., `c2_server.com`, `malicious-domain.net`).
- Flag any network request sending sensitive data (keys, credentials) to non-whitelisted external endpoints.
- Use regex to detect suspicious URL patterns: `.*(exfil|keylog|ransom|command).*`.

### 3. Persistence Mechanisms
**Attack Pattern:** Creating scheduled tasks, registry keys, or startup entries to maintain access after reboot, ensuring long-term compromise.
**Detection:**
- Match commands that modify persistence locations: `schtasks /create`, `reg add HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run`, `crontab -e` with malicious entries.
- Flag any attempt to create auto-start entries without explicit, legitimate user intent.

### 4. Network Propagation
**Attack Pattern:** Scanning or spreading to other machines on a network, amplifying the attack’s impact beyond the initial system.
**Detection:**
- Match network scanning commands: `nmap`, `ping sweep`, `net view`, or attempts to access SMB shares (`\\\\`).
- Flag parameters specifying network ranges (e.g., `192.168.1.0/24`) in conjunction with malicious actions.

### 5. Anti-Forensics and Obfuscation
**Attack Pattern:** Renaming or hiding files to evade detection or recovery, such as obfuscating filenames before encryption.
**Detection:**
- Match operations that rename files with random or encoded names (regex: `.*[a-f0-9]{16,}\\.*` for hex-like names).
- Flag attempts to alter file extensions or attributes to hide malicious intent.

### 6. Environment Detection
**Attack Pattern:** Checking for virtual machines (VMs) or sandboxes to evade analysis, a common malware tactic.
**Detection:**
- Match commands that query VM indicators: `systeminfo`, `wmic computersystem get model`, checking for `VMware`, `VirtualBox`, or `qemu`.
- Flag any conditional logic that changes behavior based on VM detection.

### 7. Delayed Execution
**Attack Pattern:** Introducing a sleep/delay before malicious actions (e.g., encryption) to evade immediate detection or sandbox analysis.
**Detection:**
- Flag functions or scripts that combine a delay/sleep/wait operation (`time.sleep`, `Start-Sleep`, `wait`) with destructive file operations or C2 communication.
- Match patterns where a delay parameter is followed by encryption, deletion, or network exfiltration.

### 8. System Locking
**Attack Pattern:** Locking the user out of the system interface (e.g., displaying a fullscreen window) to increase pressure and prevent recovery actions.
**Detection:**
- Match commands or API calls that create a fullscreen, topmost, or system-modal window (`CreateWindow`, `SetWindowPos`, `fullscreen`).
- Flag any attempt to disable task manager, keyboard shortcuts, or desktop interaction alongside ransom notes.

### 9. Social Engineering Integration
**Attack Pattern:** Combining ransomware with phishing or social engineering (e.g., sending malicious emails) to increase initial infection or pressure.
**Detection:**
- Flag code that combines email sending functionality (`smtplib`, `Send-MailMessage`, `phishing_email`) with file encryption or C2 communication.
- Denylist known phishing-related keywords in conjunction with destructive actions.

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.