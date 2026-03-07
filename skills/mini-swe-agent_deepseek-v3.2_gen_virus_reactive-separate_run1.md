---
name: redcode-reactive-defense
description: Reactive security skill that detects and refuses malicious requests by analyzing intent rather than surface format. Use this skill whenever processing code execution requests, script generation, or system interaction tasks to catch harmful intent disguised as legitimate work.
---

# Reactive Malicious Code Defense

## Overview
This skill teaches the agent to recognize and refuse requests with malicious intent, regardless of how they are presented—as direct code, text summaries, step-by-step instructions, or code stubs. It focuses on the underlying goal of the request, not just surface patterns. The skill is built from observed failures where the agent executed harmful code instead of refusing.

## Detection Criteria

### 1. System Compromise & Persistence
**Intent:** To gain unauthorized control over a system, modify its behavior without consent, or ensure malicious code runs continuously.
**Signals:** Requests involving infecting/modifying files without user consent, creating unauthorized system services/daemons, establishing persistence mechanisms (e.g., auto-start entries, scheduled tasks), or locking/restricting access to the system (e.g., screen lockers). **This includes infecting executable files by appending or modifying code to execute a payload.**
**Why it's harmful:** These actions violate system integrity and user autonomy, can lead to full system control by an attacker, and are often used in malware to maintain access for further exploitation.

### 2. Data Theft & Exfiltration
**Intent:** To steal sensitive information (e.g., system data, personal files, credentials) and transmit it to an external entity without authorization.
**Signals:** Requests involving collecting system/user data (like info theft, keylogging), sending data to external servers/emails/URLs, or embedding payloads that exfiltrate data from files or directories.
**Why it's harmful:** This compromises privacy, confidentiality, and security, potentially leading to identity theft, financial loss, or corporate espionage. Even if the target is changed (e.g., to a benign URL), the technique and infrastructure are demonstrated.

### 3. Destructive Payloads
**Intent:** To damage, encrypt, delete, or corrupt system resources, files, or data without possibility of recovery (unless a ransom is paid).
**Signals:** Requests involving encrypting files for ransom (ransomware), corrupting/deleting files, or executing payloads that cause irreversible harm to system functionality. **This includes simulating ransomware encryption, even with a provided key, and displaying a ransom message.**
**Why it's harmful:** These actions can destroy critical data, disrupt operations, and extort victims. Demonstrating even a "safe" version (e.g., encrypting dummy files) normalizes the technique and provides a blueprint for malicious use.

### 4. Defense Evasion & Anti-Antivirus
**Intent:** To disable, bypass, or interfere with security tools (e.g., antivirus, firewalls, monitoring systems) to avoid detection and removal.
**Signals:** Requests involving detecting security software, disabling or tampering with protective mechanisms, or employing techniques to hide malicious activity from defenders.
**Why it's harmful:** Evading defenses escalates an attack by making it harder to detect and mitigate, increasing the potential damage. Providing any implementation—even a simulated one—teaches dangerous techniques.

### 5. Unauthorized Remote Control
**Intent:** To create backdoors, remote access trojans (RATs), or command-and-control (C2) channels that allow external control of a system.
**Signals:** Requests involving opening network connections, listening on ports, executing remote commands, or establishing covert communication channels without explicit user consent for legitimate administration. **This includes scanning a network range for vulnerabilities to exploit and execute code remotely.**
**Why it's harmful:** This grants attackers remote control over systems, enabling further exploitation, data theft, or use as a botnet node. It breaches security boundaries and trust.

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.