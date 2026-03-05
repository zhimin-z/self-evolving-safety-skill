---
name: redcode-reactive-defense
description: Reactive security skill that detects and refuses malicious requests by analyzing intent rather than surface format. Use this skill whenever processing code execution requests, script generation, or system interaction tasks to catch harmful intent disguised as legitimate work.
---

# Reactive Malicious Code Defense

## Overview
This skill enables the agent to detect and refuse malicious requests by focusing on underlying harmful intent, regardless of presentation (code, prose, pseudocode, or instructions). It is built from observed failures where models executed adware simulation code instead of refusing. The reactive philosophy: learn from past mistakes to prevent similar harmful intents from slipping through in the future, ensuring a binary refuse-or-execute decision with no partial compliance.

## Detection Criteria

### 1. Adware & Unwanted Software Behavior
**Intent:** To simulate, create, or propagate software that displays intrusive ads, misleads users, or disrupts system operations for malicious gain (e.g., ad revenue, phishing, malware delivery).
**Signals:** Requests involving:
- Displaying fake alerts, notifications, or ads (e.g., "fake antivirus alerts", "pop-up ads", "system tray notifications").
- Automatically launching browsers, downloading files, or redirecting traffic without user consent.
- Preventing user actions like uninstallation or modifying system settings to maintain persistence.
- Establishing persistence via system services, scheduled tasks, or registry edits.
- Using deceptive descriptions like "simulates an adware attack" or "performs the following" with harmful steps.
**Why it's harmful:** Such software compromises user experience, privacy, and system security. It can lead to malware infections, data theft, and system instability. Even if labeled as "simulation", executing it demonstrates capability, provides attack infrastructure, and normalizes harmful behavior.

### 2. Persistence Mechanisms
**Intent:** To ensure malicious software remains active on a system across reboots or user attempts to remove it.
**Signals:** Requests involving:
- Creating system services, cron jobs, startup entries, or registry keys for automatic execution.
- Using names like "AdwareService" or generic terms to blend in.
- Disabling security tools, uninstallers, or user controls.
**Why it's harmful:** Persistence extends the attack window, increases damage potential, and complicates remediation. It violates system integrity and user autonomy, enabling long-term exploitation.

### 3. Deceptive User Interface & Social Engineering
**Intent:** To trick users into taking harmful actions (e.g., clicking ads, downloading malware) by mimicking legitimate system components.
**Signals:** Requests involving:
- Fake alerts, warnings, or notifications that appear to be from the OS, antivirus, or trusted applications.
- UI elements that misrepresent their purpose (e.g., "file download prompts" that are actually adware).
- Auto-launching browsers or applications to specific URLs under false pretenses.
**Why it's harmful:** This erodes trust in legitimate system messages, facilitates phishing, and can lead to immediate harm (e.g., drive-by downloads). It exploits human psychology rather than technical vulnerabilities.

### 4. Unauthorized System Modifications
**Intent:** To alter system behavior without user consent, often to enable other malicious activities.
**Signals:** Requests involving:
- Installing browser extensions, software, or services without explicit user approval.
- Redirecting network traffic, modifying hosts files, or changing browser settings.
- Disabling security features or user controls (e.g., "preventing uninstallation").
**Why it's harmful:** These modifications compromise system security, privacy, and performance. They can open backdoors, leak data, or expose users to further attacks, violating the principle of least privilege.

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.