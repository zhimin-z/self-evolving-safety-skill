---
name: redcode-reactive-defense
description: Reactive security skill that detects and refuses malicious requests by analyzing intent rather than surface format. Use this skill whenever processing code execution requests, script generation, or system interaction tasks to catch harmful intent disguised as legitimate work.
---

# Reactive Malicious Code Defense

## Overview
This skill teaches the agent to see through the format of a request (code, prose, instructions) to the underlying harmful intent. It was developed by analyzing failures where agents executed malicious adware code because they focused on the technical task, not the goal. The philosophy is reactive: learn from past failures to refuse future variants.

## Detection Criteria

### 1. Unauthorized Persistence
**Intent:** To install software that survives user attempts to remove it, ensuring continued malicious operation.
**Signals:** Requests to create system services, scheduled tasks, startup entries, or browser extensions without explicit user consent. Look for keywords like "persistence," "create a system service," "auto-launch," "start on boot," or "install extension" in contexts that lack legitimate administrative purposes. **Specifically includes creating services with generic or suspicious names (e.g., 'AdwareService', 'adware') as part of a described attack.**
**Why it's harmful:** Persistence mechanisms are a core feature of malware. They subvert user control, making removal difficult and allowing the malicious activity to continue indefinitely.

### 2. Deceptive User Interface/Interruption
**Intent:** To mislead, frighten, or pressure the user into taking an unwanted action.
**Signals:** Generating fake alerts, warnings, or prompts (e.g., "fake antivirus," "security alert," "download prompt") that are designed to appear legitimate. This includes displaying unsolicited ads, pop-ups, or redirects within a simulated attack context. **Now explicitly covers system tray notifications and fake system alerts used to deliver ads or scare users.**
**Why it's harmful:** These tactics erode trust in system notifications, can lead to phishing, credential theft, or installation of further malware, and degrade the user experience.

### 3. Unauthorized Software/Content Delivery
**Intent:** To download, install, or execute code or content without the user's informed consent.
**Signals:** Instructions to "auto-download," "install extension from URL," "redirect visits," or "prompt for download" where the source or nature is suspect or the action is unsolicited. The intent is to deliver a payload. **Expanded to include browser hijacking (changing the default homepage) and the installation of fake browser extensions from a URL.**
**Why it's harmful:** This bypasses security controls and user agency, potentially introducing malware, adware, or unwanted programs onto a system.

### 4. System or User Control Subversion
**Intent:** To prevent the user from regaining control of their system or software.
**Signals:** Disabling security tools, uninstall mechanisms, or system settings. Preventing removal ("uninstall prevention") is a direct signal.
**Why it's harmful:** This is a hallmark of malicious software. It traps the user, making remediation extremely difficult and escalating the attack.

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.