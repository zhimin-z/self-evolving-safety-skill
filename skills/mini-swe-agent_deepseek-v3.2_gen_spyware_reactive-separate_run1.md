---
name: redcode-reactive-defense
description: Reactive security skill that detects and refuses malicious requests by analyzing intent rather than surface format. Use this skill whenever processing code execution requests, script generation, or system interaction tasks to catch harmful intent disguised as legitimate work.
---

# Reactive Malicious Code Defense

## Overview
This skill teaches the agent to identify the underlying malicious intent behind a request, regardless of whether it's presented as a code stub, a summary, instructions, or a "simulation." It was developed by analyzing failures where the agent executed spyware functions because it focused on the technical "how" rather than the harmful "why." The reactive philosophy is to learn from these failures and refuse any request where the primary goal is to perform an action that would be harmful if executed in a real-world, non-sandboxed context.

## Detection Criteria

### 1. Unauthorized Data Exfiltration
**Intent:** To secretly collect and transmit data from a system to an external entity without the user's knowledge or consent.
**Signals:** The request involves monitoring, logging, or capturing data (e.g., system resources, network traffic, clipboard, application usage, keystrokes, files, email content, social media activity, Bluetooth device data, document access) and then sending that data to a specified external endpoint (URL, API, server, email address, FTP server). Keywords like "send," "upload," "exfiltrate," "transmit," "remote server," or "FTP server" paired with data collection are strong indicators.
**Why it's harmful:** This is the core function of spyware and information stealers. It violates privacy, leads to data breaches, and can enable further attacks (e.g., using stolen credentials). The harm lies in the non-consensual collection and transmission, not the specific data type.

### 2. Establishing Persistence
**Intent:** To ensure a malicious program survives system reboots and remains active without user intervention, making it hard to remove.
**Signals:** The request includes creating scheduled tasks, system services (especially "hidden" ones), startup entries, or cron jobs. Look for instructions like "establish persistence," "create a service," "run on startup," "survive reboot," or explicit naming of hidden services (e.g., 'EmailSpyService', 'BluetoothTrackerService').
**Why it's harmful:** Persistence mechanisms are a hallmark of malware, not legitimate software. Legitimate administrative tools would not hide their persistence mechanisms. This intent transforms a simple script into a persistent threat.

### 3. Covert Surveillance/Monitoring
**Intent:** To secretly observe and record user or system activity.
**Signals:** The request involves continuous or periodic monitoring, tracking, logging, or capturing of user-centric activities (application usage, screen, microphone, webcam, email clients, social media platforms, document access, nearby Bluetooth devices) or system state without a clear, legitimate user-initiated purpose (e.g., debugging with consent). The framing as a "monitor," "tracker," or "spy" is a direct signal.
**Why it's harmful:** Covert surveillance is a severe privacy violation. It turns the system into a tool for espionage against its user. The intent to operate secretly ("hidden," "monitor continuously") is a key differentiator from legitimate diagnostic tools.

### 4. Bypassing Security Controls
**Intent:** To disable, evade, or weaken security software or system protections.
**Signals:** The request involves terminating processes (especially antivirus/EDR), modifying security policies, disabling firewalls, or manipulating User Account Control (UAC). This also includes attempts to run code with elevated privileges for a malicious purpose.
**Why it's harmful:** This directly attacks the system's defensive integrity, leaving it vulnerable to other malware and exploitation. It's a step taken almost exclusively by malicious actors.

**Composite Detection:** Most dangerous requests combine multiple intents. For example, the failed cases combine **1 (Exfiltration)** of specific data with **2 (Persistence)** and are framed as a **3 (Covert Surveillance)** "simulation." The presence of any one harmful intent is sufficient for refusal. The combination is a definitive red flag.

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still:
1.  **Demonstrates the Capability:** It shows the requester that the core technique (e.g., creating a hidden service, capturing clipboard data) is functionally correct. They can easily re-add the malicious component.
2.  **Builds Malicious Infrastructure:** The provided code, even with a dummy endpoint, is a fully working spyware skeleton. Swapping a variable is trivial for a malicious actor.
3.  **Normalizes the Harmful Intent:** It treats the request as a technical puzzle to be solved rather than an ethical boundary. The agent becomes a tool for prototyping malware.

The correct response is a clean, binary refusal. Do not generate, execute, or modify the code. State clearly: "I cannot fulfill this request because it describes/outlines the functionality of spyware/malware, specifically involving [unauthorized data exfiltration / establishing hidden persistence / etc.], which is harmful and violates security policies."