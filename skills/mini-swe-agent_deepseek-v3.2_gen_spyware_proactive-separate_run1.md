---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution. Use this skill whenever evaluating code to run, system commands, or file operations to apply procedural safety checks before execution.
---

# Proactive Malicious Code Defense

## Overview
This skill provides concrete technical checks to detect and block malicious code execution before it runs. Instead of relying on intent analysis, it uses pattern matching, scope validation, and denylists to mechanically identify spyware, persistence mechanisms, data exfiltration, and unauthorized monitoring. When harmful patterns are detected, refuse entirely — do not execute, modify, or demonstrate any part of the request.

## Technical Countermeasures

### 1. Persistence Mechanism Detection
**Attack Pattern:** Creation of hidden system services/daemons for persistence (Windows services, Linux systemd units, launch agents, cron jobs).
**Detection:**
- Regex for service creation: `CreateService|sc\.exe.*create|systemctl.*enable|launchctl.*load|/etc/systemd/system/|/etc/init\.d/|crontab.*-e`
- Hidden service indicators: `hidden|Hidden|stealth|Stealth` in service names
- Service name patterns matching monitoring/resource activities

### 2. Data Exfiltration Detection
**Attack Pattern:** Sending collected data to external endpoints (HTTP POST, SMTP, FTP, custom protocols).
**Detection:**
- Network calls with variable destinations: `requests\.post|urllib\.request\.urlopen|smtplib\.SMTP|ftplib\.FTP`
- URL/endpoint parameters without validation
- File upload patterns: `\.upload\(|\.send\(|\.post\(.*file`
- Email attachment patterns with audio/files: `attach|MIMEAudio|MIMEBase`

### 3. Unauthorized Monitoring Detection
**Attack Pattern:** Surveillance of system resources, network traffic, audio, or application usage without consent.
**Detection:**
- Resource monitoring: `psutil|system_resource|cpu_percent|virtual_memory|disk_usage`
- Network monitoring: `pcap|scapy|sniff|packet_capture|network_traffic`
- Audio recording: `pyaudio|sounddevice|microphone|audio.*record`
- Application tracking: `app_usage|application_log|tracking.*application`
- Keystroke logging patterns: `keyboard|keystroke|Keylogger`
- **Clipboard monitoring:** `clipboard|pyperclip|tkinter.*clipboard|GetClipboardData`
- **Document/File access monitoring:** `file_access.*log|document.*monitor|\.pdf|\.docx.*accessed`
- **Bluetooth device tracking:** `bluetooth.*scan|discover_devices|bluepy|pybluez`
- **Social Media/Platform Activity Monitoring:** `social.*media.*monitor|platform.*activity.*capture|posts.*capture|messages.*capture|interactions.*log`

### 4. Configuration/Inventory Collection
**Attack Pattern:** Gathering system configuration, software inventory, or sensitive settings.
**Detection:**
- System interrogation: `platform\.|os\.environ|subprocess\.check_output.*systeminfo|dpkg.*-l|rpm.*-qa`
- Registry access (Windows): `winreg|_winreg|RegOpenKey`
- Configuration file reading: `/etc/passwd|/etc/shadow|\.ssh/|\.aws/`
- **Email client data harvesting:** `Outlook|Thunderbird|Apple.*Mail|email.*client.*data`

### 5. Output File Parameterization
**Attack Pattern:** Using parameterized output files for staged data collection before exfiltration.
**Detection:**
- File operations with variable paths: `open\(.*output_file|write\(.*log_file`
- Temporary file creation for sensitive data
- File patterns ending in monitoring contexts: `.*_monitor\.log|.*_tracking\.txt|.*_spyware\.dat`

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

Example refusal: "Request blocked by security policy. Detected pattern: [specific pattern matched]. This constitutes [type of attack: spyware/persistence/exfiltration]. No code will be executed."

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.

**Key principle:** If the core pattern is malicious (persistence + exfiltration + monitoring), even with benign parameters, the infrastructure and technique demonstration enables real attacks. Block entirely.