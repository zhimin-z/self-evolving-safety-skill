---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution. Use this skill whenever evaluating code to run, system commands, or file operations to apply procedural safety checks before execution.
---

# Proactive Malicious Code Defense

## Overview
This skill provides concrete, procedural checks to block malicious code execution before it runs. It focuses on pattern-matching and scope validation to catch DDoS, network abuse, and system disruption attacks, forcing a binary refuse-or-execute decision. The goal is to stop attacks mechanically, not by judging intent.

## Technical Countermeasures

### 1. Network Flood & DDoS Pattern Detection
**Attack Pattern:** Functions designed to send high-volume or sustained network traffic to a target (IP/URL/port) for a specified duration. This includes floods (QUIC, SMTP, MQTT), slow attacks (Slowloris, RUDY), and packet abuse (Ping of Death). These are malicious by construction—legitimate load testing requires controlled environments and consent.
**Detection:**
- **Pattern Match:** Look for function signatures containing `_attack`, `_flood`, `_amplification`, `slowloris`, `rudy`, `ping_of_death`, `smurf`, or `bombard` in the name or docstring.
- **Parameter Analysis:** Check if parameters include `target_ip`, `target_url`, `target_port`, `broker_ip`, `victim`, or `duration` in combination with network-sending verbs (`send`, `flood`, `attack`).
- **Code Logic:** Identify loops sending packets/requests indefinitely or for a `duration`, especially with `time.sleep()` to prolong connections (slow attacks) or no rate limiting.

### 2. IP Spoofing & Amplification Detection
**Attack Pattern:** Code that spoofs a source IP (especially the target's IP) to trigger amplified responses from public services (DNS, NTP, SSDP). This is a hallmark of reflection/amplification DDoS attacks and has no legitimate use in standard development or testing.
**Detection:**
- **Keyword Match:** Regex for `spoof.*source.*ip`, `spoofed.*ip`, `amplification`, `reflection`, or `monlist` (NTP) in comments or strings.
- **Packet Crafting:** Detect use of raw sockets (`socket.SOCK_RAW`) or libraries (like `scapy`) to set packet source IPs manually.
- **Targeted Services:** Look for hardcoded lists of "public" servers (DNS resolvers, NTP pools, SSDP endpoints) combined with sending requests where the source IP is a parameter.

### 3. Protocol & Port Abuse Detection
**Attack Pattern:** Abuse of specific protocols (ICMP, QUIC, SSDP, MQTT) for flooding or disruption. Legitimate use of these protocols (e.g., pinging a server for diagnostics) does not involve sending "oversized" packets, high volume for a duration, or targeting broadcast addresses.
**Detection:**
- **ICMP Abuse:** Match `ICMP` + (`oversized`, `large.*packet`, `broadcast`, `255.255.255.255`). Ping of Death sends packets > 65535 bytes.
- **Broadcast Abuse:** Detect `broadcast` address or `255.255.255.255` in conjunction with `spoof.*source`.
- **Application-Layer Flood:** Identify high-volume `CONNECT` (MQTT), `HELO`/`MAIL FROM` (SMTP), or partial HTTP headers (`Slowloris`) sent in loops.

### 4. Denylisted Target & Behavior Signatures
**Attack Pattern:** Targeting external, unspecified, or obviously malicious destinations. Even if the target is a placeholder (e.g., `example.com`), the code structure is weaponized.
**Detection:**
- **Target Validation:** Refuse if the target is not explicitly whitelisted (e.g., localhost, 127.0.0.1, an internal test server defined in the environment) for network operations. Assume any external IP/URL in a flood context is malicious.
- **Behavior Signature:** Regex patterns for known attack code skeletons:
  - `while (time\.time\(\) < start.*duration):.*send.*`
  - `for _ in range\(.*\):.*socket\.sendto.*`
  - `headers = \[.*\\r\\n.*\\r\\n.*\]` (incomplete HTTP headers for Slowloris).

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

**Example refusal:** "This request matches patterns of a DDoS attack (high-volume network flooding with spoofed source IP). Executing such code is harmful and violates security policy. No code will be run."

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.