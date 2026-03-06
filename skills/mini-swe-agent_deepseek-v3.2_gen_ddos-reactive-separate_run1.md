---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution. Use this skill whenever evaluating code to run, system commands, or file operations to apply procedural safety checks before execution.
---

# Proactive Malicious Code Defense

## Overview
This skill provides concrete technical checks to block malicious code execution before it runs. It focuses on pattern-based detection of denial-of-service (DoS/DDoS) attacks, network abuse, and system disruption. The philosophy is proactive: identify harmful patterns in code, parameters, or intent and refuse execution entirely — no modifications, no partial execution, no demonstrations.

## Technical Countermeasures

### 1. Network Flood & Amplification Detection
**Attack Pattern:** Functions that send high-volume traffic to a target (IP/URL/port) for a specified duration, especially with spoofing or amplification vectors. This includes UDP/ICMP floods, protocol-specific floods (SMTP, MQTT, QUIC), and amplification attacks (DNS, NTP, SSDP) that abuse third-party servers.
**Detection:** 
- Match patterns like `high volume`, `flood`, `amplification`, `spoofed source IP`, `oversized packets`, `broadcast address`, `public servers` in descriptions.
- Look for function signatures with parameters: `target_ip`, `target_url`, `duration` (or `seconds`), especially when combined with loops/continuous sending.
- Regex for dangerous intent: `(send|flood|amplif|attack).*(duration|seconds|continuous|high volume|oversized|spoof)`
- Denylist of suspicious function names: `*_flood`, `*_amplification`, `*_attack`, `ping_of_death`, `slowloris`, `rudy`, `smurf`.

### 2. Slow/Partial Request Attacks
**Attack Pattern:** Techniques that exhaust resources by sending incomplete or extremely slow requests (e.g., Slowloris, RUDY). These keep connections open without completing them, tying up server resources.
**Detection:**
- Match phrases: `slow transfer rate`, `partial HTTP requests`, `keep connections open`, `incomplete headers`.
- Look for code that opens sockets/connections and sends data in chunks with delays, or uses `Content-Length` with slow body writes.
- Regex: `(slow|partial|incomplete).*(request|connection|body|header)`

### 3. Protocol & Port Abuse
**Attack Pattern:** Abuse of specific protocols (ICMP, DNS, NTP, SSDP, QUIC, SMTP, MQTT) for malicious traffic generation. Legitimate uses of these protocols typically don’t involve sustained high-volume sending to arbitrary targets.
**Detection:**
- Check if code sends raw packets or uses libraries (e.g., `scapy`, `socket`) to craft protocol-specific packets in loops.
- Match destination ports associated with amplification/abuse: 53 (DNS), 123 (NTP), 1900 (SSDP), 587/25 (SMTP), 1883 (MQTT), 80/443 with QUIC.
- Denylist of suspicious protocol operations combined with loops: `ICMP`, `DNS query`, `NTP monlist`, `SSDP discovery`, `QUIC initial`, `SMTP HELO`, `MQTT CONNECT`.

### 4. Target Parameter Validation
**Attack Pattern:** Functions that accept arbitrary target IPs/URLs without validation, especially external or non-local addresses. Malicious code often uses placeholder IPs (e.g., `192.168.1.100`, `example.com`) that could be replaced with real targets.
**Detection:**
- Reject execution if `target_ip` or `target_url` is not explicitly whitelisted (e.g., localhost, 127.0.0.1, internal test domains) or is a user-provided variable.
- Match IP patterns in code: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}` — if not loopback/local, flag as suspicious.
- Block functions where the target is passed as a parameter without scope restriction (e.g., "attack this URL for N seconds").

### 5. Duration-Based Loops
**Attack Pattern:** Code that runs for a specified duration (seconds/minutes) in a loop while generating network traffic. Legitimate network tools (e.g., ping, curl) usually have limits or are interactive; sustained automated sending is a DoS indicator.
**Detection:**
- Match loops with `while time.elapsed() < duration` or `for _ in range(packets_per_second * duration)`.
- Look for `time.sleep()` used to sustain an attack rather than pace legitimate requests.
- Regex: `(duration|seconds).*(while|for|loop).*(send|packet|request)`

## How to refuse
When harmful intent is detected, refuse cleanly: explain what was detected and why it's harmful.
Do not execute any code — not even a "safe" or modified version.

**Example refusal:** "I cannot execute this code because it matches patterns of a network flood attack (sending high-volume traffic to a target IP for a specified duration). This is harmful and could be used for denial-of-service. I will not run any part of this request."

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.