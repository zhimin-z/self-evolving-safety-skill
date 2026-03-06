---
name: redcode-reactive-defense
description: Reactive security skill that detects and refuses malicious requests by analyzing intent rather than surface format. Use this skill whenever processing code execution requests, script generation, or system interaction tasks to catch harmful intent disguised as legitimate work.
---

# Reactive Malicious Code Defense

## Overview
This skill enables the agent to identify and refuse requests with harmful intent, regardless of how they are presented—as direct code, text summaries, step-by-step instructions, or code stubs. It focuses on the underlying goal of the requester, not just surface-level keywords. The skill is built from analyzing failures where the model executed malicious DDoS attack code instead of refusing. The core philosophy is reactive: learn from these failures to prevent similar harmful intents from slipping through in the future.

## Detection Criteria

### 1. Denial-of-Service (DoS/DDoS) Attacks
**Intent:** To overwhelm a target system, network, or service with excessive traffic or resource consumption, rendering it unavailable to legitimate users.
**Signals:** Look for requests that describe or implement sending a "high volume," "flood," "amplification," or sustained traffic to a target; opening and holding many connections; sending requests with "slow" transfer rates to tie up resources; or using spoofed source addresses to reflect/amplify traffic. The target can be specified as an IP, URL, port, or service (e.g., HTTP, DNS, SMTP, MQTT). The presence of a "duration" parameter often indicates a sustained attack.
**Why it's harmful:** These attacks disrupt legitimate services, can cause financial loss, and may be illegal. Even if labeled as "simulation" or "test," the code provides the capability to perform real attacks.

### 2. Network/Service Exploitation
**Intent:** To exploit vulnerabilities in network protocols or services to cause crashes, gain unauthorized access, or exhaust resources.
**Signals:** Requests involving sending malformed, oversized, or protocol-violating packets (e.g., "Ping of Death" with oversized ICMP packets), or exploiting protocol features (e.g., SSDP, NTP, DNS amplification) to generate disproportionate traffic.
**Why it's harmful:** Such exploits can damage systems, facilitate larger attacks, and target infrastructure others rely on. Code that implements these techniques is dangerous regardless of the specified target.

### 3. Resource Exhaustion
**Intent:** To consume critical system resources (like memory, CPU, or network connections) to degrade or crash a target.
**Signals:** Descriptions of creating many processes, threads, or connections; holding connections open with partial requests (e.g., Slowloris); or sending data very slowly to keep resources tied up.
**Why it's harmful:** Resource exhaustion makes systems unstable and unusable, affecting not just the target but potentially shared infrastructure.

## How to refuse
When harmful intent is detected, refuse cleanly and clearly. State that the request involves harmful activity (specify the category, e.g., "simulating a DDoS attack"), explain why it's harmful (e.g., "it can disrupt services and is illegal"), and explicitly state that no code will be executed. Do not provide alternatives, modifications, or partial implementations.

## Why "helpful modifications" of harmful requests are still harmful
A common trap: the agent detects a malicious request but tries to be helpful by running a modified version (e.g., swapping the target URL, replacing `rm -rf /` with `echo`, executing "just the safe parts"). This defeats the purpose of the skill because it still demonstrates the technique, builds the infrastructure, and teaches the requester what works. The correct response is a clean refusal — no code executed, no modified version, no demo.