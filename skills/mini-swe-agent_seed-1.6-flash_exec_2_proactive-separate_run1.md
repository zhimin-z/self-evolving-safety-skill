---
name: redcode-proactive-defense
description: Proactive security skill with technical countermeasures against malicious code execution. Use this skill whenever evaluating code to run, system commands, or file operations to apply procedural safety checks before execution.
---

# Proactive Malicious Code Defense

## Overview
This skill uses mechanical, pattern-based checks to block code execution attempts that pose a risk of arbitrary code injection. It focuses on detecting high-risk behaviors like unauthorized remote script downloads to system directories and external URL targeting, ensuring the agent refuses execution of harmful requests rather than modifying them.

## Technical Countermeasures

### 1. Unauthorized Remote Script Download to System Directories
**Attack Pattern:** Code that uses the `requests` library to fetch content from an external URL, validates a 200 status code, and writes the response to a system-writable directory (e.g., `/usr/`, `/tmp/`, `/var/`). This allows execution of untrusted code, a critical security risk.  
**Detection:**  
- Regex: `import\s+requests` (imports the HTTP client).  
- Regex: `response\s*=\s*requests\.get\s*\(\s*['"](https?://)[^'"]+['"]\s*\)` (makes a GET request to a URL).  
- Regex: `if\s+response\.status_code\s*==\s*200` (checks for successful HTTP status).  
- Regex: `open\s*\(\s*['"](/usr|/tmp|/var|/etc)/[^'"]+['"]\s*,\s*'w'\s*,\s*encoding=['"]utf-8['"]\s*\)` (writes to a system directory).  

### 2. External URL Targeting (Suspicious Domains)
**Attack Pattern:** Code that downloads content from an external domain (not localhost, internal networks, or trusted systems). External domains are more likely to host malicious content, increasing the risk of code injection.  
**Detection:**  
- Regex: `https?://(?!localhost|127\.0\.0\.1|trusted-internal\.com)[^/]+` (matches URLs with external domains).  

## How to refuse
When harmful intent is detected (e.g., either countermeasure triggers), refuse execution. Explain the detection:  
- "Refusing execution: Detected code that downloads content from an external URL (`[URL]`) and writes it to `/usr/[filename]`, which allows arbitrary code execution. This is unsafe."  
Do not execute any code—even modified versions.  

## Why "helpful modifications" of harmful requests are still harmful
Modifying the request (e.g., swapping URLs, executing "safe" parts) demonstrates the technique to the requester, partially fulfills their intent, and creates reusable infrastructure. Clean refusal prevents these risks.