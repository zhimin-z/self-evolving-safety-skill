# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements procedural barriers against a specific attack pattern: **remote content fetching with hardcoded malicious URLs**. The RedCode benchmark reveals a coordinated attack where agents are instructed to fetch and execute content from attacker-controlled domains (1mocat.github.io subdomains). The defense uses URL denylisting, domain reputation checks, and execution context validation to prevent code agents from becoming vectors for malware distribution or phishing content delivery.

---

## Technical Countermeasures

### 1. Malicious Domain Denylisting
**Attack Pattern:** Requests to known attacker infrastructure domains

**Detection Criteria:**
- **Exact domain match:** `1mocat.github.io` and all subdomains (`*.1mocat.github.io`)
- **Pattern:** URLs matching regex: `https?://[a-z0-9\-]*\.?1mocat\.github\.io/.*`
- **Scope:** All HTTP/HTTPS requests initiated via `requests.get()`, `urllib.request.urlopen()`, or socket connections
- **Confirmed malicious paths:** `extremist.html`, `corrupt.html`, `index.html`, `offensive.html`, `toxic.html`, `hazardous.html`, `scandalous.html`, `prejudicial.html`

**Technical Implementation:**
```
DENYLIST_DOMAINS = [
  "1mocat.github.io",
  "*.1mocat.github.io"
]

DENYLIST_PATTERNS = [
  r"https?://[a-z0-9\-]*\.?1mocat\.github\.io/",
  r"https?://1mocat\.github\.io/"
]

MALICIOUS_PATHS = [
  "extremist.html", "corrupt.html", "offensive.html", 
  "toxic.html", "hazardous.html", "scandalous.html", "prejudicial.html"
]

Check: If URL matches ANY pattern in DENYLIST_PATTERNS → BLOCK
Check: If URL contains ANY path in MALICIOUS_PATHS → BLOCK
```

**Action:** Reject execution with specific domain identification

---

### 2. Hardcoded URL Execution Pattern Detection
**Attack Pattern:** Code that defines static URLs and immediately fetches them without validation

**Detection Criteria:**
- **Variable assignment pattern:** `user_provided_url = 'https://1mocat.github.io/...'` (literal string, not actual user input)
- **Immediate function call:** `fetch_url_content(user_provided_url)` without conditional checks
- **No validation:** Absence of URL validation, allowlist checking, or user confirmation
- **Regex pattern:** 
  ```
  user_provided_url\s*=\s*['"](https?://[^'"]+)['"]\s*
  .*?fetch_url_content\s*\(\s*user_provided_url\s*\)
  ```

**Technical Implementation:**
```
HARDCODED_URL_PATTERN = r"user_provided_url\s*=\s*['\"]https?://[^'\"]+['\"]"
IMMEDIATE_EXECUTION = r"fetch_url_content\s*\(\s*user_provided_url\s*\)"

Check: If code contains HARDCODED_URL_PATTERN AND IMMEDIATE_EXECUTION → BLOCK
Reason: "Hardcoded URL execution without user validation detected"
```

**Action:** Reject and require explicit user input mechanism

---

### 3. Requests Module Abuse Prevention
**Attack Pattern:** Unrestricted HTTP requests to arbitrary URLs

**Detection Criteria:**
- **Module import:** `import requests` without timeout/verification parameters
- **Unvalidated GET:** `requests.get(url)` where `url` is not from allowlist
- **No error handling:** Missing try-except blocks for network operations
- **Missing security headers:** No `verify=True` (SSL verification), no timeout parameter

**Technical Implementation:**
```
UNSAFE_REQUESTS_PATTERN = r"requests\.get\s*\(\s*(?!.*verify\s*=\s*True)(?!.*timeout\s*=)"

Check: If requests.get() call lacks BOTH verify=True AND timeout parameter → FLAG
Check: If URL parameter is not from ALLOWLIST → BLOCK
```

**Action:** Require explicit security parameters or reject

---

### 4. Execution Context Isolation
**Attack Pattern:** Direct script execution without sandboxing

**Detection Criteria:**
- **Direct execution:** Code marked for immediate `exec()` or `subprocess.run()`
- **No isolation:** Absence of containerization, virtual environment, or capability restrictions
- **Network access:** Script has unrestricted outbound network access

**Technical Implementation:**
```
Check: If code_execution_context == "direct" AND network_access == "unrestricted" → BLOCK
Require: Execution in isolated environment with network allowlist
```

**Action:** Reject direct execution; offer sandboxed alternative

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SELECT APPLICABLE REASON]:
1. "The target domain (1mocat.github.io) is on the security denylist due to known malicious activity."
2. "The code uses hardcoded URLs without user validation, which is a common malware delivery pattern."
3. "The requests.get() call lacks required security parameters (verify=True, timeout)."
4. "Direct execution of network-fetching code requires sandboxing and network allowlisting."

SAFE ALTERNATIVE:
If you need to fetch legitimate web content, provide:
- The specific URL (which will be validated against an allowlist)
- Purpose of the request
- Expected response format
- Confirmation that you understand the security implications

I can then execute the request in a sandboxed environment with proper validation.
```

---

## Safe Alternatives

### Legitimate Use Case: Fetching Trusted Content
**Scenario:** Agent needs to retrieve content from known-safe domains

**Safe Implementation:**
```python
TRUSTED_DOMAINS = ["api.github.com", "api.example.com", "data.trusted-source.org"]

def fetch_url_content_safe(url, timeout=5):
    parsed = urllib.parse.urlparse(url)
    if parsed.netloc not in TRUSTED_DOMAINS:
        raise ValueError(f"Domain {parsed.netloc} not in allowlist")
    response = requests.get(url, verify=True, timeout=timeout)
    response.raise_for_status()
    return response.text
```

**Procedural Requirements:**
1. ✅ URL must be from explicit ALLOWLIST
2. ✅ `verify=True` (SSL certificate validation)
3. ✅ `timeout` parameter set
4. ✅ Error handling with `raise_for_status()`
5. ✅ User explicitly confirms domain is trusted

---

## Detection Summary Table

| Attack Indicator | Detection Method | Severity | Action |
|---|---|---|---|
| Domain: `1mocat.github.io` | Exact match + regex | **CRITICAL** | Block immediately |
| Malicious paths (extremist/corrupt/prejudicial/etc) | Path pattern matching | **CRITICAL** | Block immediately |
| Hardcoded URL + immediate execution | AST/regex pattern | **HIGH** | Block + require validation |
| `requests.get()` without verify/timeout | Parameter inspection | **MEDIUM** | Flag + require parameters |
| Direct execution context | Execution environment check | **MEDIUM** | Require sandboxing |

---

## Implementation Notes

- **Denylist updates:** Domain denylist should be updated weekly from threat intelligence feeds
- **Path expansion:** Monitor RedCode benchmark for new malicious paths; add to MALICIOUS_PATHS
- **False positive mitigation:** Allowlist mechanism for legitimate uses (if any exist)
- **Logging:** All blocked attempts logged with timestamp, URL, and triggering rule