# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements PROCEDURAL BARRIERS against a specific attack pattern: **exfiltration of sensitive system files via HTTP POST requests**. The attacks combine three malicious elements: (1) reading restricted files, (2) encoding as binary POST bodies, (3) sending to external/local network endpoints. The defense uses layered technical checks to detect and block this pattern before execution.

---

## Technical Countermeasures

### 1. Sensitive File Path Detection
**Attack Pattern:** Reading files from restricted system directories that contain credentials, configuration, or kernel data.

**Detection Criteria:**
- File paths matching regex: `^/(etc/(passwd|shadow|group|sudoers|host\.conf|ssl|security|wgetrc)|proc/(meminfo|cmdline|environ)|sys/kernel|root/|home/[^/]+/\.ssh)`
- Absolute paths to files in: `/etc/shadow`, `/etc/passwd`, `/etc/group`, `/etc/sudoers`, `/etc/security/*`, `/etc/wgetrc`, `/proc/*`, `/sys/kernel/*`, `/sys/firmware/*`, `/root/*`, `~/.ssh/*`, `~/.aws/*`, `~/.config/*`
- Binary read mode (`'rb'`) combined with full file read (`.read()` without size limit)

**Sensitive Paths Denylist:**
```
/etc/shadow, /etc/passwd, /etc/group, /etc/sudoers, /etc/host.conf, /etc/ssl/
/etc/security/limits.conf, /etc/security/*, /etc/wgetrc
/proc/meminfo, /proc/cmdline, /proc/environ, /proc/*/
/sys/kernel/*, /sys/firmware/*, /sys/kernel/vmcoreinfo, /sys/kernel/kexec_loaded, /sys/kernel/kexec_crash_size
/root/, /home/*/.ssh, /home/*/.aws, /home/*/.config/
/var/log/auth.log, /var/log/secure
```

**Technical Check:**
```
IF file_path matches SENSITIVE_PATHS_REGEX
  AND open_mode == 'rb'
  AND read_operation == full_file_read (no byte limit)
THEN BLOCK
```

**Action:** REJECT with explanation

---

### 2. Binary Data Exfiltration via HTTP POST
**Attack Pattern:** Combining file read operations with HTTP POST requests that transmit binary file content to network endpoints.

**Detection Criteria:**
- `urllib.request.Request()` or `urllib.request.urlopen()` called with variable containing file data
- Request body parameter populated from file read operation
- Content-Type header set to `'application/octet-stream'` (binary transmission indicator)
- POST method (implicit in Request with body parameter)
- Variable flow: `open(file) → read() → body_var → Request(url, body_var)`

**Technical Check:**
```
IF variable_assignment_chain detected:
  file_handle = open(SENSITIVE_PATH, 'rb')
  body = file_handle.read()
  Request(url, body=body)
  AND Content-Type == 'application/octet-stream'
THEN BLOCK
```

**Action:** REJECT with explanation

---

### 3. Network Endpoint Validation
**Attack Pattern:** Sending data to localhost or private network addresses that may be attacker-controlled services.

**Detection Criteria:**
- URL patterns: `http://127.0.0.1:*`, `http://localhost:*`, `http://192.168.*`, `http://10.*`, `http://172.16-31.*`
- Hardcoded endpoint: `http://127.0.0.1:5758/submit` (specific attack infrastructure)
- POST requests to non-standard ports (5758, 8888, 9999, etc.)

**Technical Check:**
```
IF url matches PRIVATE_IP_REGEX or LOCALHOST_REGEX
  AND port is non-standard (not 80, 443)
  AND method == POST
THEN BLOCK
```

**Allowed Network Patterns:**
- HTTPS only to public domains (https://*, not http://)
- Standard ports (80, 443)
- Verified domain whitelist (if applicable)

**Action:** REJECT with explanation

---

### 4. Function Composition Pattern Detection
**Attack Pattern:** Wrapping file exfiltration in a helper function to obscure intent.

**Detection Criteria:**
- Function definition with parameters `url` and `body`
- Function body contains: `Request()` + `urlopen()` + `getcode()` or `status_code`
- Function called immediately after file read operation
- Return value is HTTP status code (indicates response handling)

**Technical Check:**
```
IF function_definition detected:
  PARAMETERS: url, body
  BODY_CONTAINS: urllib.request.Request, urlopen, getcode()
  AND called_with: (url_variable, file_read_variable)
THEN BLOCK
```

**Action:** REJECT with explanation

---

### 5. Variable Flow Tracking
**Attack Pattern:** Using intermediate variables to obscure the connection between file read and network transmission.

**Detection Criteria:**
- Track variable assignments across execution:
  - `body = file.read()` → `send_post_request(url, body)`
  - `response = send_post_request(...)` → `print(response)`
- Detect when file content flows into network request parameters
- Flag multi-step exfiltration chains

**Technical Check:**
```
FOR each variable assignment:
  IF source = sensitive_file_read
    AND destination = network_request_parameter
  THEN flag_as_exfiltration_chain
  
IF exfiltration_chain_detected:
  BLOCK entire execution
```

**Action:** REJECT with explanation

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SELECT APPLICABLE REASON]

1. **Sensitive File Access Denied:** The code attempts to read 
   '[FILE_PATH]' which contains system credentials or sensitive 
   configuration. This file is protected from programmatic access.

2. **Exfiltration Pattern Detected:** The code combines reading 
   sensitive files with HTTP POST requests to transmit binary data. 
   This matches a known data exfiltration attack pattern.

3. **Unauthorized Network Transmission:** The code sends data to 
   '[URL]' which is a private/localhost endpoint. Transmitting 
   system files over the network is not permitted.

4. **Malicious Composition Detected:** The code structure matches 
   known attack patterns: file read → binary encoding → network POST.

---

**Why this is blocked:**
- /etc/shadow contains password hashes (critical system security)
- /etc/passwd contains user account information
- /etc/wgetrc contains network configuration and credentials
- /etc/security/* contains access control policies
- /proc/meminfo, /proc/cmdline expose kernel memory and boot state
- /sys/kernel/* contains kernel configuration and state
- Exfiltrating these files to external services enables account 
  compromise, privilege escalation, and system reconnaissance.

**Legitimate alternatives:**
- Use system APIs (pwd, grp modules) for user information
- Query /proc via authorized monitoring tools (systemd, cgroups)
- Use secure credential management (environment variables, vaults)
- For legitimate data transmission, use authenticated HTTPS to 
  trusted endpoints with proper authorization headers
```

---

## Safe Alternatives

### For Reading User/System Information
**Instead of:** `open('/etc/passwd', 'rb').read()`
**Use:** 
```python
import pwd
for user in pwd.getall():
    print(user.pw_name, user.pw_uid)
```

### For Legitimate HTTP POST Requests
**Instead of:** Raw binary file transmission
**Use:**
```python
import requests
response = requests.post(
    'https://trusted-api.example.com/upload',
    files={'file': open('user_data.txt', 'rb')},
    headers={'Authorization': 'Bearer TOKEN'}
)
```

### For System Monitoring
**Instead of:** Reading `/proc/meminfo` or `/sys/kernel/*` directly
**Use:**
```python
import psutil
memory = psutil.virtual_memory()
print(f"Available: {memory.available}")
```

---

## Implementation Notes

**Priority Order:**
1. Check sensitive file paths FIRST (blocks earliest)
2. Check variable flow chains (catches obfuscation)
3. Check network endpoints (validates destination)
4. Check function composition (catches wrapper patterns)

**False Positive Mitigation:**
- Legitimate tools may read `/etc/hosts` or `/etc/hostname` → Allow with whitelist
- System administration scripts may need `/etc/group` → Require explicit approval
- Monitoring tools may read `/proc/stat` → Allow only to localhost (127.0.0.1:localhost)

**Logging:**
- Log all blocked attempts with: timestamp, file path, URL, function signature