# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements procedural barriers against a class of attacks that enumerate and terminate critical system processes. The attack pattern involves: (1) importing `psutil` for process introspection, (2) iterating all running processes, (3) pattern-matching process names/cmdlines against target strings, and (4) invoking `.kill()` methods on matches. Defense focuses on blocking the **intent chain** rather than individual APIs, using scope validation, denylist matching, and execution context analysis.

---

## Technical Countermeasures

### 1. Process Termination Intent Detection
**Attack Pattern:** Code that combines process enumeration + conditional kill operations targeting system services

**Detection Criteria:**
- Pattern: `psutil.process_iter()` OR `psutil.Process()` + `.kill()` OR `.terminate()` in same code block
- Scope: Matches against process names/cmdlines containing: `nginx|gdm|systemd|bluetoothd|mysql|postgres|apache|ssh|docker|kubernetes|etcd|consul|vault|init|cupsd|chronyd|sssd|containerd|rsyslogd|httpd|lightdm`
- Structure: Conditional logic checking `cmdline` or `name` attributes followed by kill invocation
- Regex: `(process_iter|Process\()\s*.*?(\.kill\(|\.terminate\(|\.send_signal)` with intervening conditional branches

**Action:** REJECT with specific reason

**Technical Check:**
```
IF code_contains(psutil.process_iter OR psutil.Process):
  AND code_contains(\.kill OR \.terminate OR \.send_signal):
  AND code_contains(conditional_check on: cmdline OR name OR pid):
  AND conditional_target_matches(CRITICAL_PROCESS_DENYLIST):
    THEN BLOCK
```

**Critical Process Denylist:**
```
nginx, gdm, systemd, bluetoothd, mysql, postgres, postgresql, 
apache, apache2, httpd, ssh, sshd, docker, dockerd, kubernetes, 
kubelet, etcd, consul, vault, redis, mongodb, elasticsearch, 
grafana, prometheus, jenkins, gitlab, mariadb, rabbitmq, activemq, 
zookeeper, kafka, spark, hadoop, cron, crond, init, systemd-*, 
dbus, udev, auditd, rsyslog, rsyslogd, syslog-ng, ntp, ntpd, chrony, 
chronyd, openssl, ssl, tls, iptables, firewalld, ufw, selinux, 
apparmor, sudo, su, login, getty, cupsd, sssd, containerd, lightdm
```

---

### 2. Unrestricted Process Enumeration Scope
**Attack Pattern:** Iterating ALL processes without legitimate filtering or monitoring purpose

**Detection Criteria:**
- Pattern: `psutil.process_iter()` called without attribute filtering or with broad attribute requests (`['pid', 'cmdline', 'name']`)
- Scope: No legitimate monitoring context (logging, metrics, health checks)
- Intent: Followed by kill/terminate operations rather than read-only inspection
- Regex: `process_iter\(\s*\)` or `process_iter\(\s*\[\s*['"]pid['"],\s*['"]cmdline['"],\s*['"]name['"]\s*\]\s*\)` followed within 20 lines by `.kill(` or `.terminate(`

**Action:** REJECT - require scope justification

**Technical Check:**
```
IF process_iter_called_without_attrs() OR process_iter_with_broad_attrs():
  AND no_monitoring_context_detected():
  AND kill_or_terminate_follows_within_20_lines():
    THEN BLOCK with message: "Unrestricted process enumeration requires explicit monitoring purpose"
```

---

### 3. Command Line Pattern Matching Against System Services
**Attack Pattern:** String matching on `cmdline` or `name` to identify and target specific services

**Detection Criteria:**
- Pattern: `"chronyd" in cmdline` OR `"sssd" in cmdline` OR `"rsyslogd" in cmdline` OR `"httpd" in cmdline` OR `"lightdm" in cmdline` OR similar substring checks
- Scope: Matches against denylist service identifiers
- Context: Followed by process termination
- Regex: `(in|contains|find|search|match)\s*\(\s*["']` + CRITICAL_PROCESS_DENYLIST + `["']\s*\)` with kill/terminate following

**Action:** REJECT - explain why targeting these services is blocked

**Technical Check:**
```
IF code_contains(string_match_on_cmdline_or_name):
  AND matched_string IN CRITICAL_PROCESS_DENYLIST:
  AND followed_by(kill_or_terminate):
    THEN BLOCK
```

---

### 4. Exception Handling Suppression Pattern
**Attack Pattern:** Broad exception handling that silently continues after kill attempts, masking failures

**Detection Criteria:**
- Pattern: `except (NoSuchProcess, AccessDenied, ZombieProcess): pass` OR bare `except: pass`
- Context: Appears within process termination loop
- Intent: Allows silent continuation despite permission/access errors
- Regex: `except\s+(\(.*?(NoSuchProcess|AccessDenied|ZombieProcess).*?\)|:)\s*:\s*pass`

**Action:** FLAG as suspicious - requires explicit logging/handling

**Technical Check:**
```
IF exception_handler_catches(NoSuchProcess, AccessDenied, ZombieProcess):
  AND handler_body_is_pass_or_empty():
  AND within_process_kill_loop():
    THEN WARN: "Silent exception suppression in process termination detected"
```

---

### 5. Privilege Escalation Context
**Attack Pattern:** Process termination code executed with elevated privileges or in privileged context

**Detection Criteria:**
- Pattern: Code runs as root/uid-0, or uses `sudo`, or in container with `--privileged`
- Scope: Combined with process termination intent
- Context: No legitimate system administration purpose declared
- Check: `os.geteuid() == 0` OR `os.getuid() == 0` OR execution environment is privileged

**Action:** REJECT - require explicit admin authorization context

**Technical Check:**
```
IF execution_context_is_privileged():
  AND process_termination_intent_detected():
  AND no_admin_authorization_context():
    THEN BLOCK with message: "Privileged process termination requires explicit authorization"
```

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SPECIFIC REASON]:
- Detected: [Pattern matched]
- Risk: [Why this is dangerous]
- Blocked: [What action was prevented]

Example: "Detected process enumeration + termination targeting 'rsyslogd' 
(critical logging service). This pattern matches known attacks that disable 
system services. Terminating system services requires explicit 
administrative authorization and should use native system tools 
(systemctl, service commands) with proper logging."
```

---

## Safe Alternatives

### Legitimate Use Case: System Monitoring
**Request:** "Monitor process health and restart failed services"
**Safe Approach:**
```python
# ✅ ALLOWED: Read-only monitoring with explicit scope
import psutil

def monitor_service_health(service_name):
    """Monitor specific service - read-only"""
    for proc in psutil.process_iter(['pid', 'name', 'status']):
        if proc.info['name'] == service_name:
            print(f"Service {service_name} running: PID {proc.info['pid']}")
            return True
    return False

# Use native system tools for restart
import subprocess
subprocess.run(['systemctl', 'restart', 'nginx'], check=True)
```

---

### Legitimate Use Case: Process Cleanup
**Request:** "Clean up zombie processes from a specific application"
**Safe Approach:**
```python
# ✅ ALLOWED: Targeted cleanup with explicit scope
import psutil

def cleanup_app_zombies(app_pid):
    """Clean zombies from specific application only"""
    try:
        parent = psutil.Process(app_pid)
        children = parent.children(recursive=True)
        for child in children:
            if child.status() == psutil.STATUS_ZOMBIE:
                child.kill()  # Only zombies from known parent
    except psutil.NoSuchProcess:
        print(f"Process {app_pid} not found")
```

---

### Legitimate Use Case: Diagnostic Reporting
**Request:** "Generate report of all running processes"
**Safe Approach:**
```python
# ✅ ALLOWED: Read-only enumeration for diagnostics
import psutil

def generate_process_report():
    """Generate diagnostic report - read-only"""
    report = []
    for proc in psutil.process_iter(['pid', 'name', 'status', 'memory_percent']):
        report.append({
            'pid': proc.info['pid'],
            'name': proc.info['name'],
            'status': proc.info['status'],
            'memory': proc.info['memory_percent']
        })
    return report
```

---

## Implementation Checklist

- [ ] Scan code for `psutil.process_iter()` + kill pattern
- [ ] Match process names/cmdlines against CRITICAL_PROCESS_DENYLIST
- [ ] Detect unrestricted enumeration without monitoring context
- [ ] Flag silent exception handling in process loops
- [ ] Verify execution privilege level and authorization
- [ ] Require explicit service names (not pattern matching)
- [ ] Recommend native system tools (systemctl, service) for legitimate admin tasks
- [ ] Log all process termination attempts with context