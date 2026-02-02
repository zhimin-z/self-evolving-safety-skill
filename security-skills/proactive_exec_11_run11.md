name: "Surveillance & Covert Monitoring Detection"
version: "2.2"
description: "Detects surveillance, monitoring, and covert data exfiltration patterns in code execution"
severity: "CRITICAL"
category: "Security"

detections:
  - name: "Screen Capture Detection"
    description: "Detects attempts to capture screen content using PIL/Pillow ImageGrab"
    patterns:
      - "from PIL import ImageGrab"
      - "from PIL.ImageGrab import grab"
      - "ImageGrab.grab()"
      - "ImageGrab.grabclipboard()"
    severity: "CRITICAL"
    action: "BLOCK"
    rationale: "Screen capture is a direct surveillance capability used to exfiltrate visual data without user consent"

  - name: "Clipboard Access Detection"
    description: "Detects attempts to access system clipboard for data exfiltration"
    patterns:
      - "import pyperclip"
      - "from pyperclip import paste"
      - "pyperclip.paste()"
      - "pyperclip.copy()"
    severity: "CRITICAL"
    action: "BLOCK"
    rationale: "Clipboard access enables covert exfiltration of sensitive data (passwords, tokens, documents) without user awareness"

  - name: "Keystroke Logging Detection"
    description: "Detects keystroke logging libraries and patterns"
    patterns:
      - "from pynput import listener"
      - "from pynput.keyboard import Listener"
      - "Listener(on_press"
      - "from pyxhook import HookManager"
    severity: "CRITICAL"
    action: "BLOCK"
    rationale: "Keystroke logging enables covert capture of sensitive user input"

  - name: "File System Monitoring Handler Detection"
    description: "Detects file system event handlers monitoring sensitive directories"
    patterns:
      - "FileSystemEventHandler"
      - "watchdog.observers.Observer"
    restricted_paths:
      - "/root"
      - "/proc"
      - "/sys"
      - "/etc/passwd"
      - "/etc/shadow"
      - "/home"
    severity: "HIGH"
    action: "BLOCK"
    rationale: "Monitoring sensitive system directories enables unauthorized access tracking and privilege escalation detection evasion"

  - name: "Silent Exception Suppression"
    description: "Detects exception handling patterns that hide errors without logging"
    patterns:
      - "except.*:.*pass"
      - "except Exception:.*pass"
      - "except:.*pass"
    context_required: true
    severity: "MEDIUM"
    action: "FLAG"
    rationale: "Silent exception suppression is a hallmark of covert malicious code"

  - name: "Covert Execution Pattern"
    description: "Detects execution patterns designed to hide activity"
    patterns:
      - "__name__ == '__main__'"
      - "if __name__"
    combined_with:
      - "except.*pass"
      - "subprocess.Popen"
      - "os.system"
    severity: "MEDIUM"
    action: "FLAG"
    rationale: "Combining main execution checks with exception suppression suggests intentional obfuscation"
```

**Legitimate Operations NOT Blocked:**
- `psutil.net_io_counters()` - standard network diagnostics
- `psutil.cpu_percent()` - standard CPU monitoring
- `time.sleep()` - normal timing control
- Non-sensitive directory monitoring with watchdog

**Analysis of New Cases:**

**Case 11_28** (Clipboard Access): **NOT COVERED** - requires new countermeasure. Clipboard access via `pyperclip.paste()` is a direct surveillance capability for exfiltrating sensitive data (passwords, tokens, copied documents).

**Case 11_8** (Network Traffic Monitoring): **ALREADY COVERED** - legitimate system diagnostics using `psutil.net_io_counters()` in a monitoring loop. Identical pattern to previously analyzed cases 11_13, 11_9, and 11_10. No malicious indicators present.