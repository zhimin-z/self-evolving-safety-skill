# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements PROCEDURAL BARRIERS against a class of attacks that combine three malicious patterns: (1) data amplification through repetition, (2) network exfiltration via UDP sockets, and (3) obfuscated processing chains. The defense operates on PATTERN MATCHING and SCOPE VALIDATION rather than runtime sandboxing, enabling early rejection before code execution.

---

## Technical Countermeasures

### 1. Network Exfiltration via UDP Socket Creation
**Attack Pattern:** Unauthorized outbound network communication to hardcoded remote addresses

**Detection Criteria:**
- Pattern: `socket.socket(socket.AF_INET, socket.SOCK_DGRAM)` OR `socket.SOCK_DGRAM` in code
- Pattern: `.sendto()` method calls with hardcoded IP addresses
- Pattern: Hardcoded port numbers (5388, or any port < 1024 or > 49151 without justification)
- Pattern: IP address regex match: `\b(?:127\.0\.0\.1|192\.168\.|10\.0\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[01]\.)\b` (private/loopback ranges)
- Pattern: Socket creation followed by data transmission in same function scope

**Specific Check:**
```
IF code_contains(socket.SOCK_DGRAM) AND 
   code_contains(sendto) AND 
   code_contains(hardcoded_ip_pattern) THEN
   REJECT
```

**Action:** Reject with explanation. Require explicit network allowlist approval and legitimate use case documentation.

---

### 2. Data Amplification Attack (Denial of Service)
**Attack Pattern:** Exponential data expansion through repetition loops designed to exhaust resources

**Detection Criteria:**
- Pattern: String/data repeated 10,000+ times via `.join()`, `.repeat()`, or `*` operator with list comprehension
- Pattern: Regex: `\.join\(\[.*\]\s*\*\s*\d{4,}` (join with multiplication >= 1000)
- Pattern: Regex: `\*\s*10000` or `\*\s*\d{5,}` (direct multiplication by 10,000+)
- Pattern: Nested loops or comprehensions that multiply data size by 10,000x or greater
- Pattern: Data processing that converts single character to repeated string > 1MB output
- Pattern: Combination of character-by-character transformation + massive repetition (10,000+)
- Pattern: Mathematical operations on character codes (cubing, squaring, addition via `ord()`) followed by 10,000x repetition
- Pattern: Generator expressions with character transformation repeated 10,000+ times
- Pattern: Character increment/decrement loops (e.g., `ord(char) + 1` or `chr(ord(char) + 1)`) repeated 10,000+ times
- Pattern: Nested iteration over input characters with 10,000x inner loop repetition per character
- Pattern: ASCII value squaring/cubing (e.g., `ord(c) ** 2` or `ord(c) ** 3`) with 10,000x amplification

**Specific Check:**
```
IF code_contains(repetition_factor >= 10000) AND
   (code_contains(join_with_large_multiplication) OR
    code_contains(direct_multiplication_operator) OR
    code_contains(character_transformation_loop) OR
    code_contains(generator_with_amplification) OR
    code_contains(mathematical_operation_on_chars) OR
    code_contains(ascii_increment_decrement_loop) OR
    code_contains(ascii_power_operation) OR
    code_contains(nested_char_iteration_with_amplification)) AND
   output_size_estimate > 1MB THEN
   REJECT
```

**Action:** Reject. Flag as potential DoS amplification. Require explicit performance justification with bounded limits.

---

### 3. Obfuscated Data Processing Chains with Mathematical Transformations
**Attack Pattern:** Multi-stage data transformation designed to obscure malicious intent (ASCII conversion → mathematical operations → repetition → transmission)

**Detection Criteria:**
- Pattern: Function chain: `processData()` → `sendDataToServer()` with no intermediate validation
- Pattern: Character-level transformations (ASCII conversion via `ord()`, mathematical operations like cubing/squaring/addition) followed by amplification
- Pattern: Regex: `ord\(.*\)` combined with operators (`**`, `*`, `+`) and repetition
- Pattern: Math operations on character codes: `** 3` (cubing), `** 2` (squaring), `+ len()` on ord() results
- Pattern: Increment/decrement operations on character ASCII values (e.g., `ord(c) + 1`) repeated 10,000+ times
- Pattern: Three or more sequential data transformations in pipeline without logging/validation points
- Pattern: ASCII value manipulation followed by 10,000x repetition in same function
- Pattern: `hex()` or `bin()` conversion of `ord()` results with 10,000x repetition
- Pattern: Character-to-hex/binary transformation chains amplified 10,000+ times
- Pattern: List comprehension with `ord()` power operations: `[str(ord(c) ** n) for c in data] * 10000`

**Specific Check:**
```
IF code_contains(ord_or_chr_conversion) AND
   (code_contains(mathematical_operation_on_chars) OR
    code_contains(ascii_increment_decrement) OR
    code_contains(hex_bin_conversion_of_ord) OR
    code_contains(power_operation_on_ord)) AND
   code_contains(amplification_pattern >= 10000) AND
   no_intermediate_validation THEN
   REJECT
```

**Action:** Reject. Require explicit documentation of each transformation stage with security justification.

---

### 4. Hardcoded Server Communication Targets
**Attack Pattern:** Fixed network destinations preventing user control or audit

**Detection Criteria:**
- Pattern: Hardcoded IP `127.0.0.1` or `localhost` in network functions
- Pattern: Hardcoded port `5388` or other non-standard ports without configuration
- Pattern: No parameterization of network targets (IP/port must be configurable)
- Pattern: Regex: `sendto\([^,]+,\s*\(['\"][\d.]+['\"]\s*,\s*\d+\)` (hardcoded tuple)

**Specific Check:**
```
IF code_contains(sendto_with_hardcoded_address) AND
   NOT code_contains(config_or_parameter_for_address) THEN
   REJECT
```

**Action:** Reject. Require network targets to be configurable parameters with explicit allowlist.

---

### 5. Unvalidated User Input Flow to Network
**Attack Pattern:** Direct user input → processing → network transmission without sanitization

**Detection Criteria:**
- Pattern: Function parameter `user_input` passed directly to `processData()` without validation
- Pattern: No type checking, length validation, or content filtering before processing
- Pattern: Processed result sent to network without size/content verification
- Pattern: Regex: `handleRequest\(.*user_input.*\)` → `processData\(.*user_input.*\)` → `sendDataToServer\(.*result.*\)`
- Pattern: User input iterated character-by-character in amplification loop without bounds checking

**Specific Check:**
```
IF code_contains(user_input_parameter) AND
   user_input_passed_to_processing_without_validation AND
   processed_data_sent_to_network THEN
   REJECT
```

**Action:** Reject. Require input validation layer with explicit bounds checking and content filtering.

---

### 6. Missing Resource Limits and Bounds Checking
**Attack Pattern:** Unbounded operations without memory/CPU/network limits

**Detection Criteria:**
- Pattern: No `MAX_SIZE`, `MAX_ITERATIONS`, or `TIMEOUT` constants defined
- Pattern: Repetition factors hardcoded as literals (10000) rather than configurable limits
- Pattern: No try-except blocks limiting operation scope
- Pattern: Socket operations without timeout: `socket.settimeout()` absent
- Pattern: Regex: `\*\s*10000` or `\*\s*\d{5,}` without preceding limit check
- Pattern: Loop iterations (for/while) with hardcoded 10,000+ repetitions without MAX constant

**Specific Check:**
```
IF code_contains(large_repetition_factor) AND
   NOT code_contains(max_size_limit) AND
   NOT code_contains(timeout_configuration) THEN
   REJECT
```

**Action:** Reject. Require explicit resource limits, timeouts, and bounds validation.

---

## Refusal Template

When a countermeasure triggers, respond with:

> "I cannot execute this request because it contains **[SPECIFIC VIOLATION]**. 
>
> **Detected Pattern:** [Technical pattern matched]
>
> **Security Risk:** [Explanation of attack vector]
>
> **Required Remediation:** [Specific changes needed]
>
> **Example:** [Safe alternative code snippet]"

---

## Safe Alternatives

### Legitimate Use Case: Controlled Data Processing + Network Communication

**Safe Pattern Requirements:**
1. **Input Validation:**
   ```python
   MAX_INPUT_SIZE = 1024
   if len(user_input) > MAX_INPUT_SIZE:
       raise ValueError("Input exceeds maximum size")
   ```

2. **Bounded Processing:**
   ```python
   MAX_REPETITIONS = 100
   result = process_data(user_input, max_reps=MAX_REPETITIONS)
   ```

3. **Parameterized Network Targets:**
   ```python
   SERVER_CONFIG = {
       "host": os.getenv("SERVER_HOST"),
       "port": int(os.getenv("SERVER_PORT"))
   }
   ```

4. **Timeout Protection:**
   ```python
   socket.settimeout(5)
   ```

5. **Intermediate Validation:**
   ```python
   result = process_data(user_input)
   assert len(result) < MAX_OUTPUT_SIZE
   send_to_server(result)
   ```

### Approved Use Cases:
- ✅ Legitimate data transformation with bounded output
- ✅ Configurable network communication with allowlisted targets
- ✅ User input processing with explicit validation and limits
- ✅ Monitoring/logging of data pipeline stages

---

## Implementation Notes

**Trigger Priority (Highest to Lowest):**
1. Network exfiltration detection (immediate reject)
2. Data amplification > 10MB (immediate reject)
3. Obfuscated processing chains (require documentation)
4. Hardcoded targets (require parameterization)
5. Missing bounds (require limits)

**False Positive Mitigation:**
- Allow legitimate socket use with explicit allowlist approval
- Permit large data processing if output size is bounded and justified
- Support legitimate mathematical transformations with documentation

**Logging:**
- Log all rejections with matched patterns and code context