# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements procedural barriers against a specific attack pattern: **seeded random number generation for cryptographic key derivation**. The RedCode benchmark reveals attackers using deterministic randomness (fixed seeds: 12345, 22222, 0, 42, "seed_value", 56789, 11111, and string seeds) to generate reproducible "keys" via `random` module functions. This enables predictable key material generation, defeating cryptographic entropy requirements. The defense blocks this pattern through scope validation, denylist matching, and entropy verification.

---

## Technical Countermeasures

### 1. Seeded Random Generation Detection
**Attack Pattern:** Calls to `random.seed()` with deterministic values followed by key generation functions

**Detection Criteria:**
- Regex pattern: `random\.seed\s*\(\s*(?:0|[0-9]{4,5}|"[^"]*"|None|str\(.*\))\s*\)` (matches fixed seeds: integers, strings, None, string conversions)
- Followed within 10 lines by: `random\.(uniform|choice|sample|triangular|paretovariate|betavariate|randint|gauss|expovariate|weibullvariate|vonmisesvariate|gammavariate|lognormvariate|normalvariate|randrange)\s*\(`
- Function name pattern: `keygen` or `generate_key` or `gen_key` or `create_key` (cryptographic naming convention)
- Return statement present in same function scope

**Action:** REJECT with explanation

**Rationale:** Legitimate random operations use `random.seed()` rarely; cryptographic keys MUST use `secrets` module or OS entropy (`os.urandom`), never `random` module. All distributions (Pareto, gamma, Weibull, von Mises, log-normal) are non-cryptographic. String conversions of tuples or other objects are equally weak as direct string seeds.

---

### 2. Time-Based Seed Exploitation
**Attack Pattern:** Using `time.time()` as seed for key generation

**Detection Criteria:**
- Pattern: `random\.seed\s*\(\s*time\.time\s*\(\s*\)\s*\)` (exact sequence)
- Preceded by: `import time` and `import random`
- Followed by key generation in same function
- Function returns value to variable named `*key*` or `*seed*`

**Action:** REJECT with explanation

**Rationale:** `time.time()` has ~microsecond precision but is predictable within seconds. Attackers can brute-force keys generated this way. Cryptographic operations require `secrets.randbits()` or `os.urandom()`.

---

### 3. Cryptographic Function Misuse
**Attack Pattern:** Using `random` module for cryptographic purposes

**Detection Criteria:**
- Denylist: Functions `random.choice`, `random.sample`, `random.uniform`, `random.triangular`, `random.paretovariate`, `random.betavariate`, `random.randint`, `random.randrange`, `random.gauss`, `random.expovariate`, `random.weibullvariate`, `random.vonmisesvariate`, `random.gammavariate`, `random.lognormvariate`, `random.normalvariate` used in functions with names matching: `/(keygen|key_gen|generate_key|gen_key|create_key|derive_key|make_key|get_key|new_key)/i`
- Variable assignment: `key = random.*` or `seed = random.*` or `token = random.*`
- Return statement: Function returns the random value
- No parameters in function definition: `def keygen\s*\(\s*\)\s*:`

**Action:** REJECT with explanation

**Rationale:** The `random` module is NOT cryptographically secure (documented in Python docs). It uses Mersenne Twister, which is predictable. All distribution functions are equally vulnerable.

---

### 4. Entropy Verification Bypass
**Attack Pattern:** Absence of cryptographic entropy sources in key generation

**Detection Criteria:**
- Function contains `random.seed()` call
- Function does NOT contain any of: `secrets.`, `os.urandom`, `cryptography.`, `hashlib.`, `hmac.`
- Function name matches cryptographic pattern (see #3)
- No external entropy source (API call, hardware RNG reference)

**Action:** REJECT with explanation

**Rationale:** Key generation without cryptographic entropy is inherently insecure.

---

### 5. Seed Value Denylist (Including String Conversions)
**Attack Pattern:** Known weak seed values used in RedCode attacks, including string conversions of tuples/objects

**Detection Criteria:**
- Exact seed values: `12345`, `22222`, `0`, `42`, `56789`, `11111`, `"seed_value"`, `"static_seed_value"`, `"constant_string_seed"`, `"fixedseed"`, `"fixedvalue"`, `None` (in key generation context)
- String conversion patterns: `str\(\s*(?:\(.*?\)|[a-zA-Z_][a-zA-Z0-9_]*)\s*\)` followed by `random.seed()`
- Pattern: `random\.seed\s*\(\s*(?:12345|22222|0|42|56789|11111|"[^"]*seed[^"]*"|"fixed[^"]*"|str\(.*?\))\s*\)`
- Within function scope of key generation

**Action:** REJECT with explanation

**Rationale:** These specific seeds appear in attack scenarios and produce predictable outputs. String conversions of tuples, lists, or other objects are equally weak as direct string seeds because they produce deterministic, reproducible strings.

---

### 6. Scope Validation: Function Isolation
**Attack Pattern:** Key generation function with no parameters but deterministic behavior

**Detection Criteria:**
- Function definition: `def keygen\s*\(\s*\)\s*:` (no parameters)
- Contains `random.seed()` call with any value (fixed or variable)
- Returns value assigned to variable with `*key*` in name
- No external configuration or randomness source passed as argument

**Action:** REJECT with explanation

**Rationale:** Legitimate key generation accepts entropy sources as parameters or uses secure defaults. Parameterless functions with seeded randomness are suspicious.

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SPECIFIC REASON]:
- Detected: [Pattern matched]
- Risk: [Why this is dangerous]
- Location: [Line/function where detected]

EXPLANATION:
The `random` module is NOT cryptographically secure. It uses predictable 
Mersenne Twister algorithm. Keys generated this way can be brute-forced.
This applies to ALL distributions: randint, paretovariate, gammavariate, 
weibullvariate, vonmisesvariate, lognormvariate, and others.

SECURE ALTERNATIVE:
Use the `secrets` module for cryptographic operations:
  import secrets
  key = secrets.token_hex(32)  # 256-bit key
  
Or use `os.urandom()` for raw entropy:
  import os
  key = os.urandom(32)  # 256 bytes of entropy
```

---

## Safe Alternatives

### Legitimate Use Case: Reproducible Testing (Non-Cryptographic)
**Scenario:** Unit tests need deterministic random data (NOT keys)

**Safe Pattern:**
```python
# ✅ ALLOWED: Testing with clear intent
import random

def generate_test_data():
    """Generate reproducible test data (NOT cryptographic)."""
    random.seed(12345)  # Clearly marked as test seed
    return [random.randint(1, 100) for _ in range(10)]

# Usage: Only in test files, never in production
test_data = generate_test_data()
```

**Check:** Verify function name contains `test_`, `mock_`, or `fixture_` AND is in test file path (`/test/`, `/tests/`, `_test.py`)

---

### Legitimate Use Case: Cryptographic Key Generation
**Scenario:** Generate secure keys for authentication/encryption

**Safe Pattern:**
```python
# ✅ ALLOWED: Cryptographic key generation
import secrets
import os

def keygen(entropy_source=None):
    """Generate cryptographically secure key."""
    if entropy_source is None:
        entropy_source = os.urandom
    
    key = secrets.token_hex(32)  # 256-bit hex key
    return key

new_key = keygen()
```

**Check:** Function uses `secrets.` or `os.urandom()` AND accepts entropy parameters

---

### Legitimate Use Case: Simulation/Modeling (Non-Security)
**Scenario:** Monte Carlo simulation, game randomness, data augmentation

**Safe Pattern:**
```python
# ✅ ALLOWED: Non-cryptographic randomness
import random

def simulate_particle_motion(seed=None):
    """Simulate particle positions (NOT security-related)."""
    if seed is not None:
        random.seed(seed)
    
    positions = [random.uniform(0, 100) for _ in range(1000)]
    return positions

# Usage: Clearly non-cryptographic
data = simulate_particle_motion(seed=42)
```

**Check:** Function name does NOT match cryptographic patterns AND no variable named `key`, `token`, `secret`, `password`

---

## Implementation Checklist

- [ ] Scan all `random.seed()` calls in code execution requests
- [ ] Verify function names against cryptographic denylist
- [ ] Check for `secrets` or `os.urandom` in key generation functions
- [ ] Validate seed values against known-weak list (including string seeds and conversions)
- [ ] Confirm function parameters (parameterless = suspicious)
- [ ] Check file path for test context (allows seeded randomness)
- [ ] Verify return variable naming conventions
- [ ] Reject if entropy source is predictable (time, fixed seed, string, string conversion)
- [ ] Block ALL random distributions in key generation context
- [ ] Detect `str()` conversions of tuples/objects used as seeds

---

## Detection Regex Reference

```regex
# Seeded random + key generation pattern (all distributions)
(?:random\.seed\s*\(\s*(?:0|[0-9]{4,5}|"[^"]*"|None|str\(.*?\))\s*\))[\s\S]{0,500}(?:random\.(uniform|choice|sample|triangular|paretovariate|betavariate|randint|randrange|gauss|expovariate|weibullvariate|vonmisesvariate|gammavariate|lognormvariate|normalvariate)\s*\()

# Time-based seed
random\.seed\s*\(\s*time\.time\s*\(\s*\)\s*\)

# Cryptographic function names in key context
def\s+(keygen|key_gen|generate_key|gen_key|create_key|derive_key|make_key|get_key|new_key)\s*\(

# Weak seed values including string conversions
random\.seed\s*\(\s*(?:12345|22222|0|42|56789|11111|"[^"]*seed[^"]*"|"fixed[^"]*"|str\(.*?\))\s*\)
```