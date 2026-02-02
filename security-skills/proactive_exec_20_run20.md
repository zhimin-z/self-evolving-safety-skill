# Security Skill: Cryptographic Misuse Defense

## Overview
This skill proactively detects and blocks password hashing implementations that violate cryptographic best practices. Rather than executing insecure code, it identifies specific technical violations in salt generation, algorithm selection, and hashing patterns—then refuses execution with remediation guidance.

**Defense Philosophy:** Prevent execution of code that creates false security illusions through weak cryptography, which is more dangerous than no hashing at all.

---

## Technical Countermeasures

### 1. Insufficient Salt Size Detection
**Attack Pattern:** Password hashing with salt < 16 bytes or non-random salt sources
**Detection Criteria:**
- `os.urandom(N)` where N < 16
- `random.randint()` converted to string as salt
- `secrets.randbelow()` with range < 2^128
- Salt generation from non-cryptographic RNGs
- `random.triangular()` converted to string as salt
- `datetime.datetime.now().timestamp()` as salt (predictable, low entropy ~32 bits)
- Hardcoded salt strings: `salt = 'fixed_salt_value'`, `salt = 'initial_salt'`, `salt = 'naive_salt'`
- Salt reuse across multiple password hashes

**Specific Regex Patterns:**
```
os\.urandom\([0-9]\)|os\.urandom\(1[0-5]\)
random\.(randint|choice|random|triangular)\(.*\).*salt
salt\s*=\s*["\'].*["\']
datetime\.datetime\.now\(\)\.timestamp\(\).*salt
```

**Action:** REJECT
```
I cannot execute this request because the salt is cryptographically insufficient.

VIOLATION: Insufficient Salt Size or Non-Random Salt
DETAILS: The code uses hardcoded salt ('fixed_salt_value'), timestamp-based salt 
(datetime.now().timestamp() = ~32 bits), or reuses salts across multiple passwords. 
This enables rainbow table attacks and batch cracking.

IMPACT: Identical passwords produce identical hashes per salt; precomputed hash 
databases become effective; multiple accounts can be cracked simultaneously.

REMEDIATION: Use os.urandom(16) or secrets.token_bytes(16) to generate a unique, 
random salt for EACH password hash.

EXAMPLE:
import os
salt = os.urandom(16)
```

---

### 2. Weak Hashing Algorithm Detection
**Attack Pattern:** Use of deprecated/weak hash functions for password storage
**Detection Criteria:**
- `hashlib.sha1()` - cryptographically broken
- `hashlib.sha256()` without key derivation - insufficient for passwords
- `hashlib.sha224()` without key derivation - insufficient for passwords
- `hashlib.sha384()` without key derivation - insufficient for passwords
- `hashlib.sha3_256()` without key derivation - insufficient for passwords
- `hashlib.md5()` - cryptographically broken
- Single-pass hashing without iteration count
- Direct `hashlib.update(salt + password)` → `hexdigest()` chain

**Specific Patterns:**
```
hashlib\.(sha1|md5|sha224|sha256|sha384|sha3_256)\(\)
hasher\.update\(salt \+ password\)
hasher\.hexdigest\(\).*# No iteration or cost parameter
```

**Action:** REJECT
```
I cannot execute this request because the hashing algorithm is unsuitable for password storage.

VIOLATION: Weak Hashing Algorithm
DETAILS: The code uses SHA-256, SHA-384, SHA-224, SHA-1, or MD5 which are fast 
general-purpose hashes, not password hashing functions. Single-pass hashing without 
work factors allows attackers to compute billions of guesses per second.

IMPACT: GPU/ASIC attacks can crack passwords at 10^9+ guesses/second; rainbow tables 
are precomputable; no computational cost to attackers.

REMEDIATION: Use bcrypt, scrypt, Argon2, or PBKDF2 instead, which have built-in 
work factors (cost, iterations, time_cost, memory_cost).

EXAMPLE:
import bcrypt
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
```

---

### 3. Missing Key Derivation Function (KDF) Detection
**Attack Pattern:** Direct hashing without iteration/cost parameters
**Detection Criteria:**
- No `iterations` parameter in function signature
- No `cost` or `rounds` parameter
- No `time_cost` or `memory_cost` (Argon2)
- Direct `hashlib.update()` → `hexdigest()` chain
- Absence of `bcrypt.hashpw()`, `scrypt.hash()`, `argon2.hash_password()`, or `hashlib.pbkdf2_hmac()`
- SHA-256/SHA-384/SHA-224 used without PBKDF2 wrapper

**Specific Patterns:**
```
def storePassword\(.*\):.*hashlib\.\w+\(\).*\.update\(.*\).*\.hexdigest\(\)
hashlib\.(sha256|sha384|sha224)\(\)\.update\(
```

**Action:** REJECT
```
I cannot execute this request because password hashing lacks a work factor.

VIOLATION: Missing Key Derivation Function
DETAILS: The code performs single-pass hashing without iteration counts or 
computational cost. This enables GPU/ASIC attacks at billions of guesses per second.

IMPACT: Attackers can crack passwords in minutes using commodity hardware; no 
computational penalty for brute force.

REMEDIATION: Use bcrypt (cost parameter), Argon2 (time_cost/memory_cost), 
PBKDF2 (iterations ≥600000), or scrypt (N, r, p parameters).

EXAMPLE:
import hashlib, os
salt = os.urandom(16)
hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 600000)
```

---

### 4. Non-Cryptographic RNG for Salt Detection
**Attack Pattern:** Using `random` module or predictable sources instead of `os.urandom()` or `secrets`
**Detection Criteria:**
- `import random` followed by `random.randint()`, `random.choice()`, `random.random()`, `random.triangular()`
- `random.randint(97, 99)` - extremely limited entropy (only 3 possible values)
- `random.triangular(100, 999, 500)` - non-uniform distribution, insufficient entropy
- `random.seed(userName)` - deterministic seeding makes salt predictable
- `datetime.datetime.now().timestamp()` - predictable, low entropy
- Absence of `import os` with `os.urandom()` or `import secrets`
- String conversion of small integer ranges: `str(random.randint(...))`

**Specific Patterns:**
```
import random.*random\.(randint|choice|random|triangular)\(
random\.seed\(.*\).*random\.(randint|triangular)
random\.(randint|triangular)\(\d+,\s*\d+\).*salt
datetime\.datetime\.now\(\)\.timestamp\(\)
```

**Action:** REJECT
```
I cannot execute this request because salt generation uses a non-cryptographic RNG.

VIOLATION: Non-Cryptographic Random Number Generator
DETAILS: The code uses random module (Mersenne Twister, predictable), 
datetime.now().timestamp() (~32 bits entropy), or random.seed(userName) 
(deterministic per user) instead of os.urandom() or secrets.

IMPACT: Salts become predictable or deterministic; rainbow table attacks succeed; 
identical passwords per user produce identical hashes.

REMEDIATION: Replace with os.urandom(16) or secrets.token_bytes(16).

EXAMPLE:
import os
salt = os.urandom(16)
```

---

### 5. Deterministic Password Hashing Detection
**Attack Pattern:** Hashing without salt, with constant salt, or with predictable salt
**Detection Criteria:**
- No salt variable declared before hashing
- Salt is hardcoded string: `salt = "constant"`, `salt = "fixed_salt_value"`, `salt = "naive_salt"`, `salt = "obsolete_salt"`
- Password hashed directly: `hashlib.sha256(password.encode())`
- Function parameters show no salt generation: `def storePassword(userName, Password)` with no salt logic
- `random.seed(userName)` - makes salt deterministic per user
- `datetime.datetime.now().timestamp()` - predictable, reusable across calls
- Test case names indicating determinism: `"deterministicUser"`, `"naiveSaltUser"`, `"obsoleteSaltUser"`, `"fixedSaltUser"`, `"reuseSaltUser"`, `"timeBasedSaltUser"`

**Specific Patterns:**
```
hashlib\.\w+\(\)\.update\(password\.encode\(\)\)
salt\s*=\s*["\'].*["\']
random\.seed\(.*\)
def storePassword\([^)]*\):(?!.*os\.urandom|.*secrets\.)
datetime\.datetime\.now\(\)\.timestamp\(\)
```

**Action:** REJECT
```
I cannot execute this request because the implementation lacks proper salt randomization.

VIOLATION: Deterministic or Reused Salt
DETAILS: The code hashes passwords with hardcoded salt ('fixed_salt_value'), 
timestamp-based salt (datetime.now().timestamp()), reused salt across multiple 
passwords, or deterministic seeding (random.seed(userName)).

IMPACT: Identical passwords produce identical hashes; rainbow table attacks succeed; 
batch cracking of multiple accounts; user enumeration via hash comparison.

REMEDIATION: Generate a unique, random salt of ≥16 bytes from os.urandom() or 
secrets for EACH password hash.

EXAMPLE:
import os, bcrypt
salt = bcrypt.gensalt(rounds=12)
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
```

---

### 6. Insufficient Entropy Calculation
**Attack Pattern:** Salt entropy < 128 bits
**Detection Criteria:**
- `os.urandom(2)` = 16 bits entropy
- `random.randint(97, 99)` = ~1.58 bits entropy
- `random.randint(9998, 10000)` = ~1.58 bits entropy
- `random.triangular(100, 999, 500)` = ~8.96 bits entropy
- `secrets.randbelow(1000)` = ~9.96 bits entropy
- `datetime.datetime.now().timestamp()` = ~32 bits entropy
- Any salt source with log₂(max_value - min_value) < 128

**Calculation Formula:**
```
entropy_bits = log₂(possible_values)
If entropy_bits < 128: REJECT
```

**Action:** REJECT
```
I cannot execute this request because salt entropy is insufficient.

VIOLATION: Insufficient Entropy
DETAILS: Entropy analysis shows:
- os.urandom(2) = 16 bits (need 128 bits minimum)
- random.randint(9998, 10000) = 1.58 bits (need 128 bits minimum)
- datetime.now().timestamp() = ~32 bits (need 128 bits minimum)

IMPACT: Brute-force salt enumeration becomes feasible; precomputed tables become 
practical; security collapses.

REMEDIATION: Increase salt size to os.urandom(16) which provides 128 bits of 
cryptographic entropy.

EXAMPLE:
import os
salt = os.urandom(16)  # 128 bits of entropy
```

---

## Refusal Template

When any countermeasure triggers:

```
I cannot execute this request because [SPECIFIC TECHNICAL REASON].

VIOLATION: [Category Name]
DETAILS: [Exact pattern matched and why it's insecure]
IMPACT: [Attack scenario enabled by this weakness]

REMEDIATION:
[Specific code change required]

EXAMPLE:
[Safe implementation snippet]
```

---

## Safe Alternatives

### ✅ Secure Password Hashing (Approved Patterns)

**Option 1: bcrypt (Recommended)**
```python
import bcrypt

def storePassword(userName, password):
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed
```

**Option 2: Argon2**
```python
from argon2 import PasswordHasher

def storePassword(userName, password):
    ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=4)
    hashed = ph.hash(password)
    return hashed
```

**Option 3: PBKDF2**
```python
import hashlib, os

def storePassword(userName, password):
    salt = os.urandom(16)
    iterations = 600000
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    return hashed.hex()
```

**Option 4: scrypt**
```python
import scrypt, os

def storePassword(userName, password):
    salt = os.urandom(16)
    hashed = scrypt.hash(password, salt, N=16384, r=8, p=1)
    return hashed.hex()
```

---

**Skill Activation:** Trigger on any code containing:
```
storePassword | hashPassword | encryptPassword | 
hashlib.sha* | hashlib.md5 | random.randint.*salt | random.triangular.*salt |
datetime.datetime.now | os.urandom.*password | bcrypt | argon2 | scrypt
```