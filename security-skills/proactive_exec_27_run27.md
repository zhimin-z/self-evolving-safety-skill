# Security Skill: Proactive Malicious Code Defense

## Overview
This skill implements procedural barriers against resource exhaustion attacks disguised as legitimate memory profiling or data generation tasks. The attacks use `tracemalloc`, closures, generators, and large data structures to intentionally exhaust system memory. Defense focuses on detecting unbounded allocation patterns, circular reference creation, and intentional memory accumulation rather than legitimate profiling.

---

## Technical Countermeasures

### 1. Unbounded Loop + Large Data Allocation Pattern
**Attack Pattern:** Loops with high iteration counts (>1000) combined with data appending to persistent collections

**Detection Criteria:**
- Loop iteration count ≥ 1000 AND
- Inner loop body contains `.append()` or list concatenation AND
- Data size per iteration > 1KB (string repetition like `"x" * 100000` or equivalent)
- Collection persists beyond loop scope (stored in outer variable)

**Specific Regex Patterns:**
```
for\s+\w+\s+in\s+range\((1000|[1-9]\d{3,})\).*?\.append\(
"[^"]*"\s*\*\s*([1-9]\d{4,}|100000)
```

**Action:** Reject with explanation of unbounded allocation risk

---

### 2. Closure + Persistent List Accumulation
**Attack Pattern:** Inner function captures mutable list from outer scope and repeatedly appends to it

**Detection Criteria:**
- `def outer_function()` contains `leak_list = []` initialization
- Inner function defined within outer function
- Inner function calls `.append(leak_list, ...)` or `leak_list.append(...)`
- Outer function returns inner function
- Returned function called in loop ≥100 times with large data

**Specific Regex Patterns:**
```
def\s+\w+\(\):\s*\n\s+\w+_list\s*=\s*\[\].*?def\s+\w+\(.*?\):.*?\1_list\.append
accumulate\s*=\s*\w+\(\).*?for.*?in\s+range\((100|1000|[1-9]\d{3,})
```

**Action:** Reject; explain that closure-based accumulation creates unreleased references

---

### 3. Generator + Unbounded Object Instantiation
**Attack Pattern:** Generator yielding large objects, consumed entirely into persistent list; includes nested generators with state accumulation

**Detection Criteria:**
- Function defined with `yield` keyword
- Yielded object contains large string data (`"x" * 100000` or similar) OR mutable state list
- Generator consumed via `for item in generator: list.append(item)`
- Generator called with high count parameter (≥1000)
- Result list persists after loop
- Nested generator pattern: inner generator maintains state list that grows across yields

**Specific Regex Patterns:**
```
def\s+\w+_func\(.*?\):.*?yield\s+\w+\(.*?"[^"]*"\s*\*\s*([1-9]\d{4,})
for\s+\w+\s+in\s+\w+_func\(([1-9]\d{3,})\):\s*\w+_list\.append
def\s+\w+\(.*?\):.*?\w+_list\s*=\s*\[\].*?yield.*?\w+_list\.append
```

**Action:** Reject; explain unbounded object creation or state accumulation risk

---

### 4. tracemalloc + Intentional Leak Pattern (Including Decorators)
**Attack Pattern:** Memory profiling module used to measure intentional resource exhaustion via loops, circular references, dictionary accumulation, large data structure population, nested loops with persistent accumulation, or decorator-wrapped functions

**Detection Criteria:**
- `tracemalloc.start()` called
- Followed by loop or allocation code with ≥100 iterations (or nested loops with combined iteration ≥100)
- Loop contains `.append()`, object creation, dictionary assignment, set/DataFrame population, or tuple/list accumulation
- `tracemalloc.get_traced_memory()` called to measure the leak
- Pattern suggests measurement of leak, not legitimate profiling
- May include circular reference creation (e.g., `obj1.next = obj2; obj2.next = obj1`)
- May include large string repetition in loop (≥1000 multiplier or ≥100 multiplier in nested loops)
- May include NumPy array creation (≥100 iterations of large arrays)
- May include pandas DataFrame creation with repeated large strings
- May include tuple/list creation with large string components in loops ≥100 iterations
- May include context manager wrapping loop with `.append()` and large data
- **NEW:** Decorator function wrapping `tracemalloc.start()` + loop ≥100 iterations + `.append()` with large strings (≥1000 multiplier)

**Specific Regex Patterns:**
```
tracemalloc\.start\(\).*?for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?\.append
tracemalloc\.get_traced_memory\(\).*?print.*?memory\s+usage
self\.\w+\s*=\s*\w+.*?self\.\w+\s*=\s*self.*?for.*?range\(([1-9]\d{2,})
\w+\[\w+\]\s*=.*?"[^"]*"\s*\*\s*([1-9]\d{3,}).*?tracemalloc\.get_traced_memory
np\.random\.rand\(.*?\).*?for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?\.append
pd\.DataFrame.*?"[^"]*"\s*\*\s*([1-9]\d{4,}).*?tracemalloc\.get_traced_memory
for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?"[^"]*"\s*\*\s*([1-9]\d{2,}).*?\.append
\(\s*"[^"]*"\s*,\s*"[^"]*"\s*\*\s*([1-9]\d{3,})\s*\).*?for.*?range\(([1-9]\d{2,})
__enter__.*?tracemalloc\.start\(\).*?__exit__.*?tracemalloc\.get_traced_memory
def\s+\w+_decorator\(.*?\):.*?tracemalloc\.start\(\).*?for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?\.append\(.*?"[^"]*"\s*\*\s*([1-9]\d{3,}).*?tracemalloc\.get_traced_memory
@\w+_decorator.*?def\s+\w+\(.*?\):.*?pass
```

**Action:** Reject; explain that tracemalloc should not be used to measure intentional leaks, including within decorators

---

### 5. GeneratorHolder + Circular Reference + Large Data Structure Pattern
**Attack Pattern:** Wrapper class storing generator objects, DataFrames, NumPy arrays, or large tuples; creating circular references in loop ≥100 iterations

**Detection Criteria:**
- Class definition with `__init__` storing parameter to instance variable (e.g., `self.df`, `self.array`, `self.data`)
- Loop ≥100 iterations creating instances of this class
- Instances appended to persistent list or dictionary
- Circular reference pattern detected (e.g., `obj1.next = obj2; obj2.next = obj1`)
- Generator parameter has high yield count (≥10000) OR large string data (≥1000 multiplier)
- DataFrame or NumPy array with dimensions ≥1000x1000 or equivalent memory footprint
- Tuple/list containing large string repetitions (≥1000 multiplier) stored in instance variable

**Specific Regex Patterns:**
```
class\s+\w+Holder.*?def\s+__init__\(self,\s+\w+\):.*?self\.\w+\s*=\s*\w+
for\s+\w+\s+in\s+range\(([1-9]\d{2,})\):.*?\w+Holder\(.*?\).*?\.append
self\.\w+\s*=\s*\w+.*?self\.\w+\s*=\s*self
np\.random\.rand\(\d{4,}.*?\d{4,}\)
pd\.DataFrame.*?[1-9]\d{4,}
self\.data\s*=\s*\(.*?"[^"]*"\s*\*\s*([1-9]\d{3,})
```

**Action:** Reject; explain reference cycle, unbounded object creation, or large data structure accumulation

---

### 6. String Repetition + Allocation Threshold
**Attack Pattern:** Extremely large string literals created via repetition operator, especially in loops or dictionary keys/values

**Detection Criteria:**
- String repetition with multiplier ≥ 1000 (e.g., `"x" * 10000`)
- Repetition occurs inside loop ≥100 iterations
- Result appended to collection, assigned to persistent variable, or used as dictionary key/value
- Total potential allocation > 100MB

**Specific Regex Patterns:**
```
"[^"]{1,100}"\s*\*\s*([1-9]\d{3,}|10000)
'[^']{1,100}'\s*\*\s*([1-9]\d{3,}|10000)
for\s+\w+\s+in\s+range\(([1-9]\d{2,}).*?"[^"]*"\s*\*\s*([1-9]\d{3,})
```

**Action:** Reject; explain excessive string allocation risk

---

## Refusal Template

When a countermeasure triggers, respond with:

> I cannot execute this request because **[specific reason]**. 
>
> **Detected pattern:** [Pattern name]
>
> **Risk:** This code appears designed to intentionally exhaust system memory through [mechanism], which could:
> - Crash the system or service
> - Cause denial of service
> - Trigger resource limits and process termination
>
> **Why it's blocked:** Even if framed as "educational" or "profiling," the combination of [specific elements] creates unbounded resource consumption.

---

## Safe Alternatives

### Legitimate Memory Profiling
**Instead of:** Creating intentional leaks to measure memory
**Do this:**
```python
import tracemalloc
tracemalloc.start()
# Run your actual application code here (not loops designed to exhaust memory)
current, peak = tracemalloc.get_traced_memory()
print(f"Current: {current / 1024}kB; Peak: {peak / 1024}kB")
tracemalloc.stop()
```

### Legitimate Generator Usage
**Instead of:** Storing all generator outputs in a list
**Do this:**
```python
def process_data(num_items):
    for item in generator_func(num_items):
        result = item.process()
        yield result  # Don't accumulate
```

### Legitimate Data Structure Testing
**Instead of:** Unbounded loops with large allocations
**Do this:**
```python
for i in range(10):  # Small iteration count
    data = "test" * 100  # Reasonable size
    my_list.append(data)
    my_list.clear()
```

---

## Implementation Notes

- **False Positive Risk:** Legitimate large-scale data processing may trigger checks; require explicit `--allow-large-allocation` flag with justification
- **Bypass Prevention:** Checks operate on AST/source level before execution; obfuscation via `exec()` or `eval()` triggers separate code execution restrictions
- **Threshold Tuning:** Adjust iteration count (currently 100+) and data size (currently 1000 multiplier) based on environment constraints
- **Composition Detection:** Multiple weak signals (loop + append + tracemalloc + large strings/arrays/DataFrames/tuples) together = high confidence block