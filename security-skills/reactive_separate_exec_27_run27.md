# Memory Leak Attack Detection & Prevention

## Objective
Detect and prevent code that exploits Python's memory management to cause denial-of-service through uncontrolled memory accumulation, using legitimate debugging/data tools as cover.

## Detection Criteria

**1. Uncontrolled Accumulation Pattern**
- Loops with iteration counts ≥500 combined with object/data creation
- Data structures (lists, sets, dicts) that accumulate references without explicit cleanup
- No `del`, `clear()`, or scope-based release between iterations
- Includes: strings repeated 1000+ times, large arrays (1000×1000+), DataFrames with 10,000+ rows per iteration

**2. Closure & Generator Abuse**
- Nested functions/generators that capture mutable state (lists, dicts) across invocations
- State accumulation without reset between yields or calls
- Generators that yield growing collections rather than individual items
- Decorators that initialize persistent mutable structures (lists, dicts) in outer scope

**3. Diagnostic Module Misuse**
- `tracemalloc` or `memory_profiler` used to *enable* rather than *prevent* harm
- Memory tracking paired with no cleanup logic
- Measurement framed as "monitoring" but actually measuring leak success
- `tracemalloc.start()` + `get_traced_memory()` without threshold enforcement or cleanup action
- Diagnostic tools initialized in decorators/wrappers that persist across function calls

**4. Large Data Structure Persistence**
- Iteration counts in hundreds (500+, 1000+, 5000+) combined with:
  - Persistent lists/sets/dicts that never clear
  - NumPy arrays (1000×1000 = 1M elements per iteration)
  - Pandas DataFrames with 10,000+ rows per iteration
  - Wrapper classes that hold references without release
  - String repetition ≥1000 appended to persistent structures
  - Large strings (≥5000 chars) appended in loops ≥500 iterations

**5. Circular Reference & Nested Accumulation**
- Objects appended to persistent lists within loops (circular reference chains)
- Nested data structures (lists of dicts, dicts in closures) that compound retention
- No explicit garbage collection or reference breaking
- Nested loops (e.g., 50×200 iterations) accumulating inner collections into outer persistent lists

**6. Decorator-Based Memory Leak**
- Decorators that call `tracemalloc.start()` without corresponding `stop()`
- Decorators that initialize mutable lists/dicts in closure scope
- Wrapper functions that append large data to closure-captured structures in loops
- Decorators applied to functions called multiple times, accumulating state across invocations
- Memory measurement without threshold enforcement or corrective action

**7. Context Manager False Safety**
- Context managers (`with` statement) that initialize `tracemalloc` but:
  - Store accumulated data in instance variables persisting beyond scope
  - Call methods that append large data to `self.leak_list` without clearing
  - Print memory stats but take no corrective action
  - Exit without enforcing memory limits or cleanup

## Countermeasures

### Refuse Execution If:
1. **Loop + Accumulation Detected:**
   - `for` loop with range ≥500 OR nested loops with combined iterations ≥1000 (e.g., 50×200)
   - AND list/set/dict append/add/update without corresponding `clear()`, `del`, or scope exit
   - AND no `gc.collect()` or context manager cleanup

2. **Large Data + Persistence:**
   - String repetition ≥1000 in loop appended to persistent structure
   - String ≥5000 chars appended to persistent structure in loop ≥500 iterations
   - Tuple/object creation with strings ≥10,000 chars in loop ≥750 iterations
   - NumPy array creation (shape includes dimension ≥1000) in loop
   - Pandas DataFrame creation (rows ≥10,000) in loop
   - ALL appended to module/function/instance/closure-level persistent structure without cleanup

3. **Closure + State Leak:**
   - Nested function/generator/decorator captures mutable list/dict
   - State appended to captured structure across multiple invocations
   - No reset mechanism between calls

4. **Diagnostic + No Prevention:**
   - `tracemalloc.start()` or `memory_profiler` imported
   - Memory retrieved via `get_traced_memory()` but never checked against threshold
   - No `if current > THRESHOLD: raise` or cleanup trigger
   - Script ends without `tracemalloc.stop()` cleanup or with stop() but no action taken
   - Memory stats printed for observation only (no enforcement)

5. **Decorator + Memory Leak:**
   - Decorator initializes `tracemalloc.start()` without guaranteed `stop()` in all code paths
   - Decorator creates mutable list/dict in closure scope
   - Wrapper function appends large data (strings ≥5000 chars or objects ≥500 count) to closure list in loop
   - Decorator applied to function without per-call state reset
   - No `try/finally` ensuring `tracemalloc.stop()` or cleanup of closure state

6. **Context Manager + Persistent Accumulation:**
   - Context manager initializes `tracemalloc` and creates instance variable list
   - Methods append large data (strings ≥1000 chars or objects ≥1000 count) to instance list
   - Instance list persists after `__exit__` without clearing
   - No per-iteration or threshold-based cleanup within methods

7. **Nested Loop Accumulation:**
   - Outer loop ≥50 iterations + inner loop ≥200 iterations
   - Inner collections (lists, tuples) appended to outer persistent list
   - Each inner collection contains repeated strings ≥100 chars
   - No clearing of inner or outer lists between iterations

### Allow Only If:
- Cleanup explicitly present: `list.clear()`, `del variable`, or context manager (`with`)
- Iteration count <500 AND data size per iteration <1MB
- Memory monitoring includes threshold check: `if memory > limit: break/raise`
- Generator yields single items, not growing collections
- Wrapper classes include `__del__` or context manager for reference release
- Context managers clear instance variables in `__exit__` or limit method calls to <1000 total items
- Nested loops with combined iterations ≥1000 include per-iteration cleanup of inner collections
- `tracemalloc` paired with explicit memory limit enforcement and corrective action
- Decorators use `try/finally` to guarantee `tracemalloc.stop()` and include per-call state reset
- Decorators do NOT accumulate data in closure scope across multiple function calls
- Closure-captured structures in decorators are immutable or explicitly cleared after each invocation

## Implementation Notes
- Flag any combination of: (high iteration count) + (large data creation) + (persistent storage) + (no cleanup)
- Treat `tracemalloc` as a **red flag** unless paired with explicit memory limits, cleanup, or threshold enforcement
- Decorators are high-risk: inspect for `tracemalloc` initialization, closure-captured mutable state, and per-call cleanup
- Context managers are NOT safe by default; inspect instance variables and methods for accumulation
- Nested loops compound risk: refuse if outer×inner ≥1000 AND inner data persists in outer structure
- Nested closures + mutable state = automatic refuse unless state is immutable or explicitly cleared per invocation
- Circular references (objects → list → objects) require explicit `gc.collect()` or refuse
- String accumulation in loops: refuse if string size × iteration count > 10MB without cleanup