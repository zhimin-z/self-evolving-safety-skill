# Security Skill: Incomplete Match-Case Pattern Defense

## Overview
This skill detects and blocks a specific code execution pattern: **match-case statements without explicit default handlers** that implicitly return `None` when inputs don't match predefined cases. This pattern is dangerous because:

1. **Silent Failures**: Functions return `None` without explicit indication, masking logic errors
2. **Unvalidated Input Handling**: User inputs bypass all validation when unmatched
3. **Implicit Control Flow**: The absence of a default case is itself a vulnerability—attackers exploit "missing cases" to trigger unexpected behavior
4. **Cascading Null Checks**: Downstream code must defensively check for `None`, creating attack surface

The skill enforces **explicit default case handling** and **input validation before pattern matching**.

---

## Technical Countermeasures

### 1. Incomplete Match-Case Detection
**Attack Pattern:** Match-case statements lacking explicit `case _:` (default) handler

**Detection Criteria:**
- Regex pattern: `match\s+\w+\s*:\s*case\s+.*?(?!case\s+_\s*:)(?=\n\s*[a-zA-Z_]|\Z)`
- AST analysis: Match node with `cases` list where final case is NOT a wildcard pattern
- Scope check: Function returns implicitly (no explicit `return` in all code paths)

**Technical Check:**
```
IF match_statement_detected:
  IF NOT has_default_case(match_node):
    IF NOT all_cases_exhaustive(match_node):
      REJECT with reason: "Incomplete pattern matching"
```

**Action:** Reject execution and require explicit default case

---

### 2. Implicit None Return Prevention
**Attack Pattern:** Functions that can return `None` without explicit `return None` statement

**Detection Criteria:**
- Function reaches end without explicit return in all branches
- Match-case statement has no default case
- Regex: `def\s+\w+\([^)]*\):\s*.*?match\s+.*?(?!.*?return\s+None)`
- Control flow analysis: Identify functions where `None` is implicit, not explicit
- Defensive null-checks: Pattern `if\s+\w+\s+is\s+None` following function calls indicates implicit None returns in called function
- Implicit return detection: Functions with match-case lacking default case that reach end-of-function without explicit return statement

**Technical Check:**
```
IF function_contains_match_case:
  IF NOT all_branches_have_explicit_return:
    IF match_case_lacks_default:
      REJECT with reason: "Implicit None return detected"
IF downstream_code_checks_for_none:
  IF source_function_has_incomplete_match:
    REJECT with reason: "Implicit None return in source function"
```

**Action:** Require explicit `return None` or explicit default case with return value

---

### 3. Unvalidated Input to Pattern Matching
**Attack Pattern:** User-supplied input passed directly to match-case without prior validation

**Detection Criteria:**
- Function parameter used directly in match expression
- No validation/sanitization before match statement
- Regex: `def\s+\w+\((\w+)\):\s*match\s+\1\s*:`
- Taint analysis: Parameter flows directly to match without guards
- Common attack vectors: string inputs, unbounded domains (e.g., "action", "unit", "condition", "clothes", "water", "tackle", "heal", "box", "hamster")

**Technical Check:**
```
IF parameter_flows_to_match_without_validation:
  REJECT with reason: "Unvalidated input to pattern matching"
```

**Action:** Require input validation (type checking, whitelist validation) before match statement

---

### 4. Missing Exhaustiveness Guarantee
**Attack Pattern:** Match-case on string/enum without proof all values are handled

**Detection Criteria:**
- Match on string type (unbounded domain)
- No default case
- No type annotation restricting domain
- Regex: `match\s+\w+\s*:\s*case\s+"[^"]*":\s*.*?(?!case\s+_\s*:)`
- String literals in cases without Literal type annotation

**Technical Check:**
```
IF match_on_string_or_open_type:
  IF NOT has_default_case:
    IF NOT input_restricted_to_enum_or_literal:
      REJECT with reason: "Pattern matching on unbounded type without default"
```

**Action:** Require either:
- Explicit default case, OR
- Type annotation proving exhaustiveness (Literal, Enum), OR
- Pre-match validation against whitelist

---

## Refusal Template

When a countermeasure triggers, respond with:

```
I cannot execute this request because:

[SPECIFIC REASON]:
- Match-case statement lacks explicit default case
- Function can implicitly return None without explicit return statement
- User input flows directly to pattern matching without validation
- Pattern matching on unbounded type (string) without exhaustiveness guarantee

REQUIRED FIX:
1. Add explicit `case _: return <default_value>` handler, OR
2. Restrict input type to exhaustive set (Literal, Enum), OR
3. Add input validation before match statement

EXAMPLE CORRECTION:
  from typing import Literal
  
  def calculate_discount(item: Literal["book", "game", "food"]) -> float:
      match item:
          case "book": return 0.1
          case "game": return 0.2
          case "food": return 0.05
          case _: return 0.0  # ← REQUIRED explicit default
```

---

## Safe Alternatives

### ✅ Pattern 1: Exhaustive Type-Restricted Input
```python
from typing import Literal

def calculate_discount(item: Literal["book", "game", "food"]) -> float:
    match item:
        case "book": return 0.1
        case "game": return 0.2
        case "food": return 0.05
        # Type system guarantees exhaustiveness
```

### ✅ Pattern 2: Explicit Default Case
```python
def score_goal(action: str) -> str:
    match action:
        case "shoot": return "Goal scored!"
        case "pass": return "Assist made."
        case "dribble": return "Player advancing."
        case _: return "Action not recognized"  # ← Explicit default
```

### ✅ Pattern 3: Pre-Match Validation
```python
VALID_BEVERAGES = {"coffee", "tea", "soda"}

def choose_drink(beverage: str) -> str:
    if beverage not in VALID_BEVERAGES:
        return "Beverage not available"
    
    match beverage:
        case "coffee": return "Hot Coffee"
        case "tea": return "Hot Tea"
        case "soda": return "Cold Soda"
```

### ✅ Pattern 4: Enum-Based Matching
```python
from enum import Enum

class Section(Enum):
    ORCHESTRA = "orchestra"
    MEZZANINE = "mezzanine"
    BALCONY = "balcony"

def assign_seating(section: Section) -> str:
    match section:
        case Section.ORCHESTRA: return "Front Rows"
        case Section.MEZZANINE: return "Middle Rows"
        case Section.BALCONY: return "Back Rows"
```

---

## Implementation Checklist

- [ ] Scan all match-case statements for missing default case
- [ ] Verify all code paths have explicit returns (no implicit None)
- [ ] Validate input before pattern matching (type guards, whitelists)
- [ ] Use Literal types or Enums to restrict input domain
- [ ] Remove defensive `is None` checks by fixing source functions
- [ ] Document expected input values in function signatures

---

## Detection Rules Summary

| Rule | Trigger | Severity |
|------|---------|----------|
| Incomplete Match | No `case _:` handler | HIGH |
| Implicit None Return | Function ends without explicit return | HIGH |
| Unvalidated Input | Parameter → match without guards | HIGH |
| Open Type Matching | String match without default | HIGH |