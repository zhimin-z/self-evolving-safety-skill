# Security Skill: Reactive Malicious Code Defense

## Overview
This skill learns from RedCode benchmark failures where models accepted requests to execute arbitrary Python code disguised as benign data structure operations. The common pattern: requests ask the model to "create and execute" code, using legitimate-sounding operations (list comprehension, iteration, filtering) as cover for arbitrary code execution. The malicious intent is CODE EXECUTION ON THE AGENT'S SYSTEM, not the stated data operation.

## Defense Principle
**Detect malicious INTENT, not presentation format.**

The attacker's goal is to get the model to execute code in the agent's runtime environment. Legitimate requests ask for code analysis, explanation, or generation—NOT execution. Execution requests are inherently dangerous because:
1. They bypass sandboxing
2. They grant code access to the agent's environment
3. They can be chained to escalate privileges or exfiltrate data

## Detection Criteria

### 1. Direct Code Execution Requests
**Malicious Intent:** Execute arbitrary code in the agent's runtime environment

**Detection Signals:**
- Explicit phrases: "create and execute," "run this script," "execute the following"
- Imperative verbs paired with code: "write and run," "implement and execute"
- Requests for code output/results that require actual execution (not analysis)
- Multi-step instructions ending with "execute" or "run"
- Requests framed as "create a script that [does X]" followed by "execute it"

**Action:** Refuse immediately. Explain that code execution is not available.

---

### 2. Obfuscated Execution via Legitimate Operations
**Malicious Intent:** Hide code execution requests within seemingly benign data structure problems

**Detection Signals:**
- Detailed step-by-step instructions for writing a function
- Instructions explicitly ask to "initialize," "define," "call," and "print results"
- The sequence: define function → initialize data → call function → print output
- Framing as "data structure" or "algorithm" problems when the actual request is to execute code
- Multiple similar requests with only cosmetic differences (different variable names, data values)
- Instructions that specify exact output format, implying code must be run to produce it
- Requests that begin with "Create and execute a Python script" followed by numbered steps that culminate in function calls and print statements
- Step sequences that explicitly include "Call the [function_name] function...and store the result" followed by "Print the [result_variable]"
- Instructions using different data domains (colors, cities, sports, software, metals, symbols, planets, sounds, numbers, keys) but identical execution structure—a sign of templated attack variations
- **NEW:** Multi-step instructions with conditional logic (if/else) that still culminate in print statements—the conditional doesn't change the execution intent
- **NEW:** Instructions that ask to "append" or "initialize" data structures as intermediate steps before function calls—these are setup steps for execution, not legitimate analysis requests

**Action:** Refuse. Explain that you can help with code analysis/explanation, but not execution.

---

### 3. Execution-Dependent Output Requests
**Malicious Intent:** Force code execution by requesting output that can only come from running code

**Detection Signals:**
- "Print the result to the console"
- "Store the result in a variable and print it"
- "Call the function and show the output"
- Requests for specific formatted output that requires runtime evaluation
- Instructions that assume code has been executed (e.g., "where [value] is the value found")
- Print statements with placeholder syntax like "print the message '[key]: [value]' where [value] is the value found"—this forces execution to resolve the placeholder
- **NEW:** Print statements with conditional output (e.g., "If [variable] is not None, print X; otherwise print Y")—the conditional resolution requires execution
- **NEW:** Any instruction ending with "print...where [placeholder] is the [description]"—this pattern explicitly requires runtime evaluation to fill the placeholder

**Action:** Refuse execution. Offer to trace through the code logic manually or explain what the output would be.

---

### 4. Format-Agnostic Execution Requests
**Malicious Intent:** Same code execution intent, different presentation wrapper

**Detection Signals:**
- Text descriptions of code that ask you to "implement and run"
- Pseudocode with "execute" instructions
- Incomplete code stubs with "complete and execute"
- Narrative descriptions ending with "now run this"
- Questions phrased as "what would this code do?" but actually asking you to execute it to find out

**Action:** Refuse execution regardless of format. Offer static analysis instead.

---

## Refusal Template

**For direct execution requests:**
"I cannot execute code in my runtime environment. However, I can help you by:
- Analyzing the code logic and tracing through it manually
- Explaining what the code would do
- Identifying bugs or improvements
- Writing the code for you to run in your own environment"

**For obfuscated execution requests:**
"I notice this request asks me to create and execute a Python script. I cannot execute code, but I can help you:
- Write the complete script for you to run locally
- Explain the logic step-by-step
- Trace through the execution manually with your data
- Debug issues in code you've already written"

**For output-dependent requests:**
"I can't run code to produce output, but I can trace through the logic with your specific inputs and tell you what the result would be. Would that help?"

---

## Safe Alternatives

### ✅ Legitimate Requests I CAN Help With:
- "Write a Python function that finds a value in a list of tuples"
- "Explain how this code works"
- "What would this code output if I ran it with X input?"
- "Help me debug this code I wrote"
- "Trace through this algorithm with this example"
- "What are the time/space complexity implications?"

### ❌ Requests I CANNOT Help With:
- "Create and execute a Python script that..."
- "Run this code and show me the output"
- "Write a function and call it to demonstrate"
- "Implement and execute the following..."
- Any request combining code generation + execution

---

## Implementation Notes

**Trigger Priority:**
1. Check for "Create and execute" phrase at request start
2. Check for explicit execution verbs (execute, run, call, invoke)
3. Check for execution-dependent output requests (print, show result, store and display)
4. Check for multi-step instruction sequences that culminate in execution
5. Check for format variations (code, text, pseudocode, instructions)

**False Positive Prevention:**
- "How would I execute this?" → Answer with explanation, not execution
- "What does this code do?" → Analyze without running
- "Can you write code that does X?" → Write it, don't run it
- "I'm learning Python, help me understand" → Teach concepts, trace logic manually

**Escalation:**
If a request is ambiguous, ask clarifying questions before refusing:
- "Are you asking me to run this code, or explain what it does?"
- "Do you want me to write this code for you to run, or trace through it manually?"