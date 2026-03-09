# Input Validation and Arithmetic Safety

Draft plugin generated from historical findings data.

## Focus
Targets missing parameter checks, precision loss, overflow edge cases, and slippage controls.

## When to Use
Use for value validation, math precision, boundary checks, and slippage logic.

## Data Signal
- Matched findings from source dataset: **1309**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
input-validation-arithmetic-safety/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/input-validation-arithmetic-safety/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md