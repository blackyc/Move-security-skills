# Reentrancy and State Transition Analysis

Draft plugin generated from historical findings data.

## Focus
Detects reentrancy risks by checking external call ordering and state transition invariants.

## When to Use
Use when contracts execute external calls before finalizing critical state changes.

## Data Signal
- Matched findings from source dataset: **642**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
reentrancy-state-transition-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/reentrancy-state-transition-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md