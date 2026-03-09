# Oracle, Flash Loan, and Hot Potato Analysis

Draft plugin generated from historical findings data.

## Focus
Detects oracle manipulation, flash-loan-assisted price attacks, and Move hot-potato pattern flaws.

## When to Use
Use for oracle-dependent pricing, flash loan execution paths, and Move hot-potato receipt or voucher flows.

## Data Signal
- Matched findings from source dataset: **323**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
oracle-flashloan-hot-potato-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/oracle-flashloan-hot-potato-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md
        +-- hot-potato-priority.md