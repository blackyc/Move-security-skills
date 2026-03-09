# Governance and Centralization Analysis

Draft plugin generated from historical findings data.

## Focus
Detects centralized control risks, unsafe ownership transfer, and over-privileged admin operations.

## When to Use
Use for owner/admin authority reviews, timelock and multisig checks, and centralization-risk findings.

## Data Signal
- Matched findings from source dataset: **527**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
governance-centralization-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/governance-centralization-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md