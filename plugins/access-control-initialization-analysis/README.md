# Access Control and Initialization Analysis

Draft plugin generated from historical findings data.

## Focus
Detects missing authorization checks and unsafe initializer patterns.

## When to Use
Use for role checks, permission boundaries, initializer front-run risk, and auth consistency.

## Data Signal
- Matched findings from source dataset: **952**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
access-control-initialization-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/access-control-initialization-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md