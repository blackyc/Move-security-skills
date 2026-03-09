# Code Hygiene and Maintainability Analysis

Draft plugin generated from historical findings data.

## Focus
Finds hygiene issues that often correlate with security regressions in audits.

## When to Use
Use for cleanup passes: unused code, duplicate logic, typo or comment drift, and risky optimizations.

## Data Signal
- Matched findings from source dataset: **915**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
code-hygiene-maintainability-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/code-hygiene-maintainability-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md