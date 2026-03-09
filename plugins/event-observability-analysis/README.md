# Event and Observability Analysis

Draft plugin generated from historical findings data.

## Focus
Finds missing or low-quality event emissions that break auditability and monitoring.

## When to Use
Use when findings mention missing events, non-indexed parameters, or weak on-chain observability.

## Data Signal
- Matched findings from source dataset: **221**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
event-observability-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/event-observability-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md