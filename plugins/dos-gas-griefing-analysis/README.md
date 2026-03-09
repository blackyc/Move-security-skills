# DoS, Gas, and Griefing Analysis

Draft plugin generated from historical findings data.

## Focus
Detects denial-of-service vectors, gas griefing, and unbounded complexity paths.

## When to Use
Use for loops over dynamic sets, gas-sensitive logic, and liveness risk reviews.

## Data Signal
- Matched findings from source dataset: **551**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
dos-gas-griefing-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/dos-gas-griefing-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md