# External Call and Token Compatibility

Draft plugin generated from historical findings data.

## Focus
Detects unsafe token interactions and compatibility issues with non-standard token behaviors.

## When to Use
Use for ERC20 integration, fee-on-transfer or rebase behavior, and external call safety.

## Data Signal
- Matched findings from source dataset: **345**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
external-call-token-compatibility/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/external-call-token-compatibility/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md