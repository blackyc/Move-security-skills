# Signature and Replay Analysis

Draft plugin generated from historical findings data.

## Focus
Detects signature replay, nonce handling flaws, and domain separation mistakes.

## When to Use
Use for EIP-712, permit-like flows, meta-transactions, and off-chain authorization.

## Data Signal
- Matched findings from source dataset: **415**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
signature-replay-analysis/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/signature-replay-analysis/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md