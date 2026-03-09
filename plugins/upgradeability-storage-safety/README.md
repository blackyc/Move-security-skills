# Upgradeability and Storage Safety

Draft plugin generated from historical findings data.

## Focus
Detects unsafe proxy upgrades, storage layout risks, and initializer pitfalls.

## When to Use
Use for proxy, diamond, UUPS, transparent, beacon, and upgrade path reviews.

## Data Signal
- Matched findings from source dataset: **192**
- Source: Moveval/audit.json/audit_platform/findings.jsonl

## Structure
upgradeability-storage-safety/
|-- .claude-plugin/plugin.json
|-- README.md
+-- skills/upgradeability-storage-safety/
    |-- SKILL.md
    +-- references/
        |-- finding-signals.md
        +-- triage-checklist.md