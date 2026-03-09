# MoveSafe Skills (Draft)

This repository is a fast bootstrap of a security skills project, modeled after qs_skills-main and seeded by historical findings data.

## Author
- audit911
- Website: https://www.audit911.me/

## Data source
- Findings source: Moveval/audit.json/audit_platform/findings.jsonl
  - valid records: **6286**
  - invalid lines skipped: **47**
- AI findings source: Moveval/audit.json/audit_platform/ai_audit_findings.jsonl
  - valid records: **33**
  - invalid chunks skipped: **1**
- Total merged valid records: **6319**

## Included plugins
- **Governance and Centralization Analysis** (governance-centralization-analysis): matched **1297** findings
- **Event and Observability Analysis** (event-observability-analysis): matched **75** findings
- **Access Control and Initialization Analysis** (access-control-initialization-analysis): matched **735** findings
- **Input Validation and Arithmetic Safety** (input-validation-arithmetic-safety): matched **1315** findings
- **External Call and Token Compatibility** (external-call-token-compatibility): matched **375** findings
- **Signature and Replay Analysis** (signature-replay-analysis): matched **418** findings
- **Upgradeability and Storage Safety** (upgradeability-storage-safety): matched **219** findings
- **DoS, Gas, and Griefing Analysis** (dos-gas-griefing-analysis): matched **562** findings
- **Reentrancy and State Transition Analysis** (reentrancy-state-transition-analysis): matched **647** findings
- **Code Hygiene and Maintainability Analysis** (code-hygiene-maintainability-analysis): matched **917** findings
- **Oracle, Flash Loan, and Hot Potato Analysis** (oracle-flashloan-hot-potato-analysis): matched **348** findings
- **Move Object and PTBs Analysis** (move-object-ptbs-analysis): matched **3754** findings

## Notes
- Same vulnerability across different file paths is auto-compared in each skill references/cross-path-patterns.md.
- Move object and PTBs analysis is included in plugin move-object-ptbs-analysis.
- If PTBs findings are absent in a source scope, a PTBs template marked as pending is auto-generated.