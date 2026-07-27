# Architecture decision records

This ledger identifies the decision records under
`docs/contributors/adr/`. Status reflects current implementation evidence.
Historical records remain present when a later record supersedes part of a
decision.

## Contents

- [Decision ledger](#decision-ledger)
- [Historical number collision](#historical-number-collision)
- [Separate proposal series](#separate-proposal-series)
- [Status rules](#status-rules)

## Decision ledger

| File | Decision | Status |
| --- | --- | --- |
| [0001](0001-trace-and-verbosity.md) | Trace flag and verbosity refactor | Accepted; implementation incomplete |
| [0002](0002-diataxis-documentation-standard.md) | Diátaxis documentation standard | Accepted and in use |
| [0003](0003-cli-help-rewrite.md) | CLI help rewrite | Accepted and implemented |
| [0004](0004-multi-scanner-architecture.md) | Multi-scanner architecture | Accepted; implemented for TLS and SSH |
| [0005 CBOM](0005-cbom-schema-source-of-truth.md) | CycloneDX 1.6 producer decision | Accepted historically; producer version and attribution superseded by 0007 |
| [0005 size](0005-splitting-oversized-files.md) | Purpose-organized file splits | Accepted and adopted |
| [0006](0006-oss-vs-enterprise-split.md) | OSS and Enterprise boundary | Accepted |
| [0007](0007-cyclonedx-1.7-observation-contract.md) | CycloneDX 1.7 observation contract | Accepted and implemented |

## Historical number collision

Two accepted records were assigned `0005` before this ledger existed. Their
filenames and titles distinguish them:

- `0005-cbom-schema-source-of-truth.md`
- `0005-splitting-oversized-files.md`

The repository preserves both identifiers for historical traceability.
Renumbering either record would make existing commit, review, and document
references ambiguous. New records must use the next unused number.

## Separate proposal series

[`docs/adr/ADR-001-offline-cert-file-scan.md`](../../adr/ADR-001-offline-cert-file-scan.md)
predates this contributor ledger and remains a proposed offline scanner
decision. It is not the same record as contributor ADR 0001.

## Status rules

- `Accepted` records a decided architecture.
- `Implemented` requires current code or installed artifact evidence.
- `Proposed` is not shipped behavior.
- `Superseded` keeps the historical record and names the successor and exact
  decision scope.

Issue and pull request references must identify the canonical public
`breachsafe/qureddy` tracker. Pre-cutover staging numbers may appear as
unlinked historical text but must not be presented as public release evidence.
