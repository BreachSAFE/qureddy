# Project milestone reference

[![Diátaxis reference](https://img.shields.io/badge/Di%C3%A1taxis-reference-1f6feb?style=flat-square)](https://diataxis.fr/reference/)

This page records shipped, verified, and planned scope. It does not treat a
planned milestone, open issue, or accepted design as a delivered artifact.

## Contents

1. [Status definitions](#1-status-definitions)
2. [Milestone table](#2-milestone-table)
3. [Current release program](#3-current-release-program)
4. [Non-goals](#4-non-goals)
5. [Historical implementation material](#5-historical-implementation-material)
6. [Decision records](#6-decision-records)
7. [Related documentation](#7-related-documentation)

## 1. Status definitions

| Status | Meaning |
| --- | --- |
| Shipped | Present in the package version and public source |
| Verified | Shipped behavior has named local, hosted, schema, or live proof |
| Release candidate | Code and metadata are staged for publication; registry rehearsal is incomplete |
| Planned | Tracked intent without a shipped implementation |

## 2. Milestone table

| Milestone | Status | Scope | Evidence date |
| --- | --- | --- | --- |
| MVP 0.1 | Shipped | TLS 1.3 hybrid and classical control probes, Rich and JSON output, typed failures | Public `v0.1.0` tag, 2026-05-10 |
| MVP 0.2 | Shipped | Leaf certificate signature observation and legacy TLS 1.0, 1.1, and 1.2 enumeration | Current source and tests |
| MVP 0.3 | Shipped and independently verified | CycloneDX 1.7 CBOM output with pinned schema, CLI, semantic, and determinism checks | Public PRs #48 and #51, 2026-07-27 |
| MVP 0.4 | Shipped | SSH and SFTP endpoint scanner with key exchange and host key observations | Public PR #22, 2026-07-23 |
| MVP 0.5 | Planned | Local cryptographic configuration scanner | No shipped artifact or tracking milestone |
| MVP 0.6 | Planned | Source-code scanner | No shipped artifact or tracking milestone |
| Packaging and distribution | Shipped | Installable wheel and source distribution, local and CI release gates, published GHCR container image, TestPyPI distribution | Current release on TestPyPI and `ghcr.io/breachsafe/qureddy`. Publication to the public PyPI index is still pending |
| Enterprise P2 | Planned | Operated fleet, persistence, integrations, tenancy, and support | No shipped product in this repository |

The MVP labels above record the capability history. Current work is tracked in
GitHub milestones, listed in [§3](#3-current-release-program).

## 3. Current release program

The initial release sequence (issues #30 through #36: truthful green main, the
CycloneDX 1.7 observation contract, independent CBOM conformance, package artifact
proof, the repository-owned local release gate, documentation truth-up, and the
TestPyPI rehearsal) is complete. QuReddy ships its current releases to TestPyPI
and publishes a container image to GHCR.

Active work is tracked in GitHub milestones. This page intentionally does not
copy a versioned milestone table that would drift from the tracker; use the
linked milestones list for current names, owners, and state.

The always-current view is the
[milestones list](https://github.com/breachsafe/qureddy/milestones) and the
[public issue tracker](https://github.com/breachsafe/qureddy/issues). This table
records the milestones open when the page was last revised; treat the tracker as
the source of truth where they differ.

## 4. Non-goals

QuReddy does not provide:

- binary or firmware scanning;
- automated remediation;
- an always-on endpoint agent;
- AI or non-human identity inventory;
- hidden telemetry;
- support for end-of-life platforms;
- a hosted multi-tenant service in this repository.

## 5. Historical implementation material

The original TLS-only implementation milestone was captured in maintainer-local
working notes (`.agents/skills/breachsafe-implement/SKILL.md` and
`docs/contributors/agents/mvp-0.1-bootstrap-prompt.md`), which are kept out of the
public tree. They are historical and are not authority for the shipped SSH, CBOM,
packaging, or release surfaces.

Current changes must follow the repository contributor rules, accepted ADRs,
public issue acceptance criteria, code, tests, and installed artifact
behavior.

## 6. Decision records

Architecture decision records are maintained locally by the maintainer and are
not part of the public tree, customer documentation, or release artifacts.
Propose a decision that would change a documented rule or contract by opening a
public issue; the maintainer records the accepted decision in the local ledger.

## 7. Related documentation

- [Changelog](../../CHANGELOG.md)
- [Local release gate](../contributors/local-release-gate.md)
- [CBOM conformance](../contributors/cbom-conformance.md)
