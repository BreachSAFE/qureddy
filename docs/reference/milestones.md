# Project milestone reference

This page records shipped, verified, and planned scope. It does not treat a
planned milestone, open issue, or accepted design as a delivered artifact.

## Contents

- [Status definitions](#status-definitions)
- [Milestone table](#milestone-table)
- [Current release program](#current-release-program)
- [Non-goals](#non-goals)
- [Historical implementation material](#historical-implementation-material)
- [Decision records](#decision-records)
- [Related documentation](#related-documentation)

## Status definitions

| Status | Meaning |
| --- | --- |
| Shipped | Present in the package version and public source |
| Verified | Shipped behavior has named local, hosted, schema, or live proof |
| Release candidate | Code and metadata are staged for publication; registry rehearsal is incomplete |
| Planned | Tracked intent without a shipped implementation |

## Milestone table

| Milestone | Status | Scope | Evidence date |
| --- | --- | --- | --- |
| MVP 0.1 | Shipped | TLS 1.3 hybrid and classical control probes, Rich and JSON output, typed failures | Public `v0.1.0` tag, 2026-05-10 |
| MVP 0.2 | Shipped | Leaf certificate signature observation and legacy TLS 1.0, 1.1, and 1.2 enumeration | Current 0.2.13 source and tests |
| MVP 0.3 | Shipped and independently verified | CycloneDX 1.7 CBOM output with pinned schema, CLI, semantic, and determinism checks | Public PRs #48 and #51, 2026-07-27 |
| MVP 0.4 | Shipped | SSH and SFTP endpoint scanner with key exchange and host key observations | Public PR #22, 2026-07-23 |
| MVP 0.5 | Planned | Local cryptographic configuration scanner | No shipped artifact |
| MVP 0.6 | Planned | Source-code scanner | No shipped artifact |
| Packaging and TestPyPI | Release candidate | Installable wheel and source distribution, release gate, documentation, TestPyPI rehearsal | Public issues #33 through #36 |
| Enterprise P2 | Planned | Operated fleet, persistence, integrations, tenancy, and support | No shipped product in this repository |

## Current release program

The public release sequence is:

1. [#30](https://github.com/breachsafe/qureddy/issues/30): truthful green main,
   complete;
2. [#31](https://github.com/breachsafe/qureddy/issues/31): CycloneDX 1.7
   observation contract, complete;
3. [#32](https://github.com/breachsafe/qureddy/issues/32): independent CBOM
   conformance, complete;
4. [#33](https://github.com/breachsafe/qureddy/issues/33): package artifact
   proof, complete;
5. [#34](https://github.com/breachsafe/qureddy/issues/34): repository-owned
   local release gate, in progress;
6. [#35](https://github.com/breachsafe/qureddy/issues/35): documentation
   truth-up, in progress;
7. [#36](https://github.com/breachsafe/qureddy/issues/36): TestPyPI rehearsal,
   not started.

Publication is not complete until issue #36 records the registry installation
and rendering evidence.

## Non-goals

QuReddy does not provide:

- binary or firmware scanning;
- automated remediation;
- an always-on endpoint agent;
- AI or non-human identity inventory;
- hidden telemetry;
- support for end-of-life platforms;
- a hosted multi-tenant service in this repository.

## Historical implementation material

`.agents/skills/breachsafe-implement/SKILL.md` and
`docs/contributors/agents/mvp-0.1-bootstrap-prompt.md` describe the original
TLS-only implementation milestone. They are retained for history and are not
authority for the shipped SSH, CBOM, packaging, or release surfaces.

Current changes must follow the repository contributor rules, accepted ADRs,
public issue acceptance criteria, code, tests, and installed artifact
behavior.

## Maintainer decision records

Architecture decision records are maintained locally for contributors and are
not part of the customer documentation or release artifacts.

## Related documentation

- [Changelog](../../CHANGELOG.md)
- [Local release gate](../contributors/local-release-gate.md)
- [CBOM conformance](../contributors/cbom-conformance.md)
