# ADR 0006 — OSS vs Enterprise split

**Status:** Accepted
**Date:** 2026-05-10
**Deciders:** Paul Volosen (project lead)
**Consulted:** Claude (review)
**Informed:** BreachSAFE co-founder
**Supersedes:** none
**Superseded by:** none

---

## Context

QuReddy ships under Apache 2.0 with no commercial gate today. The README is the only public statement of what the project is. Several internal references hint at a future split — `CLAUDE.md`'s Roadmap section mentions a `P2` "Enterprise tier (cloud scanners, SaaS, SIEM integrations, RBAC)" — but no doc defines:

- What the line between OSS and Enterprise actually is
- Which features stay free forever vs which become paid
- Which features will never ship in either edition
- What "Enterprise" means as a product (separate offering? same package with feature flags? hosted service?)

Without that locked, two failure modes follow:

1. **Contributor confusion.** A contributor offering a feature can't tell whether it belongs in OSS or whether it crosses into commercial scope.
2. **User confusion.** Operators evaluating QuReddy can't tell whether the tool is going to stay free or become locked down later. That uncertainty kills OSS adoption.

This ADR locks the design so future contributors apply the same line without re-litigating it per PR.

## Decision

**Adopt an open-core model with one explicit principle: OSS does the cryptographic work; Enterprise does the operational work.**

Anything that requires understanding cryptography — algorithms, parsers, verdict logic, schema design, output formats — stays in QuReddy OSS, free under Apache 2.0, forever. Anything that requires running infrastructure — cloud APIs, SaaS hosting, SIEM connectors, support contracts, compliance attestations — is BreachSAFE Enterprise.

### Concretely for QuReddy

**OSS forever (Apache 2.0, no feature gates):**

- All scanners — TLS (shipped), certificate (MVP 0.2), CBOM (MVP 0.3), SSH (MVP 0.4), local config (MVP 0.5), source code (MVP 0.6)
- All output formats — Rich console, JSON, CycloneDX 1.6 CBOM, HTML, CSV, Markdown
- Single-target operation — `qureddy scan tls foo.com` and equivalents for every scanner
- All policy rules — the hardcoded MVP 0.1 rules and their evolution
- Locked JSON schema — `qureddy.scan.v1` and forward
- Local-first operation — no SaaS dependency, no telemetry
- All file parsers — PEM, DER, P12, SBOM consumption, source-code AST
- CLI surface — every flag, every default
- Documentation — Diátaxis-organized, public
- Cross-platform support — macOS, Linux, Windows

**Enterprise (BreachSAFE QuReddy Enterprise — separate product, P2 milestone):**

- **Cloud scanners** — AWS / Azure / GCP API integration for fleet-scale TLS endpoint, ACM cert, KMS key, and Key Vault scanning. Requires cloud credentials, API rate-limit handling, multi-account orchestration.
- **Fleet / batch operation** — scan 10,000+ endpoints from CSV, VPC inventory, or asset-management system with deduplication, parallelism, scheduling, persistent state.
- **SaaS dashboard** — multi-user, multi-tenant, role-based, SSO/SAML, drift detection over time, historical posture, alerting.
- **SIEM integrations** — Splunk HEC, Datadog, Elastic, Microsoft Sentinel, ServiceNow connectors with delivery guarantees and replay.
- **Custom rule packs** — non-public policy rules for customer-specific compliance frameworks beyond the public NIST / CNSA / PCI / FFIEC / CMMC mappings.
- **Compliance attestation reports** — formatted PDF deliverables for auditor consumption against PCI DSS 4.0, FFIEC, CMMC 2.0, etc.
- **Support contracts** — SLAs, dedicated support channel, prioritized bug fix routing.

**Never shipped (in either edition):**

- Binary scanning of `.exe` / `.dll` / `.jar` / firmware — crowded space, dual-use risk, different problem domain. Use other tools.
- Remediation — QuReddy reads, never writes
- Continuous monitoring agent — cron is the answer
- AI/NHI inventory — different product
- Telemetry — not in OSS, not in Enterprise, not ever
- Multi-tenant SaaS as the *only* offering — Enterprise is on top of the OSS, not instead of it

### Naming

| Name | What it refers to |
|---|---|
| **BreachSAFE** | The parent company (Austin, TX). [breachsafe.ai](https://www.breachsafe.ai). |
| **QuReddy** | The open-source PQC readiness scanner — this repository, this CLI, this PyPI package. Apache 2.0. |
| **BreachSAFE QuReddy Enterprise** | The planned commercial product line (P2 milestone). Operational features layered on top of QuReddy OSS. |

The OSS package keeps the name `breachsafe-qureddy` on PyPI (signaling the parent without locking the project to a single product). The Enterprise product, when it ships, gets distributed separately — not via the OSS PyPI package.

### Trust differentiators that hold across both editions

These are project-level commitments, not edition-level features:

- **No telemetry** in either edition
- **Read-only** in either edition
- **Local-first by default** — Enterprise *can* talk to cloud APIs, but only when the operator explicitly invokes a cloud scanner
- **Open data formats** — every Enterprise output is CycloneDX, OSCAL, SARIF, or equivalent open standard; no proprietary file formats
- **Apache 2.0 for the OSS portion is permanent** — no "open core that became proprietary" rugpull. The OSS edition cannot be moved off Apache 2.0 without project-level governance change documented in a successor ADR.

## Consequences

### What changes

- A new `docs/explanation/oss-vs-enterprise.md` describes the philosophy and the line for users and contributors.
- A new `docs/reference/editions.md` is the side-by-side capability matrix — what's in OSS, what's in Enterprise, what's never shipped.
- `docs/reference/milestones.md` is updated to cross-link the editions reference at the row mentioning P2.
- `docs/README.md` lists the two new pages under their Diátaxis quadrants.
- README.md and other public-facing files are **not changed** in this ADR — that's a separate PR after this lands and after the Enterprise product has concrete substance to point at.

### What does not change

- The current code base — no scanners added or removed, no feature flags introduced.
- The PyPI package — `breachsafe-qureddy` stays as the OSS package name; Enterprise will ship under a different distribution name.
- The license — Apache 2.0 on the OSS edition is permanent (see "Trust differentiators" above).
- Any existing user's experience — every feature that ships today stays free.

### What gets harder

- Contributors offering features that fall on the Enterprise side will need to be redirected. This ADR + the editions reference give reviewers a clear basis for that conversation.
- The line "OSS does crypto, Enterprise does ops" is bright but not perfect at the boundary. Some features (e.g. parallel scan orchestration) are operational but small enough to belong in OSS. Edge cases require judgment; the editions reference will accumulate clarifying notes.
- Marketing / positioning must reinforce the line. If the README starts implying "QuReddy is enterprise-grade" without distinguishing OSS from Enterprise, the line erodes. Hold the README to "QuReddy OSS is X; QuReddy Enterprise (planned, P2) adds Y" framing.

## Alternatives considered

### Alternative 1 — Single-tier OSS forever, no commercial product

Stay 100% open source. Sustain via grants, sponsorship, donations, dual-employment.

**Rejected.** The work to build cloud scanners, SaaS dashboards, SIEM connectors, and compliance attestations is substantial and ongoing. Sustaining that level of build-out without commercial revenue means it either doesn't happen (capability ceiling) or the maintainer's day job subsidizes it indefinitely (burnout risk). Open-core lets the commercial side fund the OSS side.

### Alternative 2 — Closed-core with OSS demo / community edition

Build the full product proprietary, release a stripped-down "Community Edition" with feature gates.

**Rejected.** This is the model that produces "OSS" projects nobody uses because the free version is artificially crippled. Operators evaluating QuReddy need the full scanner suite to be production-viable, or they'll pick `sslyze` / `testssl.sh` / nothing. Crippling the free version kills the OSS adoption that makes the commercial product credible.

### Alternative 3 — Open-core but with capability-tier OSS limits (e.g. "5 scans/day free")

Like Snyk: free for hobbyists, rate-limited to push paid adoption.

**Rejected.** Rate limits in a CLI tool that runs locally make no sense — there's no server to enforce them, and any enforcement would require telemetry (forbidden by trust commitment). Rate limits work for SaaS, not for installable CLIs.

### Alternative 4 — Two separately-licensed packages (OSS Apache 2.0, Enterprise proprietary) with no shared code

Build a wholly separate proprietary tool that uses the same name and brand but no shared codebase.

**Rejected.** Duplicates the engineering work, drifts in behavior, and confuses users. The chosen open-core model has Enterprise *extend* the OSS package (depend on it as a library + add commercial features) rather than fork it.

### Alternative 5 — Dual-license (AGPL OSS, commercial for proprietary use)

License OSS under AGPL to force enterprise users to either contribute back or pay for a commercial license.

**Rejected.** AGPL is incompatible with how security tools are typically deployed (often in restrictive environments where AGPL's network-use trigger creates legal questions). Apache 2.0 is the convention in the security-scanner space — `sslyze` MIT, `testssl.sh` GPLv2 with explicit license-compatibility statements — and the audience expects it.

## Implementation

This ADR lands in the same PR as `docs/explanation/oss-vs-enterprise.md` and `docs/reference/editions.md`. No code changes. README.md is not touched in this PR — that's a separate change after the Enterprise product has concrete substance to point at.

## Acceptance criteria

- [x] `docs/contributors/adr/0006-oss-vs-enterprise-split.md` (this file) exists with Status: Accepted
- [ ] `docs/explanation/oss-vs-enterprise.md` describes the philosophy and the line
- [ ] `docs/reference/editions.md` is the side-by-side capability matrix
- [ ] `docs/reference/milestones.md` cross-links to editions.md
- [ ] `docs/README.md` lists the new pages
- [ ] `reuse lint` passes (file moves can break SPDX coverage)
- [ ] PR description references this ADR

## Related

- [`docs/contributors/plans/0001-pypi-launch.md`](../plans/0001-pypi-launch.md) — the launch this framing must be locked before
- [`docs/contributors/plans/0002-mvp-0.1-to-0.2-sequencing.md`](../plans/0002-mvp-0.1-to-0.2-sequencing.md) — the engineering sequencing this is parallel to
- [`docs/reference/milestones.md`](../../reference/milestones.md) — the P2 milestone this gives substance to
- [ADR 0002 — Diátaxis documentation standard](0002-diataxis-documentation-standard.md) — the structure this ADR's docs follow
- [ADR 0004 — Multi-scanner architecture](0004-multi-scanner-architecture.md) — the architectural decision that makes multi-scanner ops (the Enterprise tier's main feature) feasible
