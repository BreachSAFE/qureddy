# Why QuReddy is open-core, and what that means

QuReddy is open-source — Apache 2.0, free forever — and BreachSAFE has a planned commercial product on top of it. This page explains why that split exists, where the line is drawn, and what it means for someone choosing whether to depend on QuReddy.

If you want a side-by-side capability matrix, see [editions](../reference/editions.md).
If you want the locked decision record, see [ADR 0006](../contributors/adr/0006-oss-vs-enterprise-split.md).

## The single principle

**OSS does the cryptographic work. Enterprise does the operational work.**

Anything that requires understanding cryptography — algorithms, parsers, verdict logic, schema design, output formats — stays in QuReddy OSS, free under Apache 2.0, forever.

Anything that requires running infrastructure — cloud APIs, SaaS hosting, SIEM connectors, fleet orchestration, compliance attestation reports — is BreachSAFE QuReddy Enterprise (the planned commercial product, P2 milestone).

That's it. One sentence, one line. Everything else in this page is the consequence.

## Why the line is drawn there

The cryptographic work is the part that benefits from being a public good. If QuReddy's verdicts ("this TLS endpoint negotiates X25519MLKEM768") are correct, they're correct for everyone — for the SRE auditing one server, for the security team running a fleet scan, for the regulator evaluating compliance. The algorithms don't change based on who's looking at them. A scanner that knows ML-KEM-768 properly should be available to everyone.

The operational work scales differently. Running a SaaS dashboard for 10,000 users needs servers, support, incident response, compliance evidence. Wiring QuReddy into Splunk HEC needs ongoing maintenance against API changes. Writing PCI DSS 4.0 attestation PDFs needs auditor relationships and template maintenance. None of that work belongs in a CLI tool you `pip install` from PyPI. None of it is a public good — it's a service.

This split is conventional in security tooling. The same line works for Snyk (OSS for individual developers, Enterprise for org-scale SDLC), Aqua (open-source Trivy for image scanning, Aqua Platform for enterprise context), Sysdig (open-source Falco for kernel observation, Sysdig Secure for runtime SaaS).

## What this means for someone evaluating QuReddy

### "Will the free version stay capable, or will you cripple it later to push paid?"

Apache 2.0 on the OSS edition is **permanent**. No "open core that became proprietary" rugpull. ADR 0006 makes this a project-level commitment that can only be revoked by a successor ADR through governance change — meaning a public, version-controlled decision visible in the repo. Anyone running QuReddy v0.1.x today will still be able to run it v5.x later, with the same Apache 2.0 license, with the same feature set or more. The free version doesn't get rate-limited, doesn't get feature-gated, doesn't start showing upsell prompts.

### "What's the catch?"

Three things, all visible up front:

1. **You handle your own infrastructure.** OSS is a CLI tool. If you want to scan a thousand endpoints, you write the loop. If you want results in Splunk, you wire it. If you want a dashboard, you build it.
2. **You handle your own compliance evidence.** OSS produces machine-readable JSON. Turning that into a PCI auditor's PDF is your work (or Enterprise's, if you'd rather pay).
3. **You handle your own support.** OSS has GitHub issues. Response times are best-effort. If you need an SLA, that's Enterprise.

If those three are non-issues for you, OSS does the whole job.

### "Is the OSS version a stripped-down demo?"

No. The cryptographic work is *the entire product*. Every scanner ships in OSS. Every output format ships in OSS. Every verdict the tool can produce, OSS can produce. Enterprise adds orchestration, persistence, and integrations — not capabilities.

The CycloneDX 1.6 CBOM emission (MVP 0.3) is in OSS. The NIST / CNSA / PCI / FFIEC / CMMC compliance mappings are in OSS. The hybrid PQ detection is in OSS. The classical control probe is in OSS. The exit-code contract, the JSON schema, the `--format json` for CI integration — all OSS.

What's *not* in OSS: scanning your whole AWS account in one command. Running QuReddy results through your SIEM. Generating an attestation PDF formatted for your auditor. Drift detection over 90 days of historical scans.

### "What stops you from changing the line later?"

Three things:

1. **The license.** Code released under Apache 2.0 stays Apache 2.0. The repo's history is permanent — anyone can fork what's already public.
2. **The ADR.** Decisions are recorded in `docs/contributors/adr/`. Changing the line requires a successor ADR with the same level of rigor — public reasoning, alternatives considered, consequences documented. Not a unilateral business decision in a closed meeting.
3. **The relationship with the audience.** QuReddy's reason to exist is making PQ readiness checkable by anyone who needs to check it. A scanner that's only accessible to paying customers stops being credible as a security tool. The credibility erosion would be worse for BreachSAFE than the lost revenue.

These don't make the OSS commitment unbreakable in theory. They make breaking it expensive, public, and self-defeating.

## What this means for contributors

If you're submitting a feature, ask: does this require understanding cryptography, or does this require running infrastructure?

| Feature | Side | Why |
|---|---|---|
| Parsing a new TLS group name | OSS | Cryptographic |
| Adding a new policy rule | OSS | Cryptographic |
| Supporting a new CycloneDX field | OSS | Cryptographic |
| Reading a new SBOM format | OSS | Cryptographic / parsing |
| Adding a `--targets-file FILE` flag for batch input | OSS | Edge — batch input is operational, but a flag on a CLI is small enough to belong in the tool |
| Cloud API integration to scan AWS ACM | Enterprise | Operational + credential handling |
| Persistent storage of scan history | Enterprise | Operational |
| Splunk HEC connector | Enterprise | Operational |
| Compliance attestation PDF | Enterprise | Operational + auditor relationship |

If your feature is on the OSS side, open a PR. If your feature is on the Enterprise side, file an issue describing the use case — it informs the Enterprise roadmap, but the implementation won't land in the public repo.

When the line is genuinely ambiguous (as `--targets-file` is in the table above), reviewers default to OSS for small, well-scoped additions and Enterprise for anything requiring sustained infrastructure work.

## What this means for the project lifecycle

The OSS edition is the *credibility layer*. It's where the tool gets evaluated, where bugs get found, where the cryptography gets reviewed by people who know cryptography. It can't be subordinate to Enterprise — Enterprise depends on OSS being good enough to trust.

The Enterprise edition is the *sustainability layer*. It's where BreachSAFE captures value from operational work that doesn't make sense to give away. The revenue from Enterprise funds continued OSS development (the maintainer's time is finite; commercial revenue lets it be spent on QuReddy instead of a separate day job).

Both layers depend on the line being drawn correctly and held. That's why this is an ADR — not a marketing decision someone made on a slide.

## Related

- [Reference: Editions](../reference/editions.md) — capability matrix
- [ADR 0006 — OSS vs Enterprise split](../contributors/adr/0006-oss-vs-enterprise-split.md) — the locked decision
- [Reference: Project milestones](../reference/milestones.md) — where P2 (the Enterprise milestone) sits on the roadmap
- [Threat model and scope](threat-model.md) — what QuReddy assumes about the operator, network, target (independent of edition)
- [Why hybrid post-quantum?](why-hybrid-pq.md) — the cryptographic basis that's the same in both editions
