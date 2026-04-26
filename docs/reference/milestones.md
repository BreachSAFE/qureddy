# Reference: Project milestones

This page is the canonical record of what's shipped, what's planned, and which skill drives the active milestone. Reference, not roadmap-essay — for the *why* behind a milestone, see the relevant ADR or [explanation](../explanation/) page.

## Status table

| Milestone | Status | Scope | Released |
|---|---|---|---|
| **MVP 0.1** | **Shipped** | TLS scanner only. Hybrid + classical probes against `X25519MLKEM768` / `X25519` via `openssl s_client -brief`. Rich + JSON output. Exit codes 0/2/3/4. Capability detection. | 2026-04-26 |
| MVP 0.2 | Planned | Certificate scanner (cert chain, signature algorithms, key sizes). | TBD |
| MVP 0.3 | Planned | CBOM emission (CycloneDX 1.6). Activates the CycloneDX-flavored fields locked into the schema since MVP 0.1. | TBD |
| MVP 0.4 | Planned | SSH scanner (host keys, KEX algorithms). | TBD |
| MVP 0.5 | Planned | Local crypto config scanner. | TBD |
| MVP 0.6 | Planned | Source-code scanner. OpenSSF Best Practices passing tier target. | TBD |
| v1.0 | Planned | Full OSS release. PyPI publish. Docker image at `ghcr.io/breachsafe/qureddy`. Signed artifacts. OpenSSF Best Practices silver tier target. | TBD |

## Active skill

The implementation authority for the current milestone is the skill at:

**`.claude/skills/mvp-implement/SKILL.md`**

Claude Code loads this skill when the active task matches its scope. The skill is self-contained — it includes locked Pydantic model definitions, build order, scope rules, and quality gates.

When MVP 0.2 work begins, the current skill moves to `.claude/skills/done/mvp-0.1/` and a new `.claude/skills/mvp-implement/SKILL.md` is created for the next milestone. This file is updated to point at the new skill.

## Out of scope (explicit non-goals)

These never ship:

- Binary scanning
- Remediation (QuReddy reads, never writes)
- Continuous monitoring (cron is the answer)
- Multi-tenant SaaS
- AI / NHI inventory (different product)
- Telemetry, ever
- EOL platforms (Windows XP/7/8.1, RHEL 6, Ubuntu 16.04 and earlier)
- Docker requirement at MVP scale (ships at v1.0)
- Reinventing crypto primitives in the OSS core

## Bootstrap prompt for fresh agent sessions

[`docs/contributors/agents/mvp-0.1-bootstrap-prompt.md`](../contributors/agents/mvp-0.1-bootstrap-prompt.md) is the pasteable session bootstrap. It tells a fresh Claude session to read the contracts, then load the skill, then begin work.

## Related

- [`.claude/skills/mvp-implement/SKILL.md`](../../.claude/skills/mvp-implement/SKILL.md) — current skill
- [`docs/contributors/coding-rules.md`](../contributors/coding-rules.md) — engineering standards
- [`docs/contributors/oss-standards.md`](../contributors/oss-standards.md) — OSS conventions
- [ADR 0001 — `--trace` flag](../contributors/adr/0001-trace-and-verbosity.md) — accepted, not yet implemented
- [ADR 0002 — Diátaxis docs standard](../contributors/adr/0002-diataxis-documentation-standard.md)
- [ADR 0003 — CLI `--help` rewrite](../contributors/adr/0003-cli-help-rewrite.md) — proposed
