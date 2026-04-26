# CLAUDE.md

Auto-loaded into every Claude Code session in this repo. Tight on purpose. Use it to orient fast, then read the canonical docs for detail.

## Project

| | |
|---|---|
| **Name** | BreachSAFE QuReddy OSS |
| **CLI** | `qureddy` |
| **Repo** | `github.com/paul007ex/qureddy` (will move to `github.com/breachsafe/qureddy` at v1.0) |
| **PyPI** | `breachsafe-qureddy` |
| **License** | Apache 2.0 |
| **Tagline** | QuReddy 0.1.0 — BreachSAFE OSS |

Open-source post-quantum cryptography readiness scanner. Find what's quantum-vulnerable. Generate a CBOM. Move on.

## Where to look

Read these in priority order. Skim only the first; the rest you read when relevant.

| Doc | When to read |
|---|---|
| `CLAUDE.md` (this file) | Always (auto-loaded) |
| `docs/CODING_RULES.md` | Before writing or reviewing code. Source of truth for engineering standards. |
| `docs/AGENT_ANTIPATTERNS.md` | Before responding to any task. Pre-response audit checklist. |
| `docs/OSS_STANDARDS.md` | When making decisions about repo hygiene, releases, or community. |
| `.claude/skills/<skill>/SKILL.md` | When the active task matches a skill. Skills are loaded lazily. |
| `tests/fixtures/openssl/TARGETS.md` | When writing or extending TLS scanner tests. |

## Skills

Operational workflows live under `.claude/skills/`. Read each skill's `SKILL.md` only when the current task matches the skill's scope.

| Skill | Use when |
|---|---|
| `mvp-implement` | Implementing or extending MVP 0.1 scanner code |
| `audit-pr` | Preparing or finalizing a pull request |
| `write-test-fixture` | Capturing a new OpenSSL output fixture |

See `.claude/skills/README.md` for the catalog.

## Roadmap

| Version | Scope |
|---|---|
| **MVP 0.1 (now)** | TLS scanner only. Python via `uv`/`pipx`. Mac/Linux/Windows. No Docker. |
| **MVP 0.2 - 0.6** | Cert (0.2), CBOM (0.3), SSH (0.4), config (0.5), source-code (0.6) scanners. |
| **v1.0** | Full OSS release: PyPI publish, Docker image at `ghcr.io/breachsafe/qureddy`, signed artifacts, full docs, community-ready. |
| **P2** | Enterprise tier (cloud scanners, SaaS, SIEM integrations, RBAC). Docker is not the differentiator. |

OpenSSF Best Practices Badge target: passing by MVP 0.6, silver by v1.0.

## Settled architecture

Decisions marked **pending** in `docs/CODING_RULES.md` should not be treated as final.

| Component | Decision |
|---|---|
| Language | Python 3.12+ |
| Dev tooling | `uv` |
| CLI | Typer + Rich |
| Async | `asyncio` + `aiosqlite` (storage deferred until diff capability lands) |
| TLS scanner | OpenSSL 3.5 subprocess via dedicated probe module (`scanners/tls/openssl_probe.py`) |
| Templates | Jinja2 + Tailwind CDN, single-file HTML |
| Logging | `structlog` |
| Testing | `pytest` + `pytest-rerunfailures` (3 retries, 1s delay, every test runs every time) |

## Explicit non-goals

- No binary scanning
- No remediation
- No continuous monitoring (cron is the answer)
- No multi-tenant SaaS
- No AI/NHI inventory (different product)
- No telemetry, ever
- No EOL platforms (Windows XP/7/8.1, RHEL 6, Ubuntu 16.04 and earlier)
- No Docker requirement at MVP (ships at v1.0)
- No reinventing crypto primitives in the OSS core

## Governance

| Role | Who | Scope |
|---|---|---|
| Architect / reviewer | Codex | Architecture decisions, dependency picks, design defenses |
| Implementation hand | Claude | Code, docs, tests against the spec |
| Project lead | Paul Volosen | Final calls, scope, roadmap, vendor/license calls |

## How to start a session

If you are Claude Code starting a fresh session:

1. You have already read this file (auto-loaded).
2. Read `docs/AGENT_ANTIPATTERNS.md` for the pre-response audit rules.
3. If the user names a task that matches a skill in `.claude/skills/`, read that skill's `SKILL.md` next.
4. Read `docs/CODING_RULES.md` before writing any code.
5. Begin work. Audit your output against `docs/AGENT_ANTIPATTERNS.md` before each response.

If asked for an MVP 0.1 implementation task, the operational authority is `.claude/skills/mvp-implement/SKILL.md`. The previous monolithic prompt in `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` has been migrated into that skill.

## License

Apache 2.0
