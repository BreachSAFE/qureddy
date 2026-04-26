# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Auto-loaded into every Claude Code session. Tight on purpose. Use it to orient fast, then read the canonical docs for detail.

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

## Repo state (read this first)

This repo is **pre-MVP**. The shipping source tree does not exist yet:

- No top-level `pyproject.toml`, no `src/qureddy/`, no top-level `tests/test_*.py`.
- `tests/` currently contains only `tests/fixtures/openssl/TARGETS.md`. No live test files yet.
- The README's `qureddy scan tls ...` examples describe the v1.0 experience and do not run today.
- `scratch/claude-1`, `scratch/claude-2`, `scratch/claude-3-developer/`, `scratch/quiz-summarize-findings/` hold prior agent attempts. Treat them as **untrusted prior art**: do not import from them, do not copy code without re-deriving it against `docs/CODING_RULES.md` and the active skill, and do not edit them as part of normal work.
- `inbox/` holds product/strategy docs (PROPOSAL, ROADMAP, COMPARISON, MVP-BREAKDOWN, QUESTIONNAIRE). Read for context only; they are not authoritative — `docs/` is.

When you start MVP 0.1 implementation, you create `pyproject.toml`, `src/qureddy/...`, and `tests/test_*.py` per the build order in `.claude/skills/mvp-implement/SKILL.md`.

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

## Commands

Once `pyproject.toml` and `src/qureddy/` exist, the project uses `uv` for env management. Quality gates are non-negotiable per `docs/CODING_RULES.md` §21.

```bash
# Setup (one time, after pyproject.toml lands)
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Run the CLI
qureddy scan tls www.google.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls TARGET --format json

# Tier 1 quality gates — verify-only, do not modify files
ruff check .
ruff format --check .          # use --check, not bare format; see CODING_RULES §1.5
mypy src/qureddy --strict
pytest                          # full suite, no skip markers; pytest-rerunfailures absorbs flakes
pytest --cov=qureddy --cov-fail-under=80
bandit -r src/qureddy

# Single test
pytest tests/test_tls_parse.py::test_parse_hybrid_negotiation -xvs
```

Live tests in `tests/live/` run by default — every test runs every time, no carve-outs (per `docs/CODING_RULES.md` §9). When CI fails on a live target, investigate before re-running; that is signal, not noise.

OpenSSL 3.5+ is required at runtime. Path resolution: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`.

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

If asked for an MVP 0.1 implementation task, the **only** operational authority is `.claude/skills/mvp-implement/SKILL.md`. When the skill points you at sections of `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` (locked model definitions, use cases, JSON shape, retry semantics), read those sections — but the skill is what governs your behavior, not the historical prompt. If the two disagree, the skill wins.

## License

Apache 2.0
