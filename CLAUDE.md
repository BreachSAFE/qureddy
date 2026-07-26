# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

Auto-loaded into every Claude Code session. Tight on purpose. Use it to orient fast, then read the canonical docs for detail.

## Project

| | |
|---|---|
| **Name** | BreachSAFE QuReddy OSS |
| **CLI** | `qureddy` |
| **Repo** | `github.com/breachsafe/qureddy` (canonical, public — org cutover done in #21). `github.com/paul007ex/qureddy` is a private mirror that lags behind. |
| **PyPI** | `breachsafe-qureddy` |
| **License** | Apache 2.0 |
| **Version** | Single-sourced from `pyproject.toml` (0.2.0 since the SSH scanner landed) |

Local-checkout gotcha: the git remote named `breachsafe` is canonical (PRs, issues, pushes go there); `origin` points at the stale `paul007ex` mirror. Don't push to `origin` expecting it to be the real repo.

Open-source post-quantum cryptography readiness scanner. Find what's quantum-vulnerable. Generate a CBOM. Move on.

## Repo state (read this first)

**Shipped:** MVP 0.1 (TLS scanner, 2026-04-26), MVP 0.2 initial (cert signature-algorithm detection + legacy TLS 1.0/1.1/1.2 sweep in the default scan), MVP 0.3 prototype (`--format cbom`, CycloneDX 1.6 via `cyclonedx-python-lib`), and the SSH scanner (`qureddy scan ssh`, raw-socket KEXINIT probe, no subprocess — shipped 2026-07, version bumped to 0.2.0). Note: `docs/reference/milestones.md` still lists SSH under "MVP 0.4 Planned" — known doc drift.

- `src/qureddy/` — 41 source modules: `cli.py`, `_branding.py`, `core/{models,errors,logging,policy,retry,status,targets}.py`, `output/{json,cbom,_styles}.py`, `output/console/` (renderer split into `render` + `_commands/_errors/_evidence/_tables/_verdict` per ADR 0005), `scanners/tls/` (openssl_probe, scanner, parse, _classify, _evidence, _summary, legacy_probe, _legacy_findings, cert_probe, cert_sig, _cert_findings, _net), `scanners/ssh/{probe,scanner,classify}.py`. Authoritative count: `find src/qureddy -name '*.py' | wc -l`.
- `tests/` — 17 unit test files + 1 live test file, ~290 tests collected, 80%+ coverage. Fixtures: 11 fake openssl shims under `tests/fixtures/openssl/fake/`, 8 captured `s_client -brief` fixtures under `tests/fixtures/openssl/`, cert fixtures under `tests/fixtures/certs/`. SSH tests use a real loopback TCP server, no fixtures on disk. Authoritative counts: `pytest --collect-only -q`.
- `pyproject.toml` is wired with the runtime + dev deps; `qureddy.cli:main` is the install-time entrypoint (translates Click usage errors to exit code 4 per the documented exit-code surface).
- `docs/` follows [Diátaxis](https://diataxis.fr) — see `docs/README.md` for the structure; ADR 0002 is the decision record.
- `scratch/` holds prior agent work and review artifacts. Gitignored. `scratch/claude-1`, `scratch/claude-2`, `scratch/claude-3-developer/`, `scratch/staging/claude-app/` are untrusted prior art — read for historical context only; do not import from them, do not edit them as part of normal work.

The current push is **PyPI release readiness (v1.0 track)**: green main, a tag-gated publish workflow with Trusted Publishing (issue #144 on staging), changelog/version coherence, and the launch-gate checklists (#49, #161, #162 on staging). See `docs/reference/milestones.md` for milestone scope and `.claude/skills/mvp-implement/SKILL.md` for the MVP implementation authority.

**Issue-tracker split (issue #161):** `paul007ex/qureddy` (private staging) holds the real backlog (~150 open issues); `breachsafe/qureddy` (public) has a fresh, curated tracker. When a doc or changelog cites an issue number, check which tracker it belongs to — public links to staging numbers 404.

## Where to look

Read these in priority order. Skim only the first; the rest you read when relevant.

| Doc | When to read |
|---|---|
| `CLAUDE.md` (this file) | Always (auto-loaded) |
| `docs/README.md` | When you need to figure out where docs live (Diátaxis quadrants). |
| `docs/contributors/coding-rules.md` | Before writing or reviewing code. Source of truth for engineering standards. |
| `docs/contributors/agent-antipatterns.md` | Before responding to any task. Pre-response audit checklist. |
| `docs/contributors/oss-standards.md` | When making decisions about repo hygiene, releases, or community. |
| `docs/contributors/examples.md` | Before writing the first file in a new module. Good vs bad code patterns for Pydantic models, tests, subprocess, logging, exceptions, docstrings, CLI, JSON output. |
| `docs/contributors/adr/` | When making or reviewing a load-bearing decision. ADRs 0001 (`--trace`), 0002 (Diátaxis), 0003 (`--help` rewrite), 0004 (multi-scanner architecture), 0005 (splitting oversized files). |
| `docs/reference/milestones.md` | When asked "what's shipped" or "what's next". |
| `.claude/skills/<skill>/SKILL.md` | When the active task matches a skill. Skills are loaded lazily. |
| `tests/fixtures/openssl/TARGETS.md` | When writing or extending TLS scanner tests. |

## Skills

Operational workflows live under `.claude/skills/`. Read each skill's `SKILL.md` only when the current task matches the skill's scope.

| Skill | Use when |
|---|---|
| `mvp-implement` | Implementing or extending MVP 0.1 scanner code |
| `surgical-fix` | Fixing one Python bug with a narrow test-first patch, coding-rules compliance, and anti-pattern audit |
| `audit-pr` | Preparing or finalizing a pull request |
| `run-quality-gates` | Running ruff/mypy/pytest/bandit and reporting results without modifying files |
| `write-test-fixture` | Capturing a new OpenSSL output fixture |
| `python-oss-crypto-reviewer` | Reviewing a proposed bug fix, PR diff, or another agent's code suggestion against correctness, security, and schema-stability standards |
| `validate-fix` | Verifying a PR actually resolves the linked issue (separate question from "do gates pass"); applies a `validation:claude:<verdict>` label |
| `audit-docs` | Auditing docs for drift against the working tree (stale ADR statuses, dangling refs, drifted counts, catalog mismatches). Read-only; produces a findings report. |
| `breachsafe-implement` | Writing/extending code in any BQP repo — narrow, test-first, issue-referenced scope |
| `breachsafe-quality-review` | Build/test/lint checks, PR diff audits, issue-resolution verification, doc-drift sweeps (audit-only) |
| `breachsafe-release` | Supply-chain + OSS release-readiness audit: PyPI publish readiness, Trusted Publishing/OIDC, Sigstore/SLSA, OpenSSF |
| `breachsafe-security-audit` | Crypto-correctness, side-channel, and dependency-soundness security review (audit-only) |
| `breachsafe-pqc-pm` | Cross-repo sequencing/prioritization spanning BQP components |

The five `breachsafe-*` skills are installed copies from the canonical library at `github.com/paul007ex/breachsafe-skills` — edit them there and re-run its `scripts/sync.py`, never edit the installed copies here (`scripts/drift_check.py` in that repo flags divergence).

See `.claude/skills/README.md` for the catalog.

## Roadmap

| Version | Scope |
|---|---|
| **MVP 0.1** | Shipped 2026-04-26. TLS scanner. Python via `uv`/`pipx`. Mac/Linux/Windows. No Docker. |
| **MVP 0.2** | Shipped (initial). Cert signature-algorithm detection + legacy-protocol sweep; full cert-chain/key-size analysis still open. |
| **MVP 0.3** | Shipped (prototype). CBOM via `--format cbom`; hardening (deterministic bom-refs, full protocol inventory) in open issues. |
| **MVP 0.4** | SSH scanner — shipped early as `scan ssh` (v0.2.0). |
| **MVP 0.5 - 0.6** | Config (0.5) and source-code (0.6) scanners. Planned. |
| **v1.0 (current push)** | Full OSS release: PyPI publish, Docker image at `ghcr.io/breachsafe/qureddy`, signed artifacts, full docs, community-ready. |
| **P2** | Enterprise tier (cloud scanners, SaaS, SIEM integrations, RBAC). Docker is not the differentiator. |

OpenSSF Best Practices Badge target: passing by MVP 0.6, silver by v1.0.

## Commands

The project uses `uv` for env management. Quality gates are non-negotiable per `docs/contributors/coding-rules.md` §21.

```bash
# Setup (once)
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Run the CLI
qureddy scan tls www.google.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls TARGET --format json
qureddy scan tls TARGET --format cbom     # CycloneDX 1.6 CBOM
qureddy scan ssh github.com               # SSH KEXINIT probe (no OpenSSL dependency)

# Tier 1 quality gates (full suite incl. pip-audit, deptry, reuse-lint)
just gates

# Or run individually — verify-only, do not modify files
ruff check .
ruff format --check .          # use --check, not bare format; see docs/contributors/coding-rules.md §1.5
mypy src/qureddy --strict
pytest                          # full suite, no skip markers; pytest-rerunfailures absorbs flakes
pytest --cov=qureddy --cov-fail-under=80
bandit -r src/qureddy

# Single test
pytest tests/test_tls_parse.py::test_parse_hybrid_negotiation -xvs
```

Live tests in `tests/live/` run by default — every test runs every time, no carve-outs (per `docs/contributors/coding-rules.md` §9). When CI fails on a live target, investigate before re-running; that is signal, not noise.

OpenSSL 3.5+ is required at runtime. Path resolution: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`.

## Settled architecture

Decisions marked **pending** in `docs/contributors/coding-rules.md` should not be treated as final.

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

## Conflict resolution and escape hatches

When instructions disagree, follow this priority order (from `docs/contributors/agent-antipatterns.md`). Name the conflict in your response — do not silently pick one side:

1. Hard security constraints (`docs/contributors/coding-rules.md` §26 security bar; refuse-insecure-shortcuts in §26.13)
2. System / harness / tool constraints
3. Repository documented rules (`docs/contributors/coding-rules.md`, `docs/contributors/agent-antipatterns.md`, this file)
4. The user's most recent instruction

The user can override docs (4 over 3) but cannot override security (4 cannot override 1). If the user asks for `verify=False`, `shell=True`, removed timeouts, or similar: refuse the shortcut and propose the secure alternative.

Two escape hatches exist when you must deviate from the rules — both go in your final response, not in code comments:

- `ANTIPATTERN ACCEPTED: <name>, because <reason>` — for an intentional rule violation. The known accepted one for MVP 0.1 is the CycloneDX-flavored fields on `Asset`/`Finding` (schema stability before CBOM emission).
- `ASSUMPTION: I am assuming X because the spec is silent on it. If wrong, change to Y.` — when the spec leaves a gap. Do not invent file paths, function names, or library APIs to fill it.

## How to start a session

If you are Claude Code starting a fresh session:

1. You have already read this file (auto-loaded).
2. Read `docs/contributors/agent-antipatterns.md` for the pre-response audit rules.
3. If the user names a task that matches a skill in `.claude/skills/`, read that skill's `SKILL.md` next.
4. Read `docs/contributors/coding-rules.md` before writing any code.
5. Begin work. Audit your output against `docs/contributors/agent-antipatterns.md` before each response.

If asked for an MVP 0.1 implementation task, the **only** operational authority is `.claude/skills/mvp-implement/SKILL.md`. The skill is self-contained — every use case, locked model, retry rule, JSON shape, and exit code lives inside it. The earlier monolithic prompt was removed from the public tree; if you genuinely need to see the original verbose draft for historical context, it is at `scratch/MVP-0.1-CLAUDE-PROMPT.md` (gitignored, local only).

## License

Apache 2.0
