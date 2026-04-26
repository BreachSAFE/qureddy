# CLAUDE.md

Guidance for Claude Code when working in this repository. This file is the canonical project spec. Any drift between this and other docs gets resolved here first.

## Project

| | |
|---|---|
| **Name** | BreachSAFE QuReddy OSS |
| **Friendly name** | QuReddy |
| **Binary / CLI** | `qureddy` |
| **Repo** | `github.com/breachsafe/qureddy` |
| **PyPI package** | `breachsafe-qureddy` |
| **License** | Apache 2.0 |
| **Tagline** | QuReddy 0.1.0 — BreachSAFE OSS |

Open-source post-quantum cryptography readiness scanner. Find what's quantum-vulnerable. Generate a CBOM. Move on.

## Philosophy

- Local-first, offline-capable
- No SaaS, no signup, no telemetry
- Wrap proven OSS where the wrap is cheap (semgrep, ssh-audit); call OpenSSL directly for TLS because the wrap isn't cheap and the license isn't compatible
- CycloneDX 1.6 CBOM is the primary output
- HNDL scoring is the differentiator

## Roadmap

| Version | Scope |
|---|---|
| **MVP 0.1 (now)** | TLS scanner only. Python package via `uv` for dev, `pipx` for end users. Runs on Mac. No Docker. |
| **MVP 0.2** | Cert scanner added. |
| **MVP 0.3** | CBOM emission added. |
| **MVP 0.4** | SSH scanner added. |
| **MVP 0.5** | Config file scanner added. |
| **MVP 0.6** | Source code scanner added. |
| **v1.0** | Full OSS release: PyPI publish under `breachsafe-qureddy`, Docker image at `ghcr.io/breachsafe/qureddy`, GitHub Releases with signed artifacts, real documentation, CHANGELOG, Apache 2.0, community-ready. |
| **P2** | Enterprise tier: cloud scanners, runtime agents, SIEM integrations, continuous monitoring, multi-tenant, SSO, RBAC, support contracts, possibly managed SaaS. Docker is not the differentiator here. |

See `inbox/MVP-BREAKDOWN.md` for the granular milestone breakdown.

## Platform Support

| | |
|---|---|
| **Runs on** | macOS 14+, modern Linux, Windows 10 22H2+ (via WSL2 first; native Windows at v1.0) |
| **Distributed as** | `pipx install breachsafe-qureddy` (primary), `ghcr.io/breachsafe/qureddy:latest` Docker image (at v1.0) |
| **Scans** | Anything reachable on a network port, including legacy hosts. Legacy hosts are scanned *from* a modern machine, not *on* the legacy host. |

Mac first for MVP. Linux at v1.0. Windows at v1.0.

## Architecture

Eight decisions are pending Codex sign-off. Decisions marked **pending** must not be treated as settled in code.

| Component | Decision | Status |
|---|---|---|
| Language | Python 3.12+ | settled |
| Dev tooling | `uv` | settled |
| CLI framework | Typer + Rich | settled |
| Async | `asyncio` + `aiosqlite` | settled |
| TLS scanner | OpenSSL 3.5 subprocess via dedicated probe module | settled |
| CBOM library | `cyclonedx-python-lib` vs IBM CBOMkit | **pending Codex** |
| Templates | Jinja2 + Tailwind CDN, single-file HTML | settled |
| Storage | SQLite, **deferred until diff capability lands** | settled (deferred) |
| Severity model | Custom (severity + readiness axes) | **pending Codex defense** |

## Layout

```
qureddy/
├── CLAUDE.md              # This file (canonical spec)
├── AGENTS.md              # Contributor workflow
├── README.md              # Hero copy
├── LICENSE                # Apache 2.0
├── .gitignore
├── pyproject.toml         # Dependencies, managed by uv
├── inbox/                 # Planning docs (not shipped)
│   ├── COMPARISON.md
│   ├── MVP-BREAKDOWN.md
│   ├── PROPOSAL.md
│   ├── QUESTIONNAIRE.md
│   └── ROADMAP.md
├── src/qureddy/
│   ├── __init__.py
│   ├── __main__.py        # Entry point
│   ├── cli.py             # Typer CLI
│   ├── scanners/          # tls (MVP 0.1), then certs/ssh/config/code
│   ├── analysis/          # hndl, compliance
│   ├── output/            # cbom (MVP 0.3+), html (single-file, Tailwind CDN)
│   ├── store/             # sqlite, deferred until diff lands
│   └── policies/          # YAML compliance rules
├── tests/
│   ├── fixtures/          # Captured outputs, never live network
│   └── integration/       # Network-dependent, skipped by default
├── docs/                               # contributor + standards docs (run `ls docs/` for the live list)
│   ├── CODING_RULES.md                 # Python authoring rules
│   ├── AGENT_ANTIPATTERNS.md           # canonical agent contract
│   ├── CLAUDE_DEVELOPER_PROMPT.md      # general session prompt
│   ├── OSS_STANDARDS.md
│   └── mvp/                            # milestone implementation artifacts; CURRENT.md names the active one
└── examples/
```

## Stack

| Component | Tech | Notes |
|---|---|---|
| Language | Python 3.12+ | |
| Dev tooling | `uv` | |
| CLI | Typer + Rich | |
| Async | `asyncio` + `aiosqlite` | |
| TLS | OpenSSL 3.5 subprocess | dedicated probe module per docs/CODING_RULES.md |
| Certs | `cryptography` | |
| SSH | `ssh-audit` (subprocess) | |
| Code | `semgrep` (subprocess) | |
| CBOM | pending Codex pick | |
| Templates | Jinja2 + Tailwind CDN | single-file HTML |
| Storage | SQLite via `aiosqlite` | deferred until diff lands |

## Commands

```bash
# Dev setup
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

# Run
qureddy scan tls example.com:443

# Test
pytest
```

`qureddy report` and additional `scan` subcommands land in MVP 0.2 - 0.6 per the roadmap.

## Explicit Non-Goals

- No binary scanning
- No remediation
- No continuous monitoring (cron is the answer)
- No multi-tenant SaaS
- No AI/NHI inventory (different product)
- No telemetry, ever
- No running on EOL platforms (Windows XP/7/8.1, RHEL 6, Ubuntu 16.04)
- No cloud/SaaS features in OSS core
- No Docker requirement at MVP (ships at v1.0)
- No reinventing crypto primitives in the OSS core

## Governance

| Role | Who | Scope |
|---|---|---|
| Architect / reviewer | Codex | Architecture decisions, dependency picks, design defenses |
| Implementation hand | Claude | Code, docs, tests against the spec |
| Project lead | You | Final calls, scope, roadmap, vendor/license calls |

## Documents

See `docs/` for contributor and standards documentation. The active milestone prompt is named in `docs/mvp/CURRENT.md`.

Pre-v1.0 the repo will also need a `LICENSE`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `CHANGELOG.md`, `docs/ARCHITECTURE.md`, ADR set under `docs/architecture/`, and `.github/` plumbing (workflows, issue/PR templates). Add them when you write them, not before.

## Design Decisions (settled)

1. **OpenSSL 3.5 subprocess over sslyze** — sslyze is GPL; OpenSSL subprocess is license-compatible with Apache 2.0, and the OpenSSL CLI gives us deterministic, pinnable behavior across versions.
2. **SQLite over JSON for persistence** — Enables drift detection. Deferred until diff capability lands.
3. **Policy-as-YAML** — Compliance rules are data, not code.
4. **Typer over Click** — Modern, type-hinted.
5. **`uv` over pip** — Fast dependency resolution; lockfile is committed.
6. **Single-file HTML over PDF** — No WeasyPrint, no native dependencies. Tailwind via CDN.

## Related

- **QuSecure R3** — Enterprise competitor (we're the OSS alternative)
- **IBM CBOMkit** — Source code CBOM (we add network + endpoint; CBOMkit is also a candidate library, pending Codex)
- **ssh-audit** — We wrap this for the SSH scanner (MVP 0.4)
- **semgrep** — We wrap this for the code scanner (MVP 0.6)

## License

Apache 2.0
