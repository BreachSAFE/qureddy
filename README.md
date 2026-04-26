# BreachSAFE QuReddy

[![Status: Alpha](https://img.shields.io/badge/status-alpha-blue?style=flat-square)](docs/reference/milestones.md)
[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=flat-square)](CHANGELOG.md)
[![Milestone](https://img.shields.io/badge/milestone-MVP%200.1%20shipped-brightgreen?style=flat-square)](docs/reference/milestones.md)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![CI](https://github.com/paul007ex/qureddy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/paul007ex/qureddy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/paul007ex/qureddy/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/paul007ex/qureddy/actions/workflows/codeql.yml)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen?style=flat-square)](pyproject.toml)
[![Docs: Diátaxis](https://img.shields.io/badge/docs-Diátaxis-purple?style=flat-square)](docs/README.md)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?style=flat-square&logo=conventionalcommits&logoColor=white)](https://www.conventionalcommits.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

> Open-source post-quantum cryptography readiness scanner.
> Find what's quantum-vulnerable. Generate a CBOM. Move on.

`qureddy` runs in your terminal. Apache 2.0. No signup. No telemetry.

> **Status: alpha (MVP 0.1 — TLS scanner).** The TLS scanner is shipping and works against real targets today. Cert scanning lands at MVP 0.2; CBOM emission at MVP 0.3; SSH at 0.4; the rest by v1.0. See [`docs/reference/milestones.md`](docs/reference/milestones.md) for the full roadmap.

---

## Quick Start

```bash
git clone https://github.com/paul007ex/qureddy.git
cd qureddy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

qureddy scan tls www.google.com
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls example.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

Requires Python 3.12+ and OpenSSL 3.5+. On macOS: `brew install openssl@3` and pass `--openssl $(brew --prefix openssl@3)/bin/openssl`.

For a hand-held first run see the [tutorial](docs/tutorials/your-first-scan.md).

## What it actually does today (MVP 0.1)

```text
$ qureddy scan tls www.google.com

QuReddy 0.1.0 by BreachSAFE OSS

┏━ QuReddy scan: tls://www.google.com:443 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ READY — PQ hybrid X25519MLKEM768 negotiated                                  ┃
┃ Monitor; certificate and signature chain remain classical (cert scanning     ┃
┃ lands at MVP 0.2).                                                           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

                Scan details
 schema_version    qureddy.scan.v1
 status            completed
 readiness         transitional_hybrid
 protocol          TLSv1.3
 cipher_suite      TLS_AES_256_GCM_SHA384
 hybrid probe      negotiated X25519MLKEM768
 classical probe   negotiated X25519
 findings          2
 attempts          2
```

```text
$ qureddy scan tls example.com

┏━ QuReddy scan: tls://example.com:443 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ NOT READY — classical only (X25519)                                          ┃
┃ Plan PQ migration. Move TLS termination behind an edge that supports         ┃
┃ X25519MLKEM768, or upgrade to OpenSSL 3.5+ with PQ groups enabled.           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

For machine-readable output, add `--format json` — see the [JSON schema reference](docs/reference/json-schema.md) and the [CI integration how-to](docs/how-to/json-output-for-ci.md).

For traceability, add `-vvv` — adds a "Commands run" panel showing the exact OpenSSL invocations.

## Documentation

Docs follow [Diátaxis](https://diataxis.fr) — pages are split by what the reader is trying to do. See [`docs/README.md`](docs/README.md) for the full layout.

| Quadrant | Use when | Start with |
|---|---|---|
| [Tutorials](docs/tutorials/) | Learning | [Your first PQ readiness scan](docs/tutorials/your-first-scan.md) |
| [How-to guides](docs/how-to/) | Doing a specific task | [Scan an IP with custom SNI](docs/how-to/scan-ip-with-sni.md), [JSON for CI](docs/how-to/json-output-for-ci.md) |
| [Reference](docs/reference/) | Looking something up | [CLI options](docs/reference/cli.md), [exit codes](docs/reference/exit-codes.md), [failure categories](docs/reference/failure-categories.md), [JSON schema](docs/reference/json-schema.md) |
| [Explanation](docs/explanation/) | Understanding why | [Why hybrid PQ?](docs/explanation/why-hybrid-pq.md), [HNDL](docs/explanation/hndl.md), [threat model](docs/explanation/threat-model.md) |

Contributing? See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`docs/contributors/`](docs/contributors/).

## Roadmap

| Milestone | Scope | Status |
|---|---|---|
| **MVP 0.1** | TLS scanner | **Shipped 2026-04-26** |
| MVP 0.2 | Certificate scanner (chain, signatures, key sizes) | Planned |
| MVP 0.3 | CBOM emission (CycloneDX 1.6) | Planned |
| MVP 0.4 | SSH scanner (host keys, KEX algorithms) | Planned |
| MVP 0.5 | Local crypto config scanner | Planned |
| MVP 0.6 | Source-code scanner. OpenSSF Best Practices passing tier target. | Planned |
| v1.0 | PyPI, Docker image, signed artifacts. OpenSSF silver tier target. | Planned |

Full milestone reference: [`docs/reference/milestones.md`](docs/reference/milestones.md).

## Compliance mapping (planned, not yet wired)

QuReddy outputs are designed to feed compliance reporting against:

- NIST FIPS 203 / 204 / 205
- NSA CNSA 2.0
- PCI DSS 4.0
- FFIEC / NCUA
- CMMC 2.0

The cross-reference tables land at MVP 0.3 alongside CBOM emission.

## vs other tools

| | [sslyze](https://github.com/nabla-c0d3/sslyze) | [testssl.sh](https://testssl.sh) | **QuReddy** |
|-|---|---|---|
| TLS scan | ✅ | ✅ | ✅ |
| Hybrid PQ detection | partial | partial | ✅ first-class |
| Cert scanning | ✅ | ✅ | MVP 0.2 |
| SSH scanning | ❌ | ❌ | MVP 0.4 |
| HNDL framing | ❌ | ❌ | ✅ first-class |
| CBOM output | ❌ | ❌ | MVP 0.3 |
| Local-first, no telemetry | ✅ | ✅ | ✅ |
| Apache 2.0 | partial (GPLv2) | GPLv2 | ✅ |

QuReddy's design point is **post-quantum readiness as the default lens**, not a side feature. `sslyze` and `testssl.sh` are excellent vulnerability scanners; QuReddy answers a narrower question (what's the PQ posture?) more clearly.

## Project guarantees

- **No telemetry, ever.** Outbound connections only to targets you explicitly scan.
- **Read-only.** No remediation, no writes, no auto-upgrades. QuReddy reports; humans act.
- **Locked JSON schema** at `qureddy.scan.v1`. Additive changes land in v1; breaking changes bump the version.
- **Quality bar**: ruff, mypy --strict, bandit (MEDIUM threshold), pip-audit (HIGH/CRITICAL block), reuse lint, deptry, gitleaks all green on every PR. Coverage ≥ 80%. See [`docs/contributors/coding-rules.md`](docs/contributors/coding-rules.md).

## Requirements

- Python 3.12+
- OpenSSL 3.5+ (path resolution: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`)
- macOS / Linux / Windows (CI matrix tests all three)

## License

Apache 2.0 — see [`LICENSE`](LICENSE) and [`LICENSES/`](LICENSES/). REUSE-compliant ([`REUSE.toml`](REUSE.toml)).

## Reporting

- **Bugs / feature requests**: [GitHub Issues](https://github.com/paul007ex/qureddy/issues)
- **Security vulnerabilities**: see [`SECURITY.md`](SECURITY.md)
- **Code of conduct**: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)

---

**QuReddy** — See your crypto. Score the risk. Ship the CBOM.
