# BreachSAFE QuReddy

[![Status: Pre-MVP](https://img.shields.io/badge/status-pre--MVP-orange?style=flat-square)](docs/mvp/CURRENT.md)
[![Version](https://img.shields.io/badge/version-0.0.0--dev-lightgrey?style=flat-square)](CHANGELOG.md)
[![Milestone](https://img.shields.io/badge/milestone-MVP%200.1-blue?style=flat-square)](.claude/skills/mvp-implement/SKILL.md)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow?style=flat-square)](https://github.com/PyCQA/bandit)
[![OpenSSF Best Practices](https://img.shields.io/badge/OpenSSF-passing%20%28target%20MVP%200.6%29-yellow?style=flat-square)](https://www.bestpractices.dev/)
[![CI](https://img.shields.io/badge/CI-not%20yet%20wired-lightgrey?style=flat-square)](.github/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-%E2%89%A580%25%20required-brightgreen?style=flat-square)](pyproject.toml)
[![Conventional Commits](https://img.shields.io/badge/Conventional%20Commits-1.0.0-FE5196?style=flat-square&logo=conventionalcommits&logoColor=white)](https://www.conventionalcommits.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen?style=flat-square)](CONTRIBUTING.md)

> Open-source post-quantum cryptography readiness scanner.
> Find what's quantum-vulnerable. Generate a CBOM. Move on.

`qureddy` runs in your terminal. Apache 2.0. No signup. No telemetry.

> **Status: pre-MVP.** This README describes the v1.0 experience. None of the commands or installs below work yet. The first shipping milestone (MVP 0.1) implements only the TLS scanner. See [`CLAUDE.md`](CLAUDE.md) for the project spec and roadmap, and [`docs/mvp/CURRENT.md`](docs/mvp/CURRENT.md) for the active milestone.

---

## Quick Start

At MVP 0.1 there is no published package yet. Install from this directory:

```bash
git clone git@github.com:paul007ex/qureddy.git
cd qureddy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"

qureddy scan tls www.google.com
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls example.com
```

At v1.0 the published-package install path will be:

```bash
pipx install breachsafe-qureddy
qureddy scan tls www.google.com
qureddy report --format cbom > cbom.json
```

## What It Does

```bash
$ qureddy scan tls www.google.com

Scanning www.google.com:443...

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ www.google.com:443                                         ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Certificate      ECDSA P-256          ⚠️  QUANTUM VULNERABLE┃
┃ Key Exchange     X25519MLKEM768       ✅ TRANSITIONAL HYBRID┃
┃ Encryption       AES-256-GCM          ✅ QUANTUM SAFE       ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ HNDL Score       45/100               Grade: C             ┃
┃ Recommendation   Cert chain still RSA/ECDSA — migrate 2028 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

$ qureddy scan tls pq.cloudflareresearch.com

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ pq.cloudflareresearch.com:443                              ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Certificate      ECDSA P-256          ⚠️  QUANTUM VULNERABLE┃
┃ Key Exchange     X25519MLKEM768       ✅ TRANSITIONAL HYBRID┃
┃ Encryption       AES-256-GCM          ✅ QUANTUM SAFE       ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ HNDL Score       40/100               Grade: C             ┃
┃ Recommendation   On the PQ frontier; track ML-DSA certs    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

$ qureddy scan tls example.com

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ example.com:443                                            ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Certificate      RSA 2048             ⚠️  QUANTUM VULNERABLE┃
┃ Key Exchange     X25519               ⚠️  QUANTUM VULNERABLE┃
┃ Encryption       AES-256-GCM          ✅ QUANTUM SAFE       ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ HNDL Score       87/100               Grade: F             ┃
┃ Recommendation   Migrate to PQC by 2027                    ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## What It Scans

| Scanner | Discovers |
|---------|-----------|
| `tls` | Certificates, cipher suites, PQ groups |
| `ssh` | Host keys, KEX algorithms |
| `local` | Keychain (Mac), Cert Store (Win), ~/.ssh/ |
| `certs` | PEM/DER/P12 files |
| `code` | Hardcoded crypto in source |

## HNDL Risk Grades

| Grade | Score | Action |
|-------|-------|--------|
| **A** | 0-20 | Quantum-safe |
| **B** | 21-40 | Plan for 2030 |
| **C** | 41-60 | Migrate 2028 |
| **D** | 61-80 | Migrate 2027 |
| **F** | 81-100 | Migrate now |

## Output Formats

```bash
qureddy report --format cbom   # CycloneDX 1.6 (default)
qureddy report --format html   # Single-file HTML (Tailwind CDN)
qureddy report --format csv    # Spreadsheet
qureddy report --format md     # Markdown
```

## Compliance Mapping

- NIST FIPS 203/204/205
- NSA CNSA 2.0
- PCI DSS 4.0
- FFIEC / NCUA
- CMMC 2.0

## vs Others

| | sslyze | QuSecure R3 | **QuReddy** |
|-|--------|-------------|-------------|
| TLS scan | ✅ | ✅ | ✅ |
| SSH scan | ❌ | ❌ | ✅ |
| Local certs | ❌ | ❌ | ✅ |
| HNDL scoring | ❌ | ❌ | ✅ |
| CBOM output | ❌ | ✅ | ✅ |
| Drift detect | ❌ | ✅ | ✅ |
| Local-first | ✅ | ❌ | ✅ |
| Free | ✅ | ❌ | ✅ |

## Install

```bash
# pipx (recommended)
pipx install breachsafe-qureddy

# pip
pip install breachsafe-qureddy

# From source
git clone https://github.com/breachsafe/qureddy.git
cd qureddy && uv pip install -e .
```

## Requirements

- Python 3.12+
- macOS / Linux / Windows

## License

Apache 2.0

---

**QuReddy** — See your crypto. Score the risk. Ship the CBOM.
