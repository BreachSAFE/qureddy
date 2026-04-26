# BreachSAFE QuReddy

> Open-source post-quantum cryptography readiness scanner.
> Find what's quantum-vulnerable. Generate a CBOM. Move on.

`qureddy` runs in your terminal. Apache 2.0. No signup. No telemetry.

> **Status: pre-MVP.** This README describes the v1.0 experience. None of the commands or installs below work yet. The first shipping milestone (MVP 0.1) implements only the TLS scanner. See [`CLAUDE.md`](CLAUDE.md) for the project spec and roadmap, and [`docs/mvp/CURRENT.md`](docs/mvp/CURRENT.md) for the active milestone.

---

## Quick Start

```bash
# Install (available at v1.0)
pipx install breachsafe-qureddy

# Scan a TLS endpoint
qureddy scan tls www.google.com

# Scan your local machine
qureddy scan local

# Export CBOM
qureddy report --format cbom > cbom.json
```

## What It Does

```bash
$ qureddy scan tls www.pecu.org

Scanning www.pecu.org:443...

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ www.pecu.org:443                                           ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃ Certificate      ECDSA P-256          ⚠️  QUANTUM VULNERABLE┃
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
