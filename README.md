# BreachSAFE QuReddy

[![Version](https://img.shields.io/badge/version-0.1.0-blue?style=flat-square)](CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)

QuReddy scans a TLS endpoint and tells you where it stands on the move to
post-quantum cryptography. It runs real OpenSSL handshakes against the target,
reports what was actually negotiated, and makes only the handshakes any client
would make.

It runs in your terminal, is licensed Apache 2.0, and connects only to the host
you name on the command line.

## Contents

- [What it does](#what-it-does)
- [Install](#install)
- [Usage](#usage)
- [Example](#example)
- [Output formats](#output-formats)
- [Exit codes](#exit-codes)
- [How it reads a target](#how-it-reads-a-target)
- [Scope](#scope)
- [Requirements](#requirements)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

## What it does

Point it at a host and it runs a short battery of live probes:

- **Post-quantum key exchange.** Forces the `X25519MLKEM768` hybrid group and
  reports whether the server negotiates it. This is the headline signal: a
  server that speaks the hybrid group is protected against *harvest-now,
  decrypt-later* interception today.
- **Classical key exchange.** Forces classical `X25519` as a control, so the
  report distinguishes "only classical is available" from "hybrid works and
  classical is also still accepted."
- **Legacy protocols.** Sweeps TLS 1.0, 1.1, and 1.2 and enumerates the cipher
  suites each one actually accepts, so deprecated-protocol exposure shows up
  alongside the quantum posture.
- **Certificate signature.** Reads the leaf certificate's signature algorithm
  and flags whether it is classical or post-quantum.

The result is a two-axis verdict — quantum posture on one line, protocol
hygiene on the other — because a server can be doing the right thing on one and
the wrong thing on the other, and a single pass/fail hides that. When a probe
fails, the report shows the actual OpenSSL error (for example, a
`tlsv1 alert insufficient security` from a server that rejects the hybrid
group) instead of a generic "try again."

## Install

```bash
git clone https://github.com/paul007ex/qureddy.git
cd qureddy
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

QuReddy needs a real OpenSSL 3.5+ binary to run the PQC handshakes. On macOS the
system `/usr/bin/openssl` is LibreSSL and will not work — install OpenSSL and
point QuReddy at it:

```bash
brew install openssl@3
export QUREDDY_OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
```

## Usage

```bash
qureddy scan tls www.google.com
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls example.com --format json
qureddy scan tls example.com -vvv        # show the exact OpenSSL commands run
```

Run `qureddy scan tls --help` for the full option list (SNI override, timeout,
retries, output format, verbosity).

## Example

```text
$ qureddy scan tls www.google.com

┏━ QuReddy scan: tls://www.google.com:443 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ PQ posture: ACCEPTABLE — X25519MLKEM768 negotiated                          ┃
┃ Protocol hygiene: ACTION NEEDED — TLSv1, TLSv1.1                            ┃
┃ PQ hybrid X25519MLKEM768 works. Legacy TLSv1, TLSv1.1 remain enabled;       ┃
┃ disable them when client compatibility allows.                             ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

 Findings
 Severity  Rule                                  Protocol  Crypto
 ────────────────────────────────────────────────────────────────────────
 medium    tls.legacy.protocol_offered           TLSv1     legacy protocol
 medium    tls.legacy.protocol_offered           TLSv1.1   legacy protocol
 low       tls.classical.negotiated_x25519       TLSv1.3   X25519
 low       tls.classical.protocol_offered        TLSv1.2   classical suites
 info      tls.hybrid.negotiated_x25519mlkem768  TLSv1.3   X25519MLKEM768
 info      tls.cert.signature_algorithm          —         ecdsa-with-SHA256
```

The full output also includes a Scan details block (protocol, cipher suite,
per-probe result) and a Run details block (scan ID, timestamps, duration, and
the exact OpenSSL binary used).

## Output formats

| `--format` | What you get |
|---|---|
| `rich` (default) | The colored terminal report above. |
| `json` | A stable machine document, schema `qureddy.scan.v1` — findings, evidence, and per-probe results. See the [JSON schema reference](docs/reference/json-schema.md). |
| `cbom` | A CycloneDX 1.6 Cryptography Bill of Materials of the observed crypto assets. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed. |
| `2` | The target scan failed (handshake, parse, connection). |
| `3` | The local OpenSSL is missing or unusable for PQC probing. |
| `4` | Usage or configuration error. |
| `70` | Internal error in QuReddy itself. |

Full detail: [exit codes](docs/reference/exit-codes.md) and
[failure categories](docs/reference/failure-categories.md).

## How it reads a target

QuReddy accepts a hostname, `host:port`, a `tls://` URL, or an IP address. For
an IP target, pass `--sni` so the server knows which certificate to present.
OpenSSL path resolution is `--openssl PATH`, then the `QUREDDY_OPENSSL`
environment variable, then `openssl` on your `PATH`.

## Scope

QuReddy is read-only: it observes handshakes and reports what it saw. It leaves
the target unchanged, and the only network traffic it generates is the
handshakes to the host you name. It reports the cryptography it observed and
stops there — turning that into a compliance pass/fail is a separate step that
lives outside the scanner.

## Requirements

- Python 3.12+
- OpenSSL 3.5+ (LibreSSL is not supported — it lacks the PQC groups)
- macOS, Linux, or Windows

## Documentation

Docs follow the [Diátaxis](https://diataxis.fr) structure — see
[`docs/README.md`](docs/README.md) for the full map.

- [Your first scan](docs/tutorials/your-first-scan.md) — start here
- [Scan an IP with custom SNI](docs/how-to/scan-ip-with-sni.md)
- [JSON output for CI](docs/how-to/json-output-for-ci.md)
- [CLI reference](docs/reference/cli.md)
- [Why hybrid PQ?](docs/explanation/why-hybrid-pq.md) · [Harvest now, decrypt later](docs/explanation/hndl.md)

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and
[`docs/contributors/`](docs/contributors/). The project runs ruff,
mypy `--strict`, bandit, and pytest; the engineering standards are in
[`docs/contributors/coding-rules.md`](docs/contributors/coding-rules.md).

Report bugs and request features through
[GitHub Issues](https://github.com/paul007ex/qureddy/issues). Security reports
go through [`SECURITY.md`](SECURITY.md).

## License

Apache 2.0 — see [`LICENSE`](LICENSE) and [`LICENSES/`](LICENSES/).
REUSE-compliant ([`REUSE.toml`](REUSE.toml)).
