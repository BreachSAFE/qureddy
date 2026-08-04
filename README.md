# BreachSAFE QuReddy

[![Version](https://img.shields.io/badge/version-0.2.12-blue?style=flat-square)](https://github.com/breachsafe/qureddy/blob/main/CHANGELOG.md)
[![Python](https://img.shields.io/badge/python-3.12-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: PolyForm Noncommercial](https://img.shields.io/badge/license-PolyForm%20Noncommercial-orange?style=flat-square)](https://github.com/breachsafe/qureddy/blob/main/LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/breachsafe/qureddy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/breachsafe/qureddy)

QuReddy is a source-available command line scanner for post-quantum readiness at
TLS and SSH endpoints. It records the protocol and cryptographic evidence that
the endpoint exposes to a client, then reports the observed readiness posture.

TLS scans use a local OpenSSL 3.5 LTS or newer binary. SSH scans read the server's
cleartext KEXINIT offer directly and do not require OpenSSL.

## Contents

- [Install](#install)
- [Run with Docker](#run-with-docker)
- [Run the first SSH scan](#run-the-first-ssh-scan)
- [Prepare OpenSSL for TLS](#prepare-openssl-for-tls)
- [Run the first TLS scan](#run-the-first-tls-scan)
- [Write JSON or CBOM output](#write-json-or-cbom-output)
- [Interpret the evidence](#interpret-the-evidence)
- [Exit codes](#exit-codes)
- [Network and privacy scope](#network-and-privacy-scope)
- [Requirements](#requirements)
- [Documentation and support](#documentation-and-support)
- [Contributing](#contributing)
- [License](#license)

## Install

> **Pre-release (TestPyPI):** QuReddy 0.2.12 is being published to **TestPyPI**
> while the PyPI release is finalized. Install with (**Python 3.12+**):
>
> ```bash
> pipx install --python 3.12 \
>   --index-url https://test.pypi.org/simple/ \
>   --pip-args '--extra-index-url https://pypi.org/simple/' \
>   breachsafe-qureddy
> ```
>
> The `--extra-index-url` pulls runtime dependencies from PyPI (TestPyPI hosts only
> QuReddy). Keep both indexes in this command: TestPyPI does not mirror every
> dependency release. Once the PyPI release lands, this simplifies to
> `pipx install breachsafe-qureddy`.

Install the PyPI distribution with `pipx`:

```bash
pipx install breachsafe-qureddy
qureddy --version
```

> **Python 3.12 or newer.** QuReddy targets `>=3.12` (3.12, 3.13, …). The previous
> `0.2.0` TestPyPI wheel had a `<3.13` cap; the `0.2.1` release removes that stale
> upper bound.

The expected version line is:

```text
BreachSAFE QuReddy 0.2.12 -- https://www.breachsafe.ai
```

`pipx` creates an isolated environment and places `qureddy` on your command
path. See the [installation and troubleshooting guide](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/install.md)
for macOS, Linux, Windows, virtual environment, upgrade, and uninstall
instructions.

## Run with Docker

The release image bundles the verified OpenSSL runtime and runs as an
unprivileged user:

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan tls pq.cloudflareresearch.com --format cbom
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan ssh github.com --format cbom
```

For reproducible deployments, pin an explicit version tag (for example
`ghcr.io/breachsafe/qureddy:0.2.12`) or a `@sha256:` digest instead of `:latest`.

See the [Docker and GHCR guide](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/docker.md)
for digest pinning, local builds, output redirection, and publication policy.

## Run the first SSH scan

This command needs network access to `github.com` on TCP port 22. It does not
need OpenSSL:

```bash
qureddy scan ssh github.com
```

The scanner observes the offered key exchange and host key algorithms. A
successful scan exits `0` even when it reports a vulnerable posture.

## Prepare OpenSSL for TLS

TLS scanning requires OpenSSL 3.5 LTS or newer with the
`X25519MLKEM768` TLS group. LibreSSL is not supported.

On macOS with Homebrew:

```bash
brew install openssl@3.5
export QUREDDY_OPENSSL="$(brew --prefix openssl@3.5)/bin/openssl"
qureddy scan tls --help
```

Linux and Windows installations vary by distribution. Confirm the selected
binary before scanning:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

If `openssl` is not the intended binary, set `QUREDDY_OPENSSL` or pass
`--openssl PATH`. The [installation guide](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/install.md) documents
the supported resolution order and failure diagnostics.

## Run the first TLS scan

This command needs network access to
`pq.cloudflareresearch.com` on TCP port 443:

```bash
qureddy scan tls pq.cloudflareresearch.com
```

A TLS scan separately checks hybrid TLS 1.3 key exchange, a classical TLS 1.3
control, legacy TLS protocol offers, and the leaf certificate signature
algorithm. The scan does not validate certificate trust, revocation, or the
remote software implementation.

For an IP target that requires Server Name Indication (SNI):

```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

## Write JSON or CBOM output

Use JSON for QuReddy's complete scan result:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
```

Use CBOM for a CycloneDX 1.7 Cryptography Bill of Materials containing the
positively observed cryptographic assets:

```bash
qureddy scan ssh github.com --format cbom > github-ssh.cdx.json
```

The crypto assets use native CycloneDX `cryptoProperties`, so any CycloneDX 1.7
crypto-aware tool understands the inventory and post-quantum posture. QuReddy's
interpretation and provenance ride in `qureddy:`-namespaced `metadata.properties`,
which unaware tools ignore without failing. Add `--reproducible` for a byte- and
digest-identical document. See [the CBOM design doc](https://github.com/breachsafe/qureddy/blob/main/docs/explanation/cbom-design.md)
for the design and interoperability boundary.

Machine modes write one parseable document to standard output. Without an
explicit verbosity flag, successful scans keep standard error empty.

See [generate and validate a CBOM](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/generate-a-cbom.md),
[JSON output](https://github.com/breachsafe/qureddy/blob/main/docs/reference/json-schema.md), and
[CBOM output](https://github.com/breachsafe/qureddy/blob/main/docs/reference/cbom.md)
for the exact contracts.

## Interpret the evidence

QuReddy separates four kinds of statement:

- An observation records what the endpoint returned.
- A local capability record describes the scanner host, such as its OpenSSL
  version.
- A finding interprets one or more observations under a named rule.
- `unknown` or `not_testable` preserves a missing or failed observation.

## Exit codes

| Code | Meaning | Scanner |
| --- | --- | --- |
| `0` | Scan completed; inspect the reported readiness | TLS and SSH |
| `2` | Target connection, handshake, or parse failed | TLS and SSH |
| `3` | Local OpenSSL is missing or unusable | TLS only |
| `4` | Usage or configuration error | TLS and SSH |
| `70` | Internal QuReddy error | Process wide |

Scripts must branch on the exit code instead of treating a readiness finding
as process failure. See the [exit code reference](https://github.com/breachsafe/qureddy/blob/main/docs/reference/exit-codes.md).

## Network and privacy scope

QuReddy connects only to the target named on the command line. TLS scans make
bounded TLS handshakes. SSH scans read the server identification and KEXINIT
offer without authenticating or opening an SSH session.

The scanner does not change the target, send telemetry, store scan history, or
contact a BreachSAFE service. Redirected JSON and CBOM files remain on the
operator's system unless the operator sends them elsewhere.

## Requirements

- Python `>=3.12`
- macOS, Linux, or Windows
- Network reachability to the named target
- OpenSSL 3.5 LTS or newer for TLS scans only

The clean artifact matrix installs the wheel, source distribution, and pipx
application on Linux, macOS, and Windows. Platform support does not imply that
every operating system package repository supplies a suitable OpenSSL build.

## Documentation and support

- [Documentation index](https://github.com/breachsafe/qureddy/blob/main/docs/README.md)
- [CLI reference](https://github.com/breachsafe/qureddy/blob/main/docs/reference/cli.md)
- [Install and troubleshoot](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/install.md)
- [Scan SSH or SFTP](https://github.com/breachsafe/qureddy/blob/main/docs/how-to/scan-ssh.md)
- [Security policy and private disclosure](https://github.com/breachsafe/qureddy/blob/main/SECURITY.md)
- [Public issue tracker](https://github.com/breachsafe/qureddy/issues)

Do not file security vulnerabilities in the public issue tracker. Follow
[`SECURITY.md`](https://github.com/breachsafe/qureddy/blob/main/SECURITY.md)
for private reporting.

## Contributing

See [`CONTRIBUTING.md`](https://github.com/breachsafe/qureddy/blob/main/CONTRIBUTING.md)
and the
[contributor documentation](https://github.com/breachsafe/qureddy/tree/main/docs/contributors/).
The repository enforces
formatting, lint, strict type checking, tests, security scans, dependency
audits, license metadata, file size policy, CBOM conformance, and release
artifact checks.

## License

PolyForm Noncommercial License 1.0.0. Commercial use requires a separate
license from BreachSAFE. See [`LICENSE`](https://github.com/breachsafe/qureddy/blob/main/LICENSE),
[`LICENSES/`](https://github.com/breachsafe/qureddy/tree/main/LICENSES/), and
[`REUSE.toml`](https://github.com/breachsafe/qureddy/blob/main/REUSE.toml).
