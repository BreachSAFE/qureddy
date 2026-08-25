<p align="center">
  <a href="https://www.breachsafe.io/">
    <img src="https://static.wixstatic.com/media/393c0f_0ca31d6cc7df47f9838c96483a49dd4f~mv2.png" alt="BreachSAFE" width="112">
  </a>
</p>

# BreachSAFE QuReddy

[![Latest release](https://img.shields.io/github/v/release/BreachSAFE/qureddy?display_name=tag&style=flat-square)](https://github.com/BreachSAFE/qureddy/releases/latest)
[![CI](https://github.com/BreachSAFE/qureddy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BreachSAFE/qureddy/actions/workflows/ci.yml)
[![CodeQL](https://github.com/BreachSAFE/qureddy/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/BreachSAFE/qureddy/actions/workflows/codeql.yml)
[![Container](https://github.com/BreachSAFE/qureddy/actions/workflows/container.yml/badge.svg?branch=main)](https://github.com/BreachSAFE/qureddy/actions/workflows/container.yml)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-D7FF64?style=flat-square&logo=ruff&logoColor=black)](https://docs.astral.sh/ruff/)
[![Type Checked: mypy strict](https://img.shields.io/badge/type%20check-mypy%20strict-blue?style=flat-square)](https://mypy-lang.org/)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/breachsafe/qureddy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/breachsafe/qureddy)
[![GHCR image](https://img.shields.io/badge/GHCR-qureddy-blue?style=flat-square&logo=docker)](https://github.com/BreachSAFE/qureddy/pkgs/container/qureddy)
[![TestPyPI package](https://img.shields.io/badge/TestPyPI-breachsafe--qureddy-blue?style=flat-square&logo=pypi)](https://test.pypi.org/project/breachsafe-qureddy/)
[![OpenSSL 3.5.7 LTS](https://img.shields.io/badge/OpenSSL-3.5.7%20LTS-721412?style=flat-square&logo=openssl)](https://github.com/openssl/openssl/releases/tag/openssl-3.5.7)
[![CycloneDX 1.7 CBOM](https://img.shields.io/badge/CycloneDX-1.7%20CBOM-2f6690?style=flat-square)](https://cyclonedx.org/docs/1.7/)
[![NIST PQC references](https://img.shields.io/badge/NIST-PQC%20references-005ea8?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![NIST OSCAL downstream](https://img.shields.io/badge/NIST-OSCAL%20downstream-005ea8?style=flat-square)](https://pages.nist.gov/OSCAL/)
[![NIST SP 800-53 mapping](https://img.shields.io/badge/NIST-SP%20800--53%20mapping-005ea8?style=flat-square)](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
[![CISA quantum guidance](https://img.shields.io/badge/CISA-quantum%20guidance-1a4480?style=flat-square)](https://www.cisa.gov/topics/cyber-threats-and-advisories/quantum)
[![OWASP crypto guidance](https://img.shields.io/badge/OWASP-crypto%20guidance-000000?style=flat-square&logo=owasp)](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
[![SCF Quantum Security mapping](https://img.shields.io/badge/SCF-Quantum%20Security%20mapping-4b5563?style=flat-square)](https://github.com/paul007ex/breachsafe-mint-oscal)
[![PQC evidence](https://img.shields.io/badge/QuReddy-PQC%20evidence-6f42c1?style=flat-square)](https://github.com/BreachSAFE/qureddy/blob/main/docs/explanation/hndl.md)
[![EnXemble integration](https://img.shields.io/badge/BreachSAFE-EnXemble-6f42c1?style=flat-square&logo=github)](https://github.com/BreachSAFE)

QuReddy is an open-source command line scanner for post-quantum readiness at
TLS and SSH endpoints. It records the protocol and cryptographic evidence that
the endpoint exposes to a client, then reports the observed readiness posture.

Primary integration: [BreachSAFE EnXemble](https://github.com/BreachSAFE) runs QuReddy
in its scan engine and imports the JSONL findings, JSON evidence, and CycloneDX CBOM
artifacts. The EnXemble repository is moving into the BreachSAFE organization; the
organization link remains stable during that transition.

TLS scans use a local OpenSSL 3.5.7 LTS binary. SSH scans read the server's
cleartext KEXINIT offer directly and do not require OpenSSL.

> **Tip:** Start with the [Docker quickstart](#1-quickstart-with-docker). It includes
> the pinned OpenSSL runtime and keeps the host setup small.

## At a glance

| Target | QuReddy observes | Useful outputs |
| --- | --- | --- |
| TLS endpoint | handshake, certificate, key exchange, protocol hygiene | Rich, JSON, JSONL, CBOM |
| SSH endpoint | banner, KEXINIT algorithms, host-key and authentication evidence | Rich, JSON, JSONL, CBOM |
| EnXemble host | scan bundle and CISO evaluation | JSONL, JSON, CBOM |

<details>
<summary>Try a real scan</summary>

```console
docker run --rm ghcr.io/breachsafe/qureddy:latest scan tls example.com
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com --format jsonl
```

The first command renders the human report. The second emits one deterministic
JSONL record per finding for CI, EnXemble, or another downstream consumer.

</details>

## Contents

1. [At a glance](#at-a-glance)
2. [Quickstart with Docker](#1-quickstart-with-docker)
3. [Install locally with pipx](#2-install-locally-with-pipx)
4. [Run the first SSH scan](#3-run-the-first-ssh-scan)
5. [Prepare OpenSSL for TLS](#4-prepare-openssl-for-tls)
6. [Run the first TLS scan](#5-run-the-first-tls-scan)
7. [Write JSON, JSONL, CBOM, or a bundle](#6-write-json-jsonl-cbom-or-a-bundle)
8. [Interpret the evidence](#7-interpret-the-evidence)
9. [Exit codes](#8-exit-codes)
10. [Network and privacy scope](#9-network-and-privacy-scope)
11. [Requirements](#10-requirements)
12. [Documentation and support](#11-documentation-and-support)
13. [Contributing](#12-contributing)
14. [Open-source stack](#open-source-stack)
15. [License](#13-license)

## 1. Quickstart with Docker

Docker is the primary supported way to run QuReddy and the fastest path to a
result. The image bundles the verified OpenSSL 3.5.7 LTS runtime, so TLS scanning
needs no local setup, and it runs as an unprivileged user. The image entrypoint is
the `qureddy` command, so any argument you would pass to the CLI you pass to
`docker run` unchanged:

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest scan tls example.com
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com
```

Each command needs outbound network access to the named target: TCP port 443 for
the TLS example, TCP port 22 for the SSH example. Add `--format json`,
`--format jsonl`, or `--format cbom` for machine output, as shown in
[section 6](#6-write-json-jsonl-cbom-or-a-bundle).

For reproducible deployments, pin an immutable reference instead of `:latest`.
Use an explicit version tag, or preferably a `@sha256:` digest:

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
docker inspect --format='{{index .RepoDigests 0}}' ghcr.io/breachsafe/qureddy:latest
docker run --rm ghcr.io/breachsafe/qureddy@sha256:<digest> scan ssh github.com
```

To build the image from a fresh clone instead of pulling it, run `docker build`
from the repository root. The image builds the wheel from source in an in-image
stage, so no separate wheel-build step is required:

```bash
docker build --tag qureddy:local .
docker run --rm qureddy:local --version
```

See the [Docker and GHCR guide](docs/how-to/docker.md) for digest pinning, local
builds, output redirection, and publication policy. To install QuReddy as a local
Python application instead, see [section 2](#2-install-locally-with-pipx).

For a browser-based TLS/SSH host that consumes QuReddy CBOM output, see
[Run QuReddy with a GUI](docs/how-to/run-with-a-gui.md).

## 2. Install locally with pipx

> **TestPyPI-only distribution.** QuReddy is intentionally published to **TestPyPI**
> only for now; do not expect `pipx install breachsafe-qureddy` to resolve from the
> public PyPI package index. Install from TestPyPI with PyPI as a fallback for runtime
> dependencies (**Python 3.14+**):
>
> ```bash
> pipx install --python 3.14 \
>   --index-url https://test.pypi.org/simple/ \
>   --pip-args '--extra-index-url https://pypi.org/simple/' \
>   breachsafe-qureddy
> ```
>
> The `--extra-index-url` pulls runtime dependencies from PyPI, because TestPyPI
> hosts only QuReddy and does not mirror every dependency release. Keep both indexes.
> The public PyPI package will be announced separately if and when that release is
> authorized.

Confirm the installation:

```bash
qureddy --version
```

The expected version line is:

```text
BreachSAFE QuReddy <version> -- https://www.breachsafe.ai
```

QuReddy targets Python `>=3.14`. `pipx`
creates an isolated environment and places `qureddy` on your command path. See the
[installation and troubleshooting guide](docs/how-to/install.md) for macOS, Linux,
Windows, virtual environment, upgrade, and uninstall instructions.

A local install covers SSH scanning immediately. TLS scanning additionally needs a
suitable OpenSSL, covered in [section 4](#4-prepare-openssl-for-tls). The container
in [section 1](#1-quickstart-with-docker) avoids that step entirely.

## 3. Run the first SSH scan

This command needs network access to `github.com` on TCP port 22. It does not
need OpenSSL:

```bash
qureddy scan ssh github.com
```

The scanner observes the offered key exchange and host key algorithms. A
successful scan exits `0` even when it reports a vulnerable posture.

## 4. Prepare OpenSSL for TLS

TLS scanning requires OpenSSL 3.5.7 LTS with the
`X25519MLKEM768` TLS group. LibreSSL is not supported.

On macOS, Homebrew's `openssl@3.5` formula is a moving 3.5.x channel. Inspect
the installed runtime before selecting it:

```bash
brew install openssl@3.5
QUREDDY_OPENSSL_CANDIDATE="$(brew --prefix openssl@3.5)/bin/openssl"
"$QUREDDY_OPENSSL_CANDIDATE" version
"$QUREDDY_OPENSSL_CANDIDATE" list -tls1_3 -tls-groups
```

Export the candidate only when the executable and any explicitly reported
`Library:` version are both exactly 3.5.7 and the group list contains
`X25519MLKEM768`:

```bash
export QUREDDY_OPENSSL="$QUREDDY_OPENSSL_CANDIDATE"
qureddy scan tls --help
```

If the formula has moved, use the repository's
[checksum-pinned 3.5.7 source-build recipe](.github/actions/setup-openssl/action.yml)
or the [QuReddy container](docs/how-to/docker.md); do not bypass the version gate.

Linux and Windows installations vary by distribution. Confirm the selected
binary before scanning:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

If `openssl` is not the intended binary, set `QUREDDY_OPENSSL` or pass
`--openssl PATH`. The [installation guide](docs/how-to/install.md) documents
the supported resolution order and failure diagnostics.

## 5. Run the first TLS scan

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

## 6. Write JSON, JSONL, CBOM, or a bundle

Use JSON for QuReddy's complete scan result:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
```

Use JSONL for one finding or evidence record per line, which is convenient for
streaming pipelines:

```bash
qureddy scan ssh github.com --format jsonl > github-ssh.jsonl
```

Use CBOM for a CycloneDX 1.7 Cryptography Bill of Materials containing the
positively observed cryptographic assets:

```bash
qureddy scan ssh github.com --format cbom > github-ssh.cdx.json
```

Use `--output-dir` to run the scanner once and write every supported projection:

```bash
qureddy scan ssh github.com --output-dir evidence/github-ssh
```

The directory contains `scan.json`, `scan.jsonl`, `scan.cdx.json`, and
`scan.rich.txt`. Bundle mode cannot be combined with `--output`.

The crypto assets use native CycloneDX `cryptoProperties`, so any CycloneDX 1.7
crypto-aware tool understands the inventory and post-quantum posture. QuReddy's
interpretation and provenance are native CycloneDX too: evidence is
`component.evidence.occurrences`, findings are top-level `annotations`, and each
finding's verdict is `qureddy:`-namespaced `properties` on the subject component;
scan/target/tool provenance stays in `qureddy:`-namespaced `metadata.properties`.
Unaware tools ignore the `qureddy:` keys without failing. Add `--deterministic` for a
byte- and digest-identical document. See [the CBOM design doc](docs/explanation/cbom-design.md)
for the design and interoperability boundary.

Machine modes write one parseable document to standard output. Without an
explicit verbosity flag, successful scans keep standard error empty.

See [generate and validate a CBOM](docs/how-to/generate-a-cbom.md),
[JSON output](docs/reference/json-schema.md), and
[CBOM output](docs/reference/cbom.md)
for the exact contracts.

## 7. Interpret the evidence

QuReddy separates four kinds of statement:

- An observation records what the endpoint returned.
- A local capability record describes the scanner host, such as its OpenSSL
  version.
- A finding interprets one or more observations under a named rule.
- `unknown` or `not_testable` preserves a missing or failed observation.

## 8. Exit codes

| Code | Meaning | Scanner |
| --- | --- | --- |
| `0` | Scan completed; inspect the reported readiness | TLS and SSH |
| `2` | Target connection, handshake, or parse failed | TLS and SSH |
| `3` | Local OpenSSL is missing or unusable | TLS only |
| `4` | Usage or configuration error | TLS and SSH |
| `70` | Internal QuReddy error | Process wide |

Scripts must branch on the exit code instead of treating a readiness finding
as process failure. See the [exit code reference](docs/reference/exit-codes.md).

## 9. Network and privacy scope

QuReddy connects only to the target named on the command line. TLS scans make
bounded TLS handshakes. SSH scans read the server identification and KEXINIT
offer without authenticating or opening an SSH session.

The scanner does not change the target, send telemetry, store scan history, or
contact a BreachSAFE service. Redirected JSON and CBOM files remain on the
operator's system unless the operator sends them elsewhere.

## 10. Requirements

- Python `>=3.14`
- Network reachability to the named target
- OpenSSL 3.5.7 LTS for TLS scans only

The clean-install matrix installs the wheel, source distribution, and pipx
application on Linux and macOS every release. Windows is not exercised in CI.
Platform support does not imply that every operating system package repository
supplies a suitable OpenSSL build; the container bundles a verified one and is
Linux.

## 11. Documentation and support

- [Documentation index](docs/README.md)
- [CLI reference](docs/reference/cli.md)
- [Install and troubleshoot](docs/how-to/install.md)
- [Scan SSH or SFTP](docs/how-to/scan-ssh.md)
- [Security policy and private disclosure](SECURITY.md)
- [Public issue tracker](https://github.com/breachsafe/qureddy/issues)

Do not file security vulnerabilities in the public issue tracker. Follow
[`SECURITY.md`](SECURITY.md)
for private reporting.

## 12. Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md)
and the
[contributor documentation](docs/contributors/).
The repository enforces
formatting, lint, strict type checking, tests, security scans, dependency
audits, license metadata, file size policy, CBOM conformance, and release
artifact checks.

## Open-source stack

<p align="center">
  <a href="https://www.python.org/"><img src="https://cdn.simpleicons.org/python/3776AB" alt="Python" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://www.openssl.org/"><img src="https://cdn.simpleicons.org/openssl/00D4FF" alt="OpenSSL" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://www.docker.com/"><img src="https://cdn.simpleicons.org/docker/2496ED" alt="Docker" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://test.pypi.org/project/breachsafe-qureddy/"><img src="https://cdn.simpleicons.org/pypi/3775A9" alt="TestPyPI" width="48" height="48"></a>
</p>

<p align="center">
  CLI: <a href="https://click.palletsprojects.com/">Click</a> ·
  <a href="https://github.com/Textualize/rich">Rich</a>
  &nbsp;|&nbsp; Artifacts: <a href="https://cyclonedx.org/">CycloneDX CBOM</a>
  &nbsp;|&nbsp; Tooling: <a href="https://docs.astral.sh/uv/">uv</a>
</p>

## 13. License

Apache License 2.0 (OSI-approved open source). See [`LICENSE`](LICENSE),
[`LICENSES/`](LICENSES/), and [`REUSE.toml`](REUSE.toml).
