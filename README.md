<p align="center">
  <a href="https://github.com/breachsafe/qureddy">
    <img src="https://static.wixstatic.com/media/393c0f_0ca31d6cc7df47f9838c96483a49dd4f~mv2.png" alt="BreachSAFE" width="112">
  </a>
</p>

# BreachSAFE QuReddy

[![Latest release](https://img.shields.io/github/v/release/BreachSAFE/qureddy?display_name=tag&style=flat-square)](https://github.com/BreachSAFE/qureddy/releases/latest)
[![CI](https://github.com/BreachSAFE/qureddy/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/BreachSAFE/qureddy/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/breachsafe/qureddy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/breachsafe/qureddy)
[![Python](https://img.shields.io/badge/python-3.14%2B-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue?style=flat-square)](LICENSE)
[![OpenSSL 3.5.x](https://img.shields.io/badge/OpenSSL-3.5.x-721412?style=flat-square&logo=openssl)](https://github.com/openssl/openssl)
[![CycloneDX 1.7 CBOM](https://img.shields.io/badge/CycloneDX-1.7%20CBOM-2f6690?style=flat-square)](https://cyclonedx.org/docs/1.7/)
[![GHCR image](https://img.shields.io/badge/GHCR-qureddy-blue?style=flat-square&logo=docker)](https://github.com/BreachSAFE/qureddy/pkgs/container/qureddy)
[![Docker Hub image](https://img.shields.io/badge/Docker%20Hub-qureddy-blue?style=flat-square&logo=docker)](https://hub.docker.com/r/breachsafe/qureddy)
[![TestPyPI package](https://img.shields.io/badge/TestPyPI-breachsafe--qureddy-blue?style=flat-square&logo=pypi)](https://test.pypi.org/project/breachsafe-qureddy/)

QuReddy is an open-source command-line scanner for post-quantum readiness and
cryptographic inventory. It collects evidence from the target, records where
each value came from, and reports the resulting posture together with the
coverage limits that affect the result.

Each scan lane uses the collector that fits its target. TLS uses a supported
OpenSSL 3.5.x LTS binary. SSH reads the server's identification and KEXINIT
offer. IKE uses stock `ike-scan` for lower-trust discovery. Wallet scans query
the configured public indexer or RPC endpoint. Directory and container-image
scans pass artifact bytes to the bundled `cbomkit-theia` collector; image scans
also require Docker socket access at runtime. The [Docker guide](docs/how-to/docker.md)
shows the required mounts and trust boundary.

> **Tip:** Start with the [Docker quickstart](#1-quickstart-with-docker). It includes
> a verified OpenSSL runtime and keeps host setup small.

## At a glance

| Target | Command | QuReddy observes | Output |
| --- | --- | --- | --- |
| TLS endpoint | `scan tls` | handshake, certificate, key exchange, protocol hygiene | Rich, JSON, JSONL, CBOM |
| SSH endpoint | `scan ssh` | banner, KEXINIT algorithms, host-key and authentication evidence | Rich, JSON, JSONL, CBOM |
| IKE endpoint | `scan ike` | responder modes, tool-reported transforms, NOTIFY responses | Rich, JSON, JSONL, CBOM |
| Directory | `scan dir` | artifact files through CBOMkit Theia | CycloneDX CBOM |
| Container image | `scan image` | image artifacts through CBOMkit Theia | CycloneDX CBOM |
| Wallet address | `scan wallet` | public indexer observations and cryptographic metadata | Rich, JSON, JSONL, CBOM |

<details>
<summary>Try a real scan</summary>

```console
docker run --rm ghcr.io/breachsafe/qureddy:latest scan tls example.com
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com --format jsonl
```

The first command renders the human report. The second emits one deterministic
JSONL record per finding for a CI or data pipeline.

</details>

## Understand the threat: harvest now, decrypt later

Attackers record encrypted traffic today and decrypt it once a quantum computer can break the
key exchange. Long-lived secrets sent now over classical TLS or SSH are already exposed.

[![Your Encryption Isn't Quantum Safe, IBM Technology](https://img.youtube.com/vi/ecvCfTPRBrI/maxresdefault.jpg)](https://www.youtube.com/watch?v=ecvCfTPRBrI)

Watch **[Your Encryption Isn't Quantum Safe](https://www.youtube.com/watch?v=ecvCfTPRBrI)**
(IBM Technology), then track the clock at **[Is it Q-Day?](https://isitqday.com/)**. QuReddy
shows which of your TLS, SSH, and IKE endpoints expose classical key establishment today.

## Contents

1. [At a glance](#at-a-glance)
2. [Understand the threat: harvest now, decrypt later](#understand-the-threat-harvest-now-decrypt-later)
3. [Quickstart with Docker](#1-quickstart-with-docker)
4. [Install locally with pipx](#2-install-locally-with-pipx)
5. [Run the first SSH scan](#3-run-the-first-ssh-scan)
6. [Prepare OpenSSL for TLS](#4-prepare-openssl-for-tls)
7. [Run the first TLS scan](#5-run-the-first-tls-scan)
8. [Run an IKE scan](#6-run-an-ike-scan)
9. [Scan an artifact directory or container image](#7-scan-an-artifact-directory-or-container-image)
10. [Write JSON, JSONL, CBOM, or a bundle](#8-write-json-jsonl-cbom-or-a-bundle)
11. [Interpret the evidence](#9-interpret-the-evidence)
12. [Exit codes](#10-exit-codes)
13. [Network and privacy scope](#11-network-and-privacy-scope)
14. [Requirements](#12-requirements)
15. [Documentation and support](#13-documentation-and-support)
16. [Contributing](#14-contributing)
17. [Open-source stack](#open-source-stack)
18. [License](#15-license)

## 1. Quickstart with Docker

Docker is the primary supported way to run QuReddy and the fastest path to a
result. The image bundles a verified OpenSSL 3.5.x LTS runtime, so TLS scanning
needs no local setup, and it runs as an unprivileged user. GHCR is the canonical
image registry; Docker Hub provides a mirror for environments that restrict GitHub
package access. The image entrypoint is
the `qureddy` command, so any argument you would pass to the CLI you pass to
`docker run` unchanged:

If Docker is already installed, copy and paste one of these commands:

```console
# TLS scan
docker run --rm docker.io/breachsafe/qureddy:latest scan tls badssl.com

# SSH scan
docker run --rm docker.io/breachsafe/qureddy:latest scan ssh github.com

# IKE scan
docker run --rm docker.io/breachsafe/qureddy:latest scan ike netherlands.hide.me
```

Docker downloads the image automatically. No Python or OpenSSL installation is
required on the host. The scan needs outbound access to TCP port 443 for TLS,
TCP port 22 for SSH, or UDP port 500/4500 for IKE.

If Docker Hub is unavailable, use the GHCR copy of the same release:

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest scan tls badssl.com
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com
```

For automated pulls, authenticate to Docker Hub or use GHCR. Docker Hub applies
limits to unauthenticated pulls.

Each command needs outbound network access to the named target: TCP port 443 for
the TLS example, TCP port 22 for the SSH example. Add `--format json`,
`--format jsonl`, or `--format cbom` for machine output, as shown in
[section 8](#8-write-json-jsonl-cbom-or-a-bundle).

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

### Guided scan (interactive)

Prefer to be prompted? [`examples/guided-scan.sh`](examples/guided-scan.sh) asks for the scan
type, target, and an authorization confirmation, then runs the scan in Docker. Every prompt has
a default, so pressing Enter through them scans `badssl.com` over TLS and `github.com` over SSH:

```bash
curl -fsSL https://raw.githubusercontent.com/BreachSAFE/qureddy/main/examples/guided-scan.sh -o guided-scan.sh
bash guided-scan.sh
# Scan TLS, SSH, or both? [tls/ssh/both] (default: both):   <Enter>
# Authorized to scan badssl.com:443 over tls? [Y/n]:         <Enter>
# Authorized to scan github.com:22 over ssh? [Y/n]:         <Enter>
```

Only scan targets you are authorized to test. Set `DRY_RUN=1` to print the commands without
running them. The guided Docker script covers TLS and SSH. Run IKE with the direct container
command in [section 6](#6-run-an-ike-scan).

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
BreachSAFE QuReddy <version> -- https://github.com/breachsafe/qureddy
```

QuReddy targets Python `>=3.14`. `pipx`
creates an isolated environment and places `qureddy` on your command path. See the
[installation and troubleshooting guide](docs/how-to/install.md) for macOS, Linux,
Windows, virtual environment, upgrade, and uninstall instructions.

A local install covers SSH scanning immediately. TLS scanning additionally needs a
suitable OpenSSL, covered in [section 4](#4-prepare-openssl-for-tls). IKE scanning
additionally needs stock `ike-scan`. The container bundles both external tools.

## 3. Run the first SSH scan

This command needs network access to `github.com` on TCP port 22. It does not
need OpenSSL:

```bash
qureddy scan ssh github.com
```

The scanner observes the offered key exchange and host key algorithms. A
successful scan exits `0` even when it reports a vulnerable posture.

## 4. Prepare OpenSSL for TLS

TLS scanning requires a supported OpenSSL 3.5.x LTS build with the
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
`Library:` version are supported 3.5.x releases and the group list contains
`X25519MLKEM768`:

```bash
export QUREDDY_OPENSSL="$QUREDDY_OPENSSL_CANDIDATE"
qureddy scan tls --help
```

If the formula has moved, use the repository's
[checksum-pinned OpenSSL source-build recipe](.github/actions/setup-openssl/action.yml)
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
algorithm. Certificate trust, revocation, and remote software identity are
outside this scan's evidence scope.

For an IP target that requires Server Name Indication (SNI):

```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

## 6. Run an IKE scan

For a local Python installation, install stock `ike-scan` separately and confirm its
version. The container already includes it. Scan only endpoints you are authorized to
test:

```bash
ike-scan --version
qureddy scan ike netherlands.hide.me --nat-t
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ike netherlands.hide.me --nat-t
```

The backend records lower-trust, tool-reported discovery evidence. Its scope is
responder discovery: accepted proposals, authentication, Child-SA/ESP/AH
posture, post-quantum readiness, and HNDL protection require additional
evidence. Overall IPsec HNDL exposure remains unknown.
See [Scan an IKE endpoint](docs/how-to/scan-ike.md) for the exact limits and options.

## 7. Scan an artifact directory or container image

Use `scan dir` to inspect files that already exist in a directory. Use
`scan image` to inspect the contents of a container image through the Docker
daemon. Both commands invoke the bundled `cbomkit-theia` collector and write
the collector's CycloneDX CBOM to standard output. This lane has a CBOM-only
output contract; JSON, JSONL, and Rich belong to endpoint and wallet scans.

Directory scan:

```bash
qureddy scan dir /opt/homebrew/opt/openssl@3.5 --timeout 120 \
  --output openssl.cdx.json
```

Container-image scan:

```bash
docker run --rm \
  --group-add "$(stat -c '%g' /var/run/docker.sock)" \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker.io/breachsafe/qureddy:latest \
  scan image nginx:latest --timeout 120 > nginx.cdx.json
```

The local directory must contain artifacts that the Theia plugins can inspect.
The image command needs access to the Docker socket because the collector reads
image layers from the daemon. Treat that socket as equivalent to host-daemon
access.

## 8. Write JSON, JSONL, CBOM, or a bundle

Use JSON for QuReddy's complete scan result:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
```

Use JSONL for one finding record per line followed by one canonical scan-summary
record, which is convenient for streaming pipelines:

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

The crypto assets use native CycloneDX `cryptoProperties`, so CycloneDX 1.7
tools that implement the crypto extension can consume the inventory. QuReddy's
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

## 9. Interpret the evidence

QuReddy separates four kinds of statement:

- An observation records what the endpoint returned.
- A local capability record describes the scanner host, such as its OpenSSL
  version.
- A finding interprets one or more observations under a named rule.
- `unknown` or `not_testable` preserves a missing or failed observation.

## 10. Exit codes

| Code | Meaning | Scanner |
| --- | --- | --- |
| `0` | Scan completed; inspect the reported readiness | TLS, SSH, and IKE |
| `2` | Target connection, handshake, timeout, or parse failed | TLS, SSH, and IKE |
| `3` | Required local tool is missing or unusable | TLS and IKE |
| `4` | Usage or configuration error | TLS, SSH, and IKE |
| `70` | Internal QuReddy error | Process wide |

Scripts must branch on the exit code instead of treating a readiness finding
as process failure. See the [exit code reference](docs/reference/exit-codes.md).

## 11. Network and privacy scope

QuReddy connects only to the target named on the command line. TLS scans make
bounded TLS handshakes. SSH scans read the server identification and KEXINIT
offer without authenticating or opening an SSH session. IKE scans invoke a bounded
local `ike-scan` process and send unauthenticated discovery probes to UDP/500 or UDP/4500.

QuReddy's network activity is limited to the target named on the command line;
it sends no telemetry and contacts no BreachSAFE service. Scan history and
redirected JSON or CBOM files remain on the operator's system unless the
operator sends them elsewhere.

## 12. Requirements

- Python `>=3.14`
- Network reachability to the named target
- OpenSSL 3.5.x LTS for TLS scans only
- Stock `ike-scan` for IKE scans only

The clean-install matrix installs the wheel, source distribution, and pipx
application on Linux and macOS every release. Windows is not exercised in CI.
Platform support does not imply that every operating system package repository
supplies a suitable OpenSSL build; the container bundles a verified one and is
Linux.

## 13. Documentation and support

- [Documentation index](docs/README.md)
- [CLI reference](docs/reference/cli.md)
- [Install and troubleshoot](docs/how-to/install.md)
- [Scan SSH or SFTP](docs/how-to/scan-ssh.md)
- [Scan an IKE endpoint](docs/how-to/scan-ike.md)
- [Security policy and private disclosure](SECURITY.md)
- [Public issue tracker](https://github.com/breachsafe/qureddy/issues)

Do not file security vulnerabilities in the public issue tracker. Follow
[`SECURITY.md`](SECURITY.md)
for private reporting.

## 14. Contributing

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

## 15. License

Apache License 2.0 (OSI-approved open source). See [`LICENSE`](LICENSE),
[`LICENSES/`](LICENSES/), and [`REUSE.toml`](REUSE.toml).
