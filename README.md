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

QuReddy is an open-source field kit for finding out what cryptography is
actually in use. Point it at a hostname, SSH server, VPN gateway, wallet
address, artifact directory, or container image, and QuReddy probes the target,
records the evidence, and shows what it found.

Use Rich output while investigating, JSON or JSONL in automation, and
CycloneDX CBOM when the result belongs in a cryptographic inventory. QuReddy
connects observed algorithms, certificates, key establishment, legacy
protocols, and post-quantum signals to the evidence collected during the run.

## Contents

1. [Start here](#start-here)
2. [What QuReddy scans](#what-qureddy-scans)
3. [Install locally](#install-locally)
4. [Docker and development](#docker-and-development)
5. [Run the scan lanes](#run-the-scan-lanes)
6. [Choose an output format](#choose-an-output-format)
7. [Read the result correctly](#read-the-result-correctly)
8. [Exit codes](#exit-codes)
9. [Network and privacy](#network-and-privacy)
10. [Documentation](#documentation)
11. [Contributing](#contributing)
12. [Open-source stack](#open-source-stack)
13. [License](#license)

## Start here

The container is the quickest way to try QuReddy. It includes the runtime tools
needed for TLS, IKE, and artifact scans:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest scan tls badssl.com:443
$ docker run --rm docker.io/breachsafe/qureddy:latest scan ssh github.com
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls smtp.gmail.com:587 --starttls smtp
```

A scan can report a weak or incomplete posture and still exit successfully:
read the result and the exit code together. Add `--format json` for a complete
machine-readable scan document:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls badssl.com:443 --format json > scan.json
```

Run `qureddy --help` for the short command map, or open the
[CLI reference](docs/reference/cli.md) for every option and exit code.

## What QuReddy scans

| Target | Command | Evidence collected | Output |
| --- | --- | --- | --- |
| TLS endpoint | `scan tls` | Handshake, key exchange, certificate signatures, protocol offers, and cipher behavior | Rich, JSON, JSONL, CBOM |
| STARTTLS service | `scan tls --starttls SERVICE` | Cleartext upgrade followed by TLS evidence | Rich, JSON, JSONL, CBOM |
| SSH or SFTP endpoint | `scan ssh` | Server identification, KEXINIT algorithms, host keys, and authentication methods | Rich, JSON, JSONL, CBOM |
| IKE endpoint | `scan ike` | Responder discovery, transforms, modes, and explicit tool responses | Rich, JSON, JSONL, CBOM |
| Wallet account | `scan wallet` | Public account state, key publication, signatures, nonce reuse, and indexer evidence | Rich, JSON, JSONL, CBOM |
| Artifact directory | `scan dir` | Cryptographic artifacts discovered by CBOMkit Theia | CycloneDX CBOM |
| Container image | `scan image` | Cryptographic artifacts discovered from image layers by CBOMkit Theia | CycloneDX CBOM |

The wallet lane supports Bitcoin, Litecoin, and Ethereum. STARTTLS supports
SMTP, POP3, IMAP, FTP, XMPP, XMPP server, Telnet, IRC, MySQL, PostgreSQL,
LMTP, NNTP, Sieve, and LDAP. See the [STARTTLS profile
reference](docs/reference/starttls-profiles.md) for service-specific ports and
upgrade behavior.

## Install locally

QuReddy currently distributes the package through TestPyPI. Python 3.14 or
newer is required:

```bash
pipx install --python 3.14 \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
```

Verify the installation:

```console
$ qureddy --version
BreachSAFE QuReddy <version> -- https://github.com/breachsafe/qureddy
```

Local SSH scans work without an external scanner. TLS scans require a
supported OpenSSL 3.5.x LTS build with the `X25519MLKEM768` TLS group. IKE
scans require stock `ike-scan`. Directory and image scans require
`cbomkit-theia`; the container includes it.

See [installation and troubleshooting](docs/how-to/install.md) for platform
setup, executable discovery, and failure diagnostics.

## Docker and development

GHCR is the canonical container registry, with Docker Hub as a mirror:

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
docker pull docker.io/breachsafe/qureddy:latest
```

For reproducible deployments, replace `:latest` with a release tag or an
immutable digest. To build locally from a fresh clone:

```bash
docker build --tag qureddy:local .
docker run --rm qureddy:local --version
```

For a guided TLS or SSH run, use
[`examples/guided-scan.sh`](examples/guided-scan.sh). It asks for the target
and authorization before invoking the container.

## Run the scan lanes

### TLS

```bash
qureddy scan tls badssl.com:443
qureddy scan tls tls-v1-2.badssl.com:1012 --format json
qureddy scan tls smtp.gmail.com:587 --starttls smtp
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

TLS scanning uses the selected OpenSSL 3.5.x LTS executable. Set
`QUREDDY_OPENSSL` or pass `--openssl PATH` when automatic discovery is not
the one you want. The isolated `QUREDDY_LEGACY_OPENSSL` path enables
additional legacy-protocol and cipher evidence when a compatible OpenSSL
1.0.2u executable is available.

### SSH

```bash
qureddy scan ssh github.com
qureddy scan ssh sftp://sftp.vendor.example:2222 --format cbom
```

SSH reads the server identification and KEXINIT offer directly.

### IKE

```bash
ike-scan --version
qureddy scan ike netherlands.hide.me --nat-t
```

The Python installation needs stock `ike-scan`; the container includes its
pinned package. IKE results represent lower-trust responder discovery and
tool-reported transforms. Run probes only against systems you are authorized
to test.

### Wallets

```bash
qureddy scan wallet 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
qureddy scan wallet Ler4HNAEfwYhBmGXcFP2Po1NpRUEiK8km2 --type litecoin
qureddy scan wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045
```

Wallet scans query the configured public indexer or RPC endpoint and inspect
published account data.

### Directories and images

Directory scans pass local artifact files to Theia:

```bash
qureddy scan dir /opt/application --timeout 120 --output application.cdx.json
```

Image scans read image layers through the Docker daemon. When using the
container, mount the read-only Docker socket:

```bash
docker run --rm --group-add 0 \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  docker.io/breachsafe/qureddy:latest \
  scan image nginx:latest --timeout 120 > nginx.cdx.json
```

Both artifact commands emit Theia's CycloneDX CBOM to standard output and
write diagnostics to standard error. They preserve the CBOM document produced
by Theia, including its `specVersion` and component model.

## Choose an output format

Network and wallet scans derive every projection from one canonical scan result:

```bash
# Human-readable terminal report
qureddy scan ssh github.com --format rich

# Complete QuReddy scan document
qureddy scan ssh github.com --format json > scan.json

# One finding record per line, followed by a summary record
qureddy scan ssh github.com --format jsonl > scan.jsonl

# CycloneDX 1.7 cryptographic inventory
qureddy scan ssh github.com --format cbom > scan.cdx.json

# Write all four projections from one scan
qureddy scan ssh github.com --output-dir evidence/github-ssh
```

The bundle contains `scan.json`, `scan.jsonl`, `scan.cdx.json`, and
`scan.rich.txt`. Machine-readable data goes to standard output; diagnostics go
to standard error. Use `-v`, `-vv`, or `-vvv` for progressively more process
diagnostics. Use `--deterministic` when stable bytes are required for content
addressing.

QuReddy's endpoint and wallet CBOMs use CycloneDX 1.7 crypto properties,
evidence occurrences, annotations, and namespaced provenance. The artifact
lane forwards Theia's own CycloneDX document. See the
[CBOM reference](docs/reference/cbom.md) for the exact schemas and evidence
model.

## Read the result correctly

QuReddy reports observations, local scanner capabilities, findings, and
interpretations as separate parts of a result. A finding can identify weak or
classical cryptography even when the scan itself completed successfully.
Unknown and unavailable states remain explicit so automation can distinguish
missing evidence from a favorable result.

The scan describes the evidence collected from the selected target. TLS
certificate trust and revocation, SSH authentication, and an authenticated IKE
tunnel require evidence outside the corresponding discovery probe.

## Exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Scan completed; inspect the reported posture and findings |
| `2` | Target connection, handshake, timeout, or parse failure |
| `3` | Required local tool is missing or unusable |
| `4` | Invalid target, option, or configuration |
| `70` | Internal QuReddy error |

Scripts should branch on the exit code and then inspect the structured result.
See the [exit-code reference](docs/reference/exit-codes.md) for scanner-specific
behavior.

## Network and privacy

QuReddy connects to the target named on the command line. TLS, SSH, and IKE
scans use bounded probes; wallet scans contact the configured indexer or RPC
endpoint; image scans use the Docker daemon when requested. QuReddy sends no
telemetry to BreachSAFE. Scan history and redirected result files remain on the
operator's system unless the operator sends them elsewhere.

Scan only systems and accounts you are authorized to inspect.

## Documentation

- [Documentation index](docs/README.md)
- [CLI reference](docs/reference/cli.md)
- [Install and troubleshoot](docs/how-to/install.md)
- [Docker and GHCR guide](docs/how-to/docker.md)
- [Scan an IKE endpoint](docs/how-to/scan-ike.md)
- [Generate and validate a CBOM](docs/how-to/generate-a-cbom.md)
- [JSON output for CI](docs/how-to/json-output-for-ci.md)
- [Security policy](SECURITY.md)
- [Issue tracker](https://github.com/breachsafe/qureddy/issues)

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[contributor documentation](docs/contributors/). Changes should preserve the
single canonical result model, bounded subprocess behavior, output parity, and
the evidence contracts documented in this repository.

## Open-source stack

<p align="center">
  <a href="https://www.python.org/"><img src="https://cdn.simpleicons.org/python/3776AB" alt="Python" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://www.openssl.org/"><img src="https://cdn.simpleicons.org/openssl/00D4FF" alt="OpenSSL" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://www.docker.com/"><img src="https://cdn.simpleicons.org/docker/2496ED" alt="Docker" width="48" height="48"></a>&nbsp;&nbsp;
  <a href="https://test.pypi.org/project/breachsafe-qureddy/"><img src="https://cdn.simpleicons.org/pypi/3775A9" alt="TestPyPI" width="48" height="48"></a>
</p>

CLI: [Click](https://click.palletsprojects.com/) and
[Rich](https://github.com/Textualize/rich) · Artifacts:
[CycloneDX CBOM](https://cyclonedx.org/) · Tooling:
[uv](https://docs.astral.sh/uv/)

## License

Apache License 2.0. See [`LICENSE`](LICENSE), [`LICENSES/`](LICENSES/), and
[`REUSE.toml`](REUSE.toml).
