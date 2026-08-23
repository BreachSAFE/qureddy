# Your first post-quantum readiness scan

This tutorial starts with an SSH endpoint because that path has no OpenSSL
prerequisite. It then adds the local OpenSSL collector and runs a TLS scan.
You will finish with one human report and one parseable JSON result.

## Contents

1. [Install QuReddy](#1-install-qureddy)
2. [Check the command](#2-check-the-command)
3. [Scan an SSH endpoint](#3-scan-an-ssh-endpoint)
4. [Read the SSH result](#4-read-the-ssh-result)
5. [Prepare OpenSSL](#5-prepare-openssl)
6. [Scan a TLS endpoint](#6-scan-a-tls-endpoint)
7. [Capture JSON](#7-capture-json)
8. [What you verified](#8-what-you-verified)
9. [Next steps](#9-next-steps)

## 1. Install QuReddy

This tutorial runs the `qureddy` command directly, so install it locally with
`pipx`. QuReddy requires Python `>=3.12` and is intentionally published to TestPyPI
only for now. Install from TestPyPI with PyPI as a fallback for runtime dependencies:

```bash
pipx install --python 3.12 \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
```

If `pipx` or Python 3.12 is not available, follow the
[installation guide](../how-to/install.md).

To run QuReddy without a local install, use the container image and prefix each
command below with `docker run --rm ghcr.io/breachsafe/qureddy:latest`, for example
`docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com`.

## 2. Check the command

This command is offline:

```bash
qureddy --version
```

The release candidate prints:

```text
BreachSAFE QuReddy <version> -- https://www.breachsafe.ai
```

## 3. Scan an SSH endpoint

The following command opens a read-only connection to `github.com` on TCP
port 22:

```bash
qureddy scan ssh github.com
```

The scan reads the server identification and the offered SSH key exchange and
host key algorithms. It does not authenticate or open a shell.

## 4. Read the SSH result

The report separates key exchange posture from host key posture:

- `transitional_hybrid` means the server offered a recognized post-quantum
  hybrid key exchange.
- `quantum_vulnerable` means the observed key exchange offer was classical
  only.
- `classically_weak` means the server offered a deprecated weak host key
  algorithm such as `ssh-dss`.
- `unknown` means the available evidence could not establish the posture.

Exit `0` means the scan completed. It does not mean that the target received a
favorable readiness result.

## 5. Prepare OpenSSL

TLS scans require OpenSSL 3.5.7 LTS with the `X25519MLKEM768` group. Check
the selected binary:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

On macOS, Homebrew's `openssl@3.5` formula is a moving 3.5.x channel. Inspect
it before selecting it:

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
```

If the formula has moved, use the checksum-pinned source build or container
documented in the [installation guide](../how-to/install.md). The same guide
covers Linux and Windows.

## 6. Scan a TLS endpoint

The following command opens bounded TLS handshakes to
`pq.cloudflareresearch.com` on TCP port 443:

```bash
qureddy scan tls pq.cloudflareresearch.com
```

The scan records:

- hybrid TLS 1.3 key exchange behavior;
- a classical TLS 1.3 control;
- offered TLS 1.0, 1.1, and 1.2 protocols and cipher suites;
- the observed leaf certificate signature algorithm.

The result does not establish certificate trust, revocation, remote software
identity, or a complete cryptographic inventory.

## 7. Capture JSON

Run the SSH scan in machine mode:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
python -m json.tool github-ssh.json > /dev/null
```

The document begins with `schema_version: "qureddy.scan.v1"` and contains the
scan, target, dependencies, assets, evidence, findings, and summary objects.
Identifiers and timestamps change on every run, so automation should select
named fields instead of comparing the whole document byte for byte.

## 8. What you verified

You used an installed command to:

1. scan SSH without OpenSSL;
2. distinguish scan completion from readiness;
3. select a suitable local OpenSSL binary for TLS;
4. run the TLS evidence pipeline;
5. capture one parseable JSON document.

## 9. Next steps

- [Generate and validate a CycloneDX 1.7 CBOM](../how-to/generate-a-cbom.md)
- [Scan an SSH or SFTP endpoint](../how-to/scan-ssh.md)
- [Capture machine output for CI](../how-to/json-output-for-ci.md)
- [Review every CLI option](../reference/cli.md)
