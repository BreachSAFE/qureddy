# Your first post-quantum readiness scan

This tutorial starts with an SSH endpoint because that path has no OpenSSL
prerequisite. It then adds the local OpenSSL collector and runs a TLS scan.
You will finish with one human report and one parseable JSON result.

## Contents

- [Install QuReddy](#install-qureddy)
- [Check the command](#check-the-command)
- [Scan an SSH endpoint](#scan-an-ssh-endpoint)
- [Read the SSH result](#read-the-ssh-result)
- [Prepare OpenSSL](#prepare-openssl)
- [Scan a TLS endpoint](#scan-a-tls-endpoint)
- [Capture JSON](#capture-json)
- [What you verified](#what-you-verified)
- [Next steps](#next-steps)

## Install QuReddy

QuReddy requires Python `>=3.12`.

```bash
pipx install breachsafe-qureddy
```

If `pipx` or Python 3.12 is not available, follow the
[installation guide](../how-to/install.md).

## Check the command

This command is offline:

```bash
qureddy --version
```

The release candidate prints:

```text
BreachSAFE QuReddy 0.2.4 -- https://www.breachsafe.ai
```

## Scan an SSH endpoint

The following command opens a read-only connection to `github.com` on TCP
port 22:

```bash
qureddy scan ssh github.com
```

The scan reads the server identification and the offered SSH key exchange and
host key algorithms. It does not authenticate or open a shell.

## Read the SSH result

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

## Prepare OpenSSL

TLS scans require OpenSSL 3.5 LTS or newer with the `X25519MLKEM768` group. Check
the selected binary:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

On macOS with Homebrew:

```bash
brew install openssl@3.5
export QUREDDY_OPENSSL="$(brew --prefix openssl@3.5)/bin/openssl"
```

Use the [installation guide](../how-to/install.md) for Linux and Windows.

## Scan a TLS endpoint

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

## Capture JSON

Run the SSH scan in machine mode:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
python -m json.tool github-ssh.json > /dev/null
```

The document begins with `schema_version: "qureddy.scan.v1"` and contains the
scan, target, dependencies, assets, evidence, findings, and summary objects.
Identifiers and timestamps change on every run, so automation should select
named fields instead of comparing the whole document byte for byte.

## What you verified

You used an installed command to:

1. scan SSH without OpenSSL;
2. distinguish scan completion from readiness;
3. select a suitable local OpenSSL binary for TLS;
4. run the TLS evidence pipeline;
5. capture one parseable JSON document.

## Next steps

- [Generate and validate a CycloneDX 1.7 CBOM](../how-to/generate-a-cbom.md)
- [Scan an SSH or SFTP endpoint](../how-to/scan-ssh.md)
- [Capture machine output for CI](../how-to/json-output-for-ci.md)
- [Review every CLI option](../reference/cli.md)
