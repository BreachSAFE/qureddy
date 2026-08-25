# How to generate a CBOM

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

Use `--format cbom` with either scanner to write a CycloneDX Cryptography
Bill of Materials to standard output.

## Contents

1. [TLS endpoint](#1-tls-endpoint)
2. [SSH endpoint](#2-ssh-endpoint)
3. [Validate the final bytes](#3-validate-the-final-bytes)
4. [Evidence limits](#4-evidence-limits)
5. [Related documentation](#5-related-documentation)

## 1. TLS endpoint

TLS scanning requires OpenSSL 3.5.7 LTS:

```bash
qureddy scan tls example.com --format cbom > example-tls.cbom.json
```

## 2. SSH endpoint

SSH scanning has no OpenSSL dependency:

```bash
qureddy scan ssh github.com --format cbom > github-ssh.cbom.json
```

QuReddy writes the CBOM document to stdout. Redirect it to a file as shown
above, and use the process exit code to distinguish a successful scan from a
target, local-dependency, usage, or internal failure.

## 3. Validate the final bytes

QuReddy emits CycloneDX 1.7. The release gate validates the final bytes against
the pinned CycloneDX 1.7.1 JSON schemas, `cyclonedx-cli` 0.33.1, and QuReddy's
semantic checks. See the
[CBOM conformance procedure](../contributors/cbom-conformance.md) for the
reproducible validator commands and pinned digests.

Check JSON syntax with Python:

```bash
python -m json.tool github-ssh.cbom.json > /dev/null
```

Then validate with CycloneDX CLI 0.33.1:

```bash
cyclonedx --version
cyclonedx validate \
  --input-file github-ssh.cbom.json \
  --input-format json \
  --input-version v1_7 \
  --fail-on-errors
```

Use the checksum-pinned platform asset recorded in
[`tests/conformance/cyclonedx-cli-v0.33.1.json`](../../tests/conformance/cyclonedx-cli-v0.33.1.json)
when reproducing release evidence. The repository-owned release gate downloads
and verifies that asset before running the validator.

Confirm the declared version:

```bash
python -c 'import json; print(json.load(open("github-ssh.cbom.json"))["specVersion"])'
```

The expected value is `1.7`.

## 4. Evidence limits

The CBOM reports observations made by QuReddy. It is not a claim of complete
cryptographic inventory, remote implementation identity, certificate trust,
or revocation validation.

## 5. Related documentation

- [CLI options](../reference/cli.md)
- [Exit codes](../reference/exit-codes.md)
- [Capture machine-readable output for CI](json-output-for-ci.md)
