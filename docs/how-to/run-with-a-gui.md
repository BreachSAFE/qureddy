<!-- SPDX-FileCopyrightText: 2026 BreachSAFE -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Run QuReddy with a GUI

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

Use the BreachSAFE EnXemble reference host when you want a browser UI for
QuReddy's TLS and SSH scans. The host captures the CLI's CycloneDX CBOM and
displays evidence validity separately from readiness posture.

## Contents

1. [Start the reference host](#1-start-the-reference-host)
2. [Run a scan](#2-run-a-scan)
3. [Understand the two results](#3-understand-the-two-results)
4. [Enterprise conversion boundary](#4-enterprise-conversion-boundary)
5. [Run from source](#5-run-from-source)

## 1. Start the reference host

The reference host is maintained in the BreachSAFE organization. Use its
published deployment image and descriptor for the current image name:

```bash
docker run --rm --pull=always -p 7860:7860 \
  --name enxemble <enxemble-image>:latest
```

Open <http://127.0.0.1:7860>. Pin the image by digest for a reproducible
deployment; `:latest` is convenient for trying the reference host, not an
immutable production reference.

## 2. Run a scan

Use the TLS and SSH audit tabs. Both tabs invoke QuReddy with `--format cbom` by
default and capture the document from stdout. TLS accepts a host, port, timeout,
and optional SNI; SSH accepts a host, port, and timeout. The container needs
outbound TCP 443 for TLS targets and TCP 22 for SSH targets.

The host also supports a local installation. In that mode, install
`breachsafe-qureddy` so `qureddy --version` resolves on `PATH`; the host does not
bundle a separate API client.

## 3. Understand the two results

The evidence badge answers: “is this CBOM structurally valid CycloneDX 1.7?”
The readiness banner answers: “what posture did the scan observe?” These are
independent. A valid CBOM can report `quantum_vulnerable`, and an unavailable or
failed scan must remain unknown rather than becoming safe.

For the underlying fields and exit behavior, see the
[host integration reference](../reference/host-integration.md).

## 4. Enterprise conversion boundary

QuReddy itself emits facts and evidence: observations, CBOM, scan status, and
readiness posture. The optional `Convert to OSCAL` action is feature-flagged by
the host (`mint_oscal`) and belongs to the Enterprise compliance/tooling path.
The base QuReddy package does not emit an OSCAL compliance verdict.

## 5. Run from source

For host development, follow the EnXemble source instructions in the
BreachSAFE organization. The host must be able to resolve a Python 3.14+
QuReddy installation on `PATH`. Use the descriptor files in the host repository
as the source of truth for command arguments and artifact handling.
