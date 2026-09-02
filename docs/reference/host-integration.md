<!-- SPDX-FileCopyrightText: 2026 BreachSAFE -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Host integration reference

[![Diátaxis reference](https://img.shields.io/badge/Di%C3%A1taxis-reference-1f6feb?style=flat-square)](https://diataxis.fr/reference/)

This page documents the contract used by a BreachSAFE EnXemble host to run
QuReddy and consume its machine-readable result.

## Contents

1. [Execution boundary](#1-execution-boundary)
2. [Command shape](#2-command-shape)
3. [Artifact and streams](#3-artifact-and-streams)
4. [Exit-code contract](#4-exit-code-contract)
5. [CBOM validation and posture](#5-cbom-validation-and-posture)
6. [OSS and Enterprise boundary](#6-oss-and-enterprise-boundary)
7. [Related documentation](#7-related-documentation)

## 1. Execution boundary

The host invokes the `qureddy` CLI. There is no QuReddy daemon or API for the
host to call. A packaged installation places `qureddy` on `PATH`; a container
deployment can use the descriptor's Docker fallback image
`ghcr.io/breachsafe/qureddy:<tag>`.

The host's canonical descriptors currently cover TLS and SSH. IKE produces the
same machine artifact contract, but a host descriptor is not part of this change.

## 2. Command shape

The descriptors build commands equivalent to:

```text
qureddy scan tls <host>:<port> --format cbom [--timeout N] [--sni NAME]
qureddy scan ssh <host>:<port> --format cbom [--timeout N]
qureddy scan ike <host>:<port> --format cbom [--timeout N] [--nat-t]
```

Each value is passed as its own argument by the host; it is not interpolated
into a shell command. `cbom` is the default because it is the validated
CycloneDX 1.7 artifact. `json` is available for the raw scan document.

## 3. Artifact and streams

With `--format cbom` or `--format json`, the single parseable document is written
to **stdout**. The host captures stdout as the artifact. Diagnostics are kept on
stderr; a successful machine-format scan does not mix human text into stdout.

Do not pass `--output`/`-o` when the host is capturing stdout: that option writes
the document to a file and intentionally leaves stdout empty. The host descriptor
uses `artifact_from: stdout` and names the resulting artifact `cbom.json`.

## 4. Exit-code contract

Hosts must branch on the exit code for execution state, not treat a readiness
finding as process failure:

| Code | Meaning |
|---:|---|
| 0 | Scan completed; inspect posture and `scan.status`. A vulnerable finding can still exit 0. |
| 2 | Target connection, handshake, timeout, or parsing failure. |
| 3 | Required local executable missing or unsupported; TLS and IKE only. |
| 4 | Usage or configuration error. |
| 70 | Internal QuReddy error. |

See the [exit-code reference](exit-codes.md) for the complete contract.

## 5. CBOM validation and posture

The host can validate a CBOM against the CycloneDX 1.7 schema and show an
evidence badge. That badge describes document validity, not endpoint security.
Readiness is a separate value from the namespaced properties:

- `qureddy:scan.readiness`: `quantum_vulnerable`, `classically_weak`,
  `transitional_hybrid`, `quantum_safe`, `unknown`, or `not_applicable`;
- `qureddy:scan.status`: `completed` or a typed failure category.

A schema-valid CBOM with `quantum_vulnerable` posture is valid evidence of a
classically exposed endpoint, not a green security verdict. Preserve unknown and
failure states rather than converting them to safe/valid.

## 6. OSS and Enterprise boundary

QuReddy is the evidence layer: it produces protocol observations, the CBOM, and
the readiness posture. Compliance interpretation is outside the base scanner.
The UX `Convert to OSCAL` chain is feature-flagged (`mint_oscal`) and belongs to
the Enterprise/OSCAL tooling; it must not be described as a QuReddy OSS output.

## 7. Related documentation

- [CycloneDX CBOM reference](cbom.md)
- [CLI options](cli.md)
- [Exit codes](exit-codes.md)
- [Run QuReddy with a GUI](../how-to/run-with-a-gui.md)
