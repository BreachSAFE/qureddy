# Run QuReddy with Docker

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

The QuReddy container packages the release wheel with a checksum-verified
OpenSSL 3.5.7 runtime. It runs as an unprivileged user and is published to the
BreachSAFE GitHub Container Registry (GHCR).

## Contents

1. [Pull the release image](#1-pull-the-release-image)
2. [Run a TLS scan](#2-run-a-tls-scan)
3. [Run an SSH scan](#3-run-an-ssh-scan)
4. [Write JSON or CBOM output](#4-write-json-or-cbom-output)
5. [Pin the image digest](#5-pin-the-image-digest)
6. [Build locally](#6-build-locally)
7. [Publish a release image](#7-publish-a-release-image)

## 1. Pull the release image

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
```

The image includes the TLS collector. A host OpenSSL installation and
`QUREDDY_OPENSSL` setting are unnecessary inside the container.

## 2. Run a TLS scan

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan tls pq.cloudflareresearch.com
```

For an IP target that requires SNI:

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan tls 1.1.1.1:443 --sni one.one.one.one
```

## 3. Run an SSH scan

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan ssh github.com
```

SSH scans need outbound TCP 22 access and do not invoke OpenSSL.

## 4. Write JSON or CBOM output

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan tls pq.cloudflareresearch.com --format json > scan.json

docker run --rm ghcr.io/breachsafe/qureddy:latest \
  scan ssh github.com --format cbom > github-ssh.cdx.json
```

CBOM output is CycloneDX 1.7. Machine output goes to standard output;
diagnostics remain on standard error unless verbosity is requested. The
documented exit-code contract applies inside the container, including exit
code `2` for a target handshake failure and `3` for a local TLS collector
failure.

## 5. Pin the image digest

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
docker image inspect ghcr.io/breachsafe/qureddy:latest \
  --format '{{index .RepoDigests 0}}'
```

Replace the tag with the returned `@sha256:...` reference in production jobs.

## 6. Build locally

A fresh clone builds with no prerequisites; the image builds the wheel from
source in an in-image stage, so no host `python -m build` step is needed:

```bash
docker build --tag qureddy:local .
docker run --rm qureddy:local --version
```

The Dockerfile verifies the OpenSSL source archive SHA-256 before compiling,
builds the wheel from source, and copies only the installed runtime into the
final image.

## 7. Publish a release image

The repository workflow at `.github/workflows/container.yml` publishes when a
GitHub Release is published, and on demand through a manual dispatch with
`publish=true`. It authenticates to GHCR with the repository token, builds
`linux/amd64` and `linux/arm64` on native runners, and emits the version tag,
`latest`, and a commit (`sha-`) tag. Pull requests run the smoke gate but never
publish.

Publishing requires the GHCR package to grant this repository write access under
the package's "Manage Actions access" settings. Without it the push fails with
`denied: permission_denied: write_package` even though the workflow already holds
`packages: write`.

See [installation and troubleshooting](install.md), [CBOM reference](../reference/cbom.md),
and [exit codes](../reference/exit-codes.md) for the surrounding contracts.
