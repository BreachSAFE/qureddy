# Run QuReddy with Docker

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

The QuReddy container packages the release wheel with a checksum-verified
OpenSSL 3.5.7 runtime. It runs as an unprivileged user and is published to the
BreachSAFE GitHub Container Registry (GHCR) and Docker Hub mirror.

## Contents

1. [Pull the release image](#1-pull-the-release-image)
2. [Run a TLS scan](#2-run-a-tls-scan)
3. [Run an SSH scan](#3-run-an-ssh-scan)
4. [Write JSON or CBOM output](#4-write-json-or-cbom-output)
5. [Pin the image digest](#5-pin-the-image-digest)
6. [Build locally](#6-build-locally)
7. [Publish a release image](#7-publish-a-release-image)

## 1. Pull the release image

If Docker is installed, no Python or OpenSSL setup is required. Run a scan
directly; Docker downloads the image automatically:

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan tls mozilla.org
```

For SSH:

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan ssh github.com
```

The container needs outbound TCP port 443 for TLS or TCP port 22 for SSH.

If Docker Hub is unavailable, run the same commands from GHCR:

```bash
docker run --rm ghcr.io/breachsafe/qureddy:latest scan tls mozilla.org
docker run --rm ghcr.io/breachsafe/qureddy:latest scan ssh github.com
```

The current image does not bundle the GPL-licensed stock `ike-scan`
executable. Run `qureddy scan ike` from a local installation that can resolve
`ike-scan`; do not treat the container's missing executable as absent IKE
support in the Python package.

To download the image without running a scan:

```bash
docker pull ghcr.io/breachsafe/qureddy:latest
```

The GHCR image is also available:

```bash
docker pull docker.io/breachsafe/qureddy:latest
```

GHCR is the canonical image registry. Both registries are promoted from the same
verified multi-architecture manifest.

Docker Hub applies limits to unauthenticated pulls. Authenticate with
`docker login` for automation, or use the GHCR copy when Docker Hub access is
limited.

The image includes the TLS collector. A host OpenSSL installation and
`QUREDDY_OPENSSL` setting are unnecessary inside the container.

## 2. Run a TLS scan

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan tls pq.cloudflareresearch.com
```

For an IP target that requires SNI:

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan tls 1.1.1.1:443 --sni one.one.one.one
```

## 3. Run an SSH scan

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan ssh github.com
```

SSH scans need outbound TCP 22 access and do not invoke OpenSSL.

## 4. Write JSON or CBOM output

```bash
docker run --rm docker.io/breachsafe/qureddy:latest \
  scan tls pq.cloudflareresearch.com --format json > scan.json

docker run --rm docker.io/breachsafe/qureddy:latest \
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
`linux/amd64` and `linux/arm64` on native runners, promotes the same manifest to
Docker Hub, and emits the version tag, `latest`, and a commit (`sha-`) tag. Pull
requests run the smoke gate but never publish.

Publishing requires the GHCR package to grant this repository write access under
the package's "Manage Actions access" settings. Docker Hub publication additionally
requires the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`. The
workflow fails closed when either registry authentication or digest verification
fails.

See [installation and troubleshooting](install.md), [CBOM reference](../reference/cbom.md),
and [exit codes](../reference/exit-codes.md) for the surrounding contracts.
