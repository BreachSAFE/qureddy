# Run QuReddy with Docker

The QuReddy container packages the release wheel with a checksum-verified
OpenSSL 3.5.7 runtime. It runs as an unprivileged user and is published to the
BreachSAFE GitHub Container Registry (GHCR).

## Contents

- [Pull the release image](#pull-the-release-image)
- [Run a TLS scan](#run-a-tls-scan)
- [Run an SSH scan](#run-an-ssh-scan)
- [Write JSON or CBOM output](#write-json-or-cbom-output)
- [Pin the image digest](#pin-the-image-digest)
- [Build locally](#build-locally)
- [Publish a release image](#publish-a-release-image)

## Pull the release image

```bash
docker pull --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0
```

The image includes the TLS collector. A host OpenSSL installation and
`QUREDDY_OPENSSL` setting are unnecessary inside the container.
The published `0.2.0` tag targets `linux/amd64`; Docker Desktop on Apple
Silicon runs it through its standard amd64 emulation.

## Run a TLS scan

```bash
docker run --rm --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0 \
  scan tls pq.cloudflareresearch.com
```

For an IP target that requires SNI:

```bash
docker run --rm --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0 \
  scan tls 1.1.1.1:443 --sni one.one.one.one
```

## Run an SSH scan

```bash
docker run --rm --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0 \
  scan ssh github.com
```

SSH scans need outbound TCP 22 access and do not invoke OpenSSL.

## Write JSON or CBOM output

```bash
docker run --rm --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0 \
  scan tls pq.cloudflareresearch.com --format json > scan.json

docker run --rm --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0 \
  scan ssh github.com --format cbom > github-ssh.cdx.json
```

CBOM output is CycloneDX 1.7. Machine output goes to standard output;
diagnostics remain on standard error unless verbosity is requested. The
documented exit-code contract applies inside the container, including exit
code `2` for a target handshake failure and `3` for a local TLS collector
failure.

## Pin the image digest

```bash
docker pull --platform linux/amd64 ghcr.io/breachsafe/qureddy:0.2.0
docker image inspect ghcr.io/breachsafe/qureddy:0.2.0 \
  --format '{{index .RepoDigests 0}}'
```

Replace the tag with the returned `@sha256:...` reference in production jobs.

## Build locally

```bash
python -m build --wheel
docker build --tag qureddy:local .
docker run --rm qureddy:local --version
```

The Dockerfile verifies the OpenSSL source archive SHA-256 before compiling
and copies only the installed runtime into the final image.

## Publish a release image

The repository workflow at `.github/workflows/container.yml` publishes only
through an explicit manual dispatch with `publish=true`. It authenticates to
GHCR with the repository token, builds the verified `linux/amd64` image, and
emits the version tag plus a commit tag. Pull requests run the smoke gate but
never publish.

See [installation and troubleshooting](install.md), [CBOM reference](../reference/cbom.md),
and [exit codes](../reference/exit-codes.md) for the surrounding contracts.
