#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# Manual GHCR publish for the QuReddy container image.
#
# This is the MANUAL fallback path for when the `.github/workflows/container.yml`
# workflow is disabled (e.g. GitHub Actions turned off for the repo). The workflow
# is the normal path: it builds + pushes automatically on a published Release.
#
# Prerequisites:
#   - Docker with buildx, and a builder that can target linux/amd64 + linux/arm64.
#   - You MUST authenticate to GHCR first, e.g.:
#         echo "$GHCR_TOKEN" | docker login ghcr.io -u <user> --password-stdin
#     (token needs write:packages scope for ghcr.io/breachsafe/qureddy).
#
# It reads the version from pyproject.toml (the single source of truth) to tag and
# label the image, then builds + pushes the multi-arch image. The Dockerfile builds
# the release wheel from source in-image (issue #253), so no host wheel is needed.

set -euo pipefail

# cd to repo root (parent of this script's scripts/ directory).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

# Single source of truth: [project] version in pyproject.toml.
VERSION="$(grep -m1 -E '^version[[:space:]]*=' pyproject.toml | sed -E 's/.*"([^"]+)".*/\1/')"
if [ -z "$VERSION" ]; then
  echo "ERROR: could not read version from pyproject.toml" >&2
  exit 1
fi

REVISION="$(git rev-parse HEAD)"
SHA_TAG="sha-$(echo "$REVISION" | cut -c1-12)"

echo "Publishing ghcr.io/breachsafe/qureddy:$VERSION (revision $REVISION)"
echo "NOTE: requires 'docker login ghcr.io' first. This is the MANUAL path used"
echo "      when the container.yml GitHub Actions workflow is disabled."

docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg QUREDDY_VERSION="$VERSION" \
  --label org.opencontainers.image.version="$VERSION" \
  --label org.opencontainers.image.revision="$REVISION" \
  -t "ghcr.io/breachsafe/qureddy:$VERSION" \
  -t "ghcr.io/breachsafe/qureddy:latest" \
  -t "ghcr.io/breachsafe/qureddy:$SHA_TAG" \
  --push \
  .

echo "Pushed ghcr.io/breachsafe/qureddy tags: $VERSION, latest, $SHA_TAG"
