#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0

# Registry signature indexes can be briefly stale after `cosign sign`. Retry
# only that read-after-write boundary, then fail closed before mutable tags move.

set -u

readonly MAX_ATTEMPTS=5
readonly OIDC_ISSUER="https://token.actions.githubusercontent.com"
readonly IDENTITY_REGEXP='^https://github.com/BreachSAFE/qureddy/\.github/workflows/'

if [ "$#" -ne 1 ] || [ -z "$1" ]; then
  echo "usage: $0 <image-reference>" >&2
  exit 2
fi

image_ref="$1"
attempt=1

while [ "$attempt" -le "$MAX_ATTEMPTS" ]; do
  if cosign verify "$image_ref" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    --certificate-identity-regexp "$IDENTITY_REGEXP"; then
    exit 0
  fi

  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    echo "cosign verification failed after ${MAX_ATTEMPTS} attempts: ${image_ref}" >&2
    exit 1
  fi

  delay_seconds=$((attempt * 2))
  echo "cosign verification attempt ${attempt} failed; retrying in ${delay_seconds}s" >&2
  sleep "$delay_seconds"
  attempt=$((attempt + 1))
done
