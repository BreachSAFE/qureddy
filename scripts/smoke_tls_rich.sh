#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Run the required dual-runtime TLS smoke scans directly in the terminal.

set -euo pipefail

legacy_openssl="${QUREDDY_LEGACY_OPENSSL:-}"
timeout_seconds="${QUREDDY_TIMEOUT:-8}"

if [[ -z "${legacy_openssl}" || ! -x "${legacy_openssl}" ]]; then
  printf 'WARNING: OpenSSL 1.0.2u not found; compatibility coverage is limited.\n' >&2
  legacy_openssl=""
fi

overall_status=0

if [[ -n "${legacy_openssl}" ]]; then
  printf 'OpenSSL 1.0.2u: '
  "${legacy_openssl}" version
fi

run_scan() {
  if [[ -n "${legacy_openssl}" ]]; then
    QUREDDY_LEGACY_OPENSSL="${legacy_openssl}" \
      uv run --locked qureddy scan tls "$1" \
        --format rich \
        --timeout "${timeout_seconds}"
  else
    env -u QUREDDY_LEGACY_OPENSSL \
      uv run --locked qureddy scan tls "$1" \
        --format rich \
        --timeout "${timeout_seconds}"
  fi
}

for target in badssl.com pecutx.org; do
  printf '\n=== %s ===\n' "${target}"
  set +e
  run_scan "${target}"
  target_status=$?
  set -e
  if (( target_status != 0 )); then
    printf 'Target exit code: %d\n' "${target_status}" >&2
    overall_status="${target_status}"
  fi
done

exit "${overall_status}"
