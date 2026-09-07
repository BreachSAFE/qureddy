#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Run the dual-runtime TLS smoke scans directly in the terminal.
#
# This is intentionally TLS-only. SSH and IKE have different toolchains and
# failure semantics; run those lanes separately so one protocol cannot hide
# or mislabel another protocol's result.

set -euo pipefail

legacy_openssl="${QUREDDY_LEGACY_OPENSSL:-}"
timeout_seconds="${QUREDDY_TIMEOUT:-8}"

if [[ -n "${legacy_openssl}" ]]; then
  if [[ ! -x "${legacy_openssl}" ]]; then
    printf 'WARNING: configured OpenSSL 1.0.2u is not executable; compatibility coverage is limited.\n' >&2
    legacy_openssl=""
  fi
else
  for candidate in \
    /opt/openssl-legacy/bin/openssl \
    /opt/openssl10/bin/openssl \
    /usr/local/openssl-legacy/bin/openssl; do
    if [[ -x "${candidate}" ]]; then
      legacy_openssl="${candidate}"
      break
    fi
  done
  if [[ -z "${legacy_openssl}" ]]; then
    printf 'WARNING: OpenSSL 1.0.2u not found; compatibility coverage is limited.\n' >&2
  fi
fi

overall_status=0

printf 'QuReddy: '
uv run --locked qureddy --version

if command -v openssl >/dev/null 2>&1; then
  printf 'System OpenSSL: '
  openssl version
else
  printf 'WARNING: system OpenSSL is not on PATH.\n' >&2
fi

if [[ -n "${legacy_openssl}" ]]; then
  printf 'Legacy OpenSSL: '
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

# These are the authorized live TLS smoke targets: production PQ endpoints and
# controlled BadSSL protocol baselines. The IP/SNI case needs its own command.
for target in \
  www.cloudflare.com \
  pq.cloudflareresearch.com \
  www.google.com \
  tls-v1-2.badssl.com:1012 \
  tls-v1-1.badssl.com:1011 \
  tls-v1-0.badssl.com:1010; do
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
