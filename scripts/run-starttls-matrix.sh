#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
set -u -o pipefail

# Run against real services. This script does not start, fake, or replay a server.
# Override QUREDDY_BIN, QUREDDY_OUT, and QUREDDY_TIMEOUT for a local lab.
QUREDDY_BIN="${QUREDDY_BIN:-qureddy}"
QUREDDY_OUT="${QUREDDY_OUT:-./starttls-evidence-$(date +%Y%m%dT%H%M%S)}"
QUREDDY_TIMEOUT="${QUREDDY_TIMEOUT:-3}"

mkdir -p "$QUREDDY_OUT"

run_scan() {
  local name="$1" target="$2" mode="${3:-}" dir="$QUREDDY_OUT/$1" code
  mkdir -p "$dir"
  printf '\n== %s: %s%s ==\n' "$name" "$target" \
    "${mode:+ (STARTTLS $mode)}"
  if [[ -n "$mode" ]]; then
    "$QUREDDY_BIN" scan tls "$target" --starttls "$mode" \
      --format json --output-dir "$dir" --timeout "$QUREDDY_TIMEOUT" \
      -vvv --log "$dir/run.log" >"$dir/stdout.txt" 2>"$dir/stderr.txt"
  else
    "$QUREDDY_BIN" scan tls "$target" \
      --format json --output-dir "$dir" --timeout "$QUREDDY_TIMEOUT" \
      -vvv --log "$dir/run.log" >"$dir/stdout.txt" 2>"$dir/stderr.txt"
  fi
  code=$?
  printf 'exit=%s\n' "$code"
  if [[ -f "$dir/scan.json" ]] && command -v jq >/dev/null 2>&1; then
    jq -r '[.scan.status, (.summary.readiness // "unknown"), (.summary.hndl_exposure // "unknown")] | @tsv' \
      "$dir/scan.json"
  fi
  return 0
}

# OpenLDAP, Dovecot, and Pure-FTPd lab services.
run_scan ldap-starttls 127.0.0.1:389 ldap
run_scan ldaps 127.0.0.1:636
run_scan imap-starttls 127.0.0.1:143 imap
run_scan imaps 127.0.0.1:993
run_scan pop3-starttls 127.0.0.1:110 pop3
run_scan pop3s 127.0.0.1:995
run_scan ftp-starttls 127.0.0.1:21 ftp

# Postfix, when the lab listener is enabled.
run_scan smtp 127.0.0.1:25 smtp
run_scan submission 127.0.0.1:587 smtp
run_scan smtps 127.0.0.1:465

# High-port database services.
run_scan postgres 127.0.0.1:5432 postgres
run_scan mysql 127.0.0.1:3306 mysql

printf '\nEvidence root: %s\n' "$QUREDDY_OUT"
printf 'Each attempted target has stdout.txt, stderr.txt, run.log, and any generated scan artifacts.\n'
