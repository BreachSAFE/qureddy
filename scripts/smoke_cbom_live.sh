#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
set -u -o pipefail

# Live conformance smoke test for the one-scan output bundle. This deliberately
# does not use exit status as the evidence: a target can reject or time out and
# still need to produce valid, correlated JSON/CBOM/JSONL/Rich artifacts.

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
timeout_seconds=${QUREDDY_SMOKE_TIMEOUT:-8}
keep_artifacts=${QUREDDY_KEEP_SMOKE_ARTIFACTS:-0}

if ! [[ "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
    printf 'QUREDDY_SMOKE_TIMEOUT must be a positive integer\n' >&2
    exit 4
fi

tmp_parent=${TMPDIR:-/tmp}
run_root=$(mktemp -d "${tmp_parent%/}/qureddy-cbom-live.XXXXXX") || exit 3
cleanup() {
    if [[ "$keep_artifacts" == 1 ]]; then
        printf 'Artifacts retained at %s\n' "$run_root" >&2
    else
        rm -r -- "$run_root"
    fi
}
trap cleanup EXIT

failures=0
run_count=0

validate_bundle() {
    local run_dir=$1
    local scanner=$2
    local target=$3
    local stdout_path=$4

    if [[ -s "$stdout_path" ]]; then
        printf 'FAIL %s %s: stdout was not clean in bundle mode\n' "$scanner" "$target" >&2
        failures=$((failures + 1))
    fi

    uv run --locked python "$repo_root/scripts/validate_output_bundle.py" \
        --run-dir "$run_dir" --scanner "$scanner" --target "$target"
    local validation_rc=$?
    if (( validation_rc != 0 )); then
        printf 'FAIL %s %s: artifact validation failed\n' "$scanner" "$target" >&2
        failures=$((failures + 1))
    fi
}

run_scan() {
    local label=$1
    local scanner=$2
    local target=$3
    shift 3
    local run_dir="$run_root/$label"
    mkdir -p "$run_dir"
    run_count=$((run_count + 1))

    local stdout_path="$run_dir/cli.stdout"
    local stderr_path="$run_dir/cli.stderr"
    local -a command=(
        uv run --locked qureddy scan "$scanner" "$target"
        --output-dir "$run_dir"
        --timeout "$timeout_seconds"
        --deterministic
        "$@"
    )
    printf 'RUN  %-12s %s\n' "$scanner" "$target"
    "${command[@]}" >"$stdout_path" 2>"$stderr_path"
    local cli_rc=$?
    printf 'CLI  %-12s rc=%s\n' "$label" "$cli_rc"
    if (( cli_rc != 0 )); then
        printf 'FAIL %s %s: unexpected CLI exit %s\n' "$scanner" "$target" "$cli_rc" >&2
        failures=$((failures + 1))
    fi
    validate_bundle "$run_dir" "$scanner" "$target" "$stdout_path"
    if [[ -s "$run_dir/scan.rich.txt" ]]; then
        printf '\n--- Rich output: %s %s ---\n' "$scanner" "$target"
        cat "$run_dir/scan.rich.txt"
    fi
}

printf 'QuReddy live CBOM conformance smoke\n'
printf 'repo=%s timeout=%ss\n' "$repo_root" "$timeout_seconds"

run_scan tls_google tls www.google.com
run_scan tls_badssl12 tls tls-v1-2.badssl.com:1012
run_scan tls_badssl11 tls tls-v1-1.badssl.com:1011
run_scan tls_badssl10 tls tls-v1-0.badssl.com:1010
run_scan ssh_github ssh github.com
run_scan ike_hide_me ike netherlands.hide.me --nat-t

printf 'RESULT scans=%s failures=%s\n' "$run_count" "$failures"
if (( failures != 0 )); then
    exit 1
fi
