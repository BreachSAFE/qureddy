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

    uv run --locked python - "$repo_root" "$run_dir" "$scanner" "$target" <<'PY'
from __future__ import annotations

import json
import sys
from pathlib import Path

repo_root, run_dir_name, expected_scanner, expected_target = sys.argv[1:]
sys.path.insert(0, repo_root)

from tests.conformance.harness import official_errors, semantic_errors  # noqa: E402

run_dir = Path(run_dir_name)
required = ("scan.json", "scan.cdx.json", "scan.jsonl", "scan.rich.txt")
missing = [name for name in required if not (run_dir / name).is_file()]
if missing:
    raise SystemExit(f"missing bundle artifacts: {', '.join(missing)}")

canonical = json.loads((run_dir / "scan.json").read_text(encoding="utf-8"))
scan = canonical.get("scan")
target = canonical.get("target")
if not isinstance(scan, dict) or not isinstance(target, dict):
    raise SystemExit("scan.json missing scan or target object")
if scan.get("scanner_name") != expected_scanner:
    raise SystemExit(f"scanner mismatch: {scan.get('scanner_name')!r}")
if target.get("original_input") != expected_target:
    raise SystemExit(
        f"target mismatch: {target.get('original_input')!r} != {expected_target!r}"
    )
scan_id = scan.get("scan_id")
scan_status = scan.get("status")
if not isinstance(scan_id, str) or not scan_id:
    raise SystemExit("scan.json has no scan_id")
if not isinstance(scan_status, str) or not scan_status:
    raise SystemExit("scan.json has no status")

cbom = json.loads((run_dir / "scan.cdx.json").read_text(encoding="utf-8"))
schema_errors = official_errors(cbom)
semantic = semantic_errors(cbom)
if schema_errors or semantic:
    details = " | ".join(schema_errors + semantic)
    raise SystemExit(f"CBOM validation failed: {details}")
if cbom.get("specVersion") != "1.7":
    raise SystemExit("CBOM is not CycloneDX 1.7")
if not isinstance(cbom.get("components"), list):
    raise SystemExit("CBOM components is not an array")
properties = {
    item.get("name"): item.get("value")
    for item in cbom.get("metadata", {}).get("properties", [])
    if isinstance(item, dict)
}
if properties.get("qureddy:scan.scanner_name") != expected_scanner:
    raise SystemExit("CBOM scanner identity is not correlated with scan.json")
if properties.get("qureddy:target.original_input") != expected_target:
    raise SystemExit("CBOM target identity is not correlated with scan.json")

records = []
for line_number, line in enumerate(
    (run_dir / "scan.jsonl").read_text(encoding="utf-8").splitlines(), 1
):
    if not line.strip():
        continue
    try:
        records.append(json.loads(line))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"JSONL line {line_number} is invalid: {exc}") from exc
if not records:
    raise SystemExit("scan.jsonl is empty")
summary = records[-1]
if summary.get("type") != "scan_summary":
    raise SystemExit("scan.jsonl does not end with scan_summary")
if summary.get("scan_id") != scan_id or summary.get("status") != scan_status:
    raise SystemExit("JSONL summary is not correlated with scan.json")
for record in records[:-1]:
    metadata = record.get("info", {}).get("metadata", {})
    if metadata.get("scan_id") != scan_id:
        raise SystemExit("JSONL finding is not correlated with scan.json")

rich = (run_dir / "scan.rich.txt").read_text(encoding="utf-8")
if not rich.startswith("QuReddy"):
    raise SystemExit("Rich output does not carry the QuReddy header")
if expected_scanner.upper() not in rich.upper():
    raise SystemExit("Rich output does not identify the scanner")

print(
    f"status={scan_status} attempts={scan.get('total_attempts', 0)} "
    f"evidence={len(canonical.get('evidence', []))} "
    f"components={len(cbom['components'])} jsonl_records={len(records)}"
)
PY
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
