#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# Read-only real-CLI pressure harness for QuReddy. It deliberately keeps the
# exploratory corpus outside the product test suite and records every command,
# stdout, stderr, exit code, and generated artifact under one run directory.
#
# Usage:
#   scripts/pressure_test_matrix.sh [--out-dir DIR] [--timeout SECONDS]
#
# The harness does not change source, git state, releases, or repository
# settings. Network targets are intentionally explicit and may be unavailable.

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT" || exit 1

OUT_DIR=""
TIMEOUT="5"

usage() {
  printf '%s\n' \
    'Usage: scripts/pressure_test_matrix.sh [--out-dir DIR] [--timeout SECONDS]' \
    '' \
    'Runs the supplemental public-endpoint matrix and records every result.' \
    'This exploratory harness is not a release or interoperability gate.'
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out-dir)
      [ "$#" -ge 2 ] || { echo "missing value for --out-dir" >&2; exit 64; }
      OUT_DIR="$2"; shift 2 ;;
    --timeout)
      [ "$#" -ge 2 ] || { echo "missing value for --timeout" >&2; exit 64; }
      TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 64 ;;
  esac
done

case "$TIMEOUT" in
  ''|0|*[!0-9]*) echo "timeout must be a positive integer" >&2; exit 64 ;;
esac

if [ -z "$OUT_DIR" ]; then
  PRESSURE_TMP_ROOT="${TMPDIR:-/tmp}"
  mkdir -p "$PRESSURE_TMP_ROOT" || exit 1
  OUT_DIR="$(mktemp -d "$PRESSURE_TMP_ROOT/qureddy-pressure-XXXXXX")" || exit 1
else
  mkdir -p "$OUT_DIR" || exit 1
fi

SUMMARY="$OUT_DIR/summary.tsv"
RUN_LOG="$OUT_DIR/harness.log"
printf 'id\tprotocol\ttarget\tformat\texit\tseconds\tstdout\tstderr\tartifacts\n' > "$SUMMARY"

if command -v uv >/dev/null 2>&1; then
  CLI=(uv run --locked qureddy)
elif command -v qureddy >/dev/null 2>&1; then
  CLI=(qureddy)
else
  echo "neither uv nor qureddy is available" >&2
  exit 69
fi

if ! CLI_VERSION="$("${CLI[@]}" --version 2>&1)"; then
  echo "qureddy CLI is not executable: $CLI_VERSION" >&2
  exit 69
fi

echo "QuReddy pressure matrix" | tee "$RUN_LOG"
echo "repo=$REPO_ROOT" | tee -a "$RUN_LOG"
echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unknown)" | tee -a "$RUN_LOG"
echo "cli=${CLI[*]}" | tee -a "$RUN_LOG"
echo "cli_version=$CLI_VERSION" | tee -a "$RUN_LOG"
echo "out=$OUT_DIR" | tee -a "$RUN_LOG"

run_case() {
  id="$1"; protocol="$2"; target="$3"; format="$4"; shift 4
  case_dir="$OUT_DIR/$id"
  mkdir -p "$case_dir"
  stdout="$case_dir/stdout"
  stderr="$case_dir/stderr"
  started="$(date +%s)"
  printf '\n[%s] %s scan %s --format %s\n' "$id" "$protocol" "$target" "$format" | tee -a "$RUN_LOG"
  "${CLI[@]}" scan "$protocol" "$target" --format "$format" --timeout "$TIMEOUT" "$@" >"$stdout" 2>"$stderr"
  status=$?
  ended="$(date +%s)"
  elapsed=$((ended - started))
  artifacts="-"
  if [ -d "$case_dir/output" ]; then
    artifacts="$(find "$case_dir/output" -maxdepth 1 -type f -print | sort | tr '\n' ',' | sed 's/,$//')"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$protocol" "$target" "$format" "$status" "$elapsed" \
    "$stdout" "$stderr" "$artifacts" >> "$SUMMARY"
  printf '[%s] exit=%s elapsed=%ss\n' "$id" "$status" "$elapsed" | tee -a "$RUN_LOG"
}

run_output_dir_case() {
  id="$1"; protocol="$2"; target="$3"
  case_dir="$OUT_DIR/$id"
  mkdir -p "$case_dir/output"
  stdout="$case_dir/stdout"
  stderr="$case_dir/stderr"
  started="$(date +%s)"
  printf '\n[%s] %s scan %s --output-dir\n' "$id" "$protocol" "$target" | tee -a "$RUN_LOG"
  "${CLI[@]}" scan "$protocol" "$target" --output-dir "$case_dir/output" --timeout "$TIMEOUT" -vvv >"$stdout" 2>"$stderr"
  status=$?
  ended="$(date +%s)"
  elapsed=$((ended - started))
  artifacts="$(find "$case_dir/output" -maxdepth 1 -type f -print | sort | tr '\n' ',' | sed 's/,$//')"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$id" "$protocol" "$target" output-dir "$status" "$elapsed" \
    "$stdout" "$stderr" "$artifacts" >> "$SUMMARY"
  printf '[%s] exit=%s elapsed=%ss artifacts=%s\n' "$id" "$status" "$elapsed" "$artifacts" | tee -a "$RUN_LOG"
}

i=0
for target in example.com mozilla.org pecutx.org pq.cloudflareresearch.com; do
  for format in rich json jsonl cbom; do
    i=$((i + 1))
    run_case "tls-$i" tls "$target" "$format"
  done
  i=$((i + 1))
  run_output_dir_case "tls-$i" tls "$target"
done

target=github.com:22
for format in rich json jsonl cbom; do
  i=$((i + 1))
  run_case "ssh-$i" ssh "$target" "$format"
done
i=$((i + 1))
run_output_dir_case "ssh-$i" ssh "$target"

echo | tee -a "$RUN_LOG"
echo "Summary: $SUMMARY" | tee -a "$RUN_LOG"
awk -F '\t' 'NR > 1 { total++; if ($5 == 0) pass++; else fail++ } END { printf "cases=%d pass=%d nonzero=%d\n", total, pass, fail }' "$SUMMARY" | tee -a "$RUN_LOG"
echo "Nonzero exits are recorded findings; the harness exits 0 so the full matrix is always collected." | tee -a "$RUN_LOG"
exit 0
