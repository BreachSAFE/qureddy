# Capture machine-readable output for CI

This guide covers using `--format json` to capture scan results in a way CI pipelines, dashboards, or scripts can consume. Use it when you're wiring QuReddy into nightly scans, alerting, or compliance dashboards.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Capture a result](#2-capture-a-result)
3. [Branch on the exit code](#3-branch-on-the-exit-code)
4. [Read fields with jq](#4-read-fields-with-jq)
5. [Scan several targets](#5-scan-several-targets)
6. [Aggregate results](#6-aggregate-results)
7. [Separate diagnostics](#7-separate-diagnostics)
8. [Handle failed scans](#8-handle-failed-scans)
9. [Schema stability](#9-schema-stability)
10. [Related documentation](#10-related-documentation)

## 1. Prerequisites

- A working `qureddy` install ([tutorial](../tutorials/your-first-scan.md))
- A target list (one per line, or programmatically generated)

## 2. Capture a result

```bash
qureddy scan tls www.google.com --format json > scan.json
```

The output is a single JSON document. Top-level keys are locked and appear in this order:

```
schema_version, scan, target, dependencies, assets, evidence, findings, summary
```

Don't depend on field order *inside* the nested objects; only the top level is contractually stable.

## 3. Branch on the exit code

QuReddy uses POSIX exit codes:

| Exit code | Meaning |
|---|---|
| 0 | Scan succeeded |
| 2 | Target scan failed (network, TLS, or parser error) |
| 3 | Local OpenSSL is missing or unsupported (operator's problem, not the target's) |
| 4 | Usage / configuration error (bad flag value, unknown retry category) |
| 70 | Internal QuReddy error |

In a CI step:

```yaml
- name: Scan production endpoint
  run: |
    qureddy scan tls api.example.com --format json > scan.json
  # Pipeline continues only if exit code is 0
```

If you need to keep the pipeline running on a failed scan but record the result, capture the exit code explicitly:

```yaml
- name: Scan and continue
  run: |
    set +e
    qureddy scan tls api.example.com --format json > scan.json
    echo "exit=$?" >> "$GITHUB_OUTPUT"
    set -e
```

## 4. Read fields with jq

```bash
qureddy scan tls www.google.com --format json | jq -r '.summary.readiness'
# transitional_hybrid
```

Other useful queries:

```bash
# Failure category if the scan didn't succeed
jq -r '.summary.failure_category // "none"' scan.json

# Negotiated TLS group from the hybrid probe
jq -r '.evidence[] | select(.notes[]?|contains("X25519MLKEM768")) | .negotiated_group' scan.json

# All findings as rule_id -> readiness
jq -r '.findings[] | "\(.rule_id) \(.readiness)"' scan.json

# OpenSSL invocations the scanner ran (always present in JSON, regardless of -vvv)
jq -r '.evidence[].probe_result.command | "\(.executable) \(.args | join(" "))"' scan.json | sort -u
```

## 5. Scan several targets

```bash
mkdir -p scans
for target in api.example.com www.example.com mail.example.com; do
  qureddy scan tls "$target" --format json > "scans/${target}.json" || true
done
```

Each scan writes to its own file. The `|| true` keeps the loop running if individual scans fail; check exit codes if you need stricter behavior.

## 6. Aggregate results

`jq -s` ("slurp") combines multiple JSON files into one array:

```bash
jq -s '[.[] | {target: .target.locator, readiness: .summary.readiness, findings: .summary.finding_count}]' scans/*.json
```

Output:

```json
[
  {"target": "tls://api.example.com:443", "readiness": "transitional_hybrid", "findings": 2},
  {"target": "tls://www.example.com:443", "readiness": "quantum_vulnerable", "findings": 1},
  {"target": "tls://mail.example.com:443", "readiness": "transitional_hybrid", "findings": 2}
]
```

## 7. Separate diagnostics

Machine output defaults to quiet logging. A successful scan without an
explicit verbosity flag writes one document to standard output and leaves
standard error empty. Redirect both streams when a pipeline needs explicit
artifacts:

```bash
qureddy scan tls www.google.com --format json > scan.json 2> scan.log
```

For structured log capture (parseable in log aggregators), add `--json-logs`:

```bash
qureddy scan tls www.google.com --format json --json-logs > scan.json 2> scan.log
# scan.log now contains one JSON object per line
```

## 8. Handle failed scans

JSON and CBOM failures still emit one structured document and preserve the
documented nonzero exit code. With separate streams, an actionable operator
hint remains on stderr, including with `--quiet`. Under genuine shell-level
`2>&1`, QuReddy suppresses that courtesy hint so the merged stream remains one
parseable document.

Explicit `-v`, `-vv`, or `-vvv` requests diagnostic logs. Keep stderr separate
when using verbose machine output:

```bash
qureddy scan tls api.example.com --format json -v > scan.json 2> scan.log
```

Merging explicitly requested verbose logs with `2>&1` mixes diagnostics with
the document by design.

## 9. Schema stability

The top-level shape (`schema_version: "qureddy.scan.v1"`) will not change without a version bump. Additive changes to nested objects (new optional fields) can land in v1; breaking changes bump to `v2`.

If you depend on a specific nested field, pin against the field name and tolerate missing optional fields. Don't depend on object-field order beyond the locked top-level keys.

## 10. Related documentation

- [Reference: JSON output schema](../reference/json-schema.md); every field, every type
- [Reference: Exit codes](../reference/exit-codes.md); full surface
- [Reference: Failure categories](../reference/failure-categories.md); what each `summary.failure_category` value means
