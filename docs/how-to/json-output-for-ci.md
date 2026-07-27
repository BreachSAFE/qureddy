# Capture machine-readable output for CI

This guide covers using `--format json` to capture scan results in a way CI pipelines, dashboards, or scripts can consume. Use it when you're wiring QuReddy into nightly scans, alerting, or compliance dashboards.

## Prerequisites

- A working `qureddy` install ([tutorial](../tutorials/your-first-scan.md))
- A target list (one per line, or programmatically generated)

## Steps

### 1. Get JSON for a single target

```bash
qureddy scan tls www.google.com --format json > scan.json
```

The output is a single JSON document. Top-level keys are locked and appear in this order:

```
schema_version, scan, target, dependencies, assets, evidence, findings, summary
```

Don't depend on field order *inside* the nested objects — only the top level is contractually stable.

### 2. Check the exit code, not the JSON, for success/failure

QuReddy uses POSIX exit codes:

| Exit code | Meaning |
|---|---|
| 0 | Scan succeeded |
| 2 | Target scan failed (network, TLS, or parser error) |
| 3 | Local OpenSSL is missing or unsupported (operator's problem, not the target's) |
| 4 | Usage / configuration error (bad flag value, unknown retry category) |

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

### 3. Extract the readiness verdict with `jq`

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

### 4. Scan multiple targets in a loop

```bash
mkdir -p scans
for target in api.example.com www.example.com mail.example.com; do
  qureddy scan tls "$target" --format json > "scans/${target}.json" || true
done
```

Each scan writes to its own file. The `|| true` keeps the loop running if individual scans fail; check exit codes if you need stricter behavior.

### 5. Aggregate across many scans

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

## Suppressing console logs

By default, INFO logs go to stderr. For clean JSON capture, redirect stderr or use `--quiet`:

```bash
# Suppress all but ERROR-level logs
qureddy scan tls www.google.com --format json --quiet > scan.json

# Or redirect stderr if you want to keep WARNING logs in a separate file
qureddy scan tls www.google.com --format json > scan.json 2> scan.log
```

For structured log capture (parseable in log aggregators), add `--json-logs`:

```bash
qureddy scan tls www.google.com --format json --json-logs > scan.json 2> scan.log
# scan.log now contains one JSON object per line
```

## Failure diagnostics and merged streams

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

## Schema stability

The top-level shape (`schema_version: "qureddy.scan.v1"`) will not change without a version bump. Additive changes to nested objects (new optional fields) can land in v1; breaking changes bump to `v2`.

If you depend on a specific nested field, pin against the field name and tolerate missing optional fields. Don't depend on object-field order beyond the locked top-level keys.

## Related

- [Reference: JSON output schema](../reference/json-schema.md) — every field, every type
- [Reference: Exit codes](../reference/exit-codes.md) — full surface
- [Reference: Failure categories](../reference/failure-categories.md) — what each `summary.failure_category` value means
