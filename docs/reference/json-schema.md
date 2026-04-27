# Reference: JSON output schema

This page documents the JSON shape produced by `qureddy scan tls TARGET --format json`. The top-level keys are locked and appear in this exact order; nested objects may grow optional fields without bumping `schema_version`.

## Schema version

```json
{ "schema_version": "qureddy.scan.v1", ... }
```

`v1` is stable for QuReddy 0.1.x. Additive changes (new optional fields) land in v1; breaking changes bump to v2. Consumers should pin against the field names they read and tolerate optional fields they don't recognize.

## Top-level shape

The order is contractual:

| # | Key | Type | What it is |
|---|---|---|---|
| 1 | `schema_version` | string | Always `"qureddy.scan.v1"` for this release |
| 2 | `scan` | `ScanMetadata` object | Run-level metadata (id, timing, status) |
| 3 | `target` | `ScanTarget` object | What was scanned (host, port, sni, locator) |
| 4 | `dependencies` | array of `OpenSSLDependency` | Local-capability info; usually one element |
| 5 | `assets` | array of `Asset` | The crypto assets observed (TLS endpoint at MVP 0.1) |
| 6 | `evidence` | array of `Evidence` | Probe outcomes; one per probe attempt |
| 7 | `findings` | array of `Finding` | Policy verdicts; zero or more |
| 8 | `summary` | `ScanSummary` object | Top-line verdict (readiness, finding count, failure category) |

## Nested objects

### `ScanMetadata` (`scan`)

| Field | Type | Notes |
|---|---|---|
| `scan_id` | string | `scan-<uuid>` |
| `started_at` | ISO 8601 string | UTC |
| `completed_at` | ISO 8601 string | UTC |
| `scanner_name` | string | `"tls"` at MVP 0.1 |
| `scanner_version` | string | `"0.1.0"` at MVP 0.1 |
| `status` | string | `"completed"` on success, or a `FailureCategory` value on failure |
| `total_attempts` | int | Number of probe invocations (≥ 2 for a successful scan) |

### `ScanTarget` (`target`)

| Field | Type | Notes |
|---|---|---|
| `original_input` | string | Raw user input |
| `host` | string | Normalized hostname or IP |
| `port` | int | 1–65535 |
| `sni` | string \| null | What's sent in the TLS SNI extension; `null` for IP targets without `--sni` |
| `scheme` | string | Always `"tls"` at MVP 0.1 |
| `locator` | string | `"tls://host:port"` |

### `OpenSSLDependency` (`dependencies[]`)

| Field | Type | Notes |
|---|---|---|
| `name` | string | Always `"openssl"` |
| `path` | string \| null | Resolved path; `null` if missing |
| `version` | string \| null | e.g. `"3.5.6"` |
| `supports_tls13_groups` | bool | Whether `openssl list -tls1_3 -tls-groups` produced output |
| `supports_x25519mlkem768` | bool | Whether the hybrid group appears in the supported list |
| `failure_category` | string \| null | One of `local_openssl_missing`, `local_openssl_broken`, `local_openssl_version_unreadable`, `local_openssl_too_old`, `local_openssl_lacks_group`, or `null` if usable |

### `Asset` (`assets[]`)

| Field | Type | Notes |
|---|---|---|
| `id` | string | `asset-<uuid>` |
| `asset_type` | string | `"tls.endpoint"` at MVP 0.1 |
| `locator` | string | Mirrors `target.locator` |
| `display_name` | string | `"host:port"` |
| `protocol` | string | Always `"tls"` at MVP 0.1 |
| `protocol_version` | string \| null | e.g. `"TLSv1.3"` |
| `algorithm` | string \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `primitive` | string \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `parameter_set_identifier` | string \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `key_size` | int \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `negotiated_group` | string \| null | TLS 1.3 group name |
| `bom_ref` | string \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `oid` | string \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `nist_quantum_security_level` | int \| null | 0–5 (CycloneDX-flavored, unused at MVP 0.1) |

The CycloneDX-flavored fields are locked into the schema now to avoid a JSON schema migration when CBOM emission lands at MVP 0.3. They are always `null` at MVP 0.1.

### `Evidence` (`evidence[]`)

| Field | Type | Notes |
|---|---|---|
| `id` | string | `ev-<uuid>` |
| `asset_id` | string | References an `Asset.id` |
| `evidence_type` | string | E.g. `"tls.negotiation"`, `"tls.probe.failure"`, `"tls.probe.parse"`, `"tls.capability"` |
| `observation_type` | string | One of `negotiated`, `offered`, `observed`, `inferred`, `not_testable` |
| `source` | string | E.g. `"qureddy.openssl_probe"`, `"qureddy.scanners.tls.parse"` |
| `protocol` | string | `"tls"` |
| `protocol_version` | string \| null | E.g. `"TLSv1.3"` |
| `cipher_suite` | string \| null | E.g. `"TLS_AES_256_GCM_SHA384"` |
| `negotiated_group` | string \| null | The actual group selected |
| `probe_result` | `ProbeResult` \| null | The subprocess invocation that produced this evidence (see below) |
| `failure_category` | string \| null | A `FailureCategory` value when this evidence is a failure record |
| `confidence` | string | `high`, `medium`, or `low` |
| `notes` | array of string | Human-readable annotations |

### `ProbeResult` (`evidence[].probe_result`)

| Field | Type | Notes |
|---|---|---|
| `command` | `ProbeCommand` object | The subprocess args |
| `return_code` | int | OpenSSL exit code |
| `stdout_sha256` | string | SHA-256 of full stdout |
| `stderr_sha256` | string | SHA-256 of full stderr |
| `stdout_excerpt` | string | First 4096 bytes of stdout |
| `stderr_excerpt` | string | First 4096 bytes of stderr |
| `duration_ms` | int | Wall time |
| `attempt_number` | int | 1-based; > 1 means this was a retry |
| `failure_category` | string \| null | Stderr-classified failure |

### `ProbeCommand` (`evidence[].probe_result.command`)

| Field | Type | Notes |
|---|---|---|
| `executable` | string | Resolved OpenSSL path |
| `args` | array of string | Argv minus the executable |
| `timeout_seconds` | int | What `--timeout` was set to |
| `redacted` | bool | False at MVP 0.1; reserved for future redaction |

### `Finding` (`findings[]`)

| Field | Type | Notes |
|---|---|---|
| `id` | string | `finding-<uuid>` |
| `asset_id` | string | References an `Asset.id` |
| `evidence_ids` | array of string | One or more `Evidence.id` references; never empty |
| `rule_id` | string | E.g. `tls.hybrid.negotiated_x25519mlkem768`, `tls.classical.negotiated_x25519`, `tls.hybrid.not_testable`, `tls.hybrid.probe_failed` |
| `finding_type` | string | E.g. `tls.kex.hybrid` |
| `title` | string | Short rule title |
| `description` | string | Longer rule description |
| `severity` | string | `critical`, `high`, `medium`, `low`, `info` |
| `readiness` | string | `quantum_vulnerable`, `classically_weak`, `transitional_hybrid`, `quantum_safe`, `unknown`, `not_applicable` |
| `confidence` | string | `high`, `medium`, `low` |
| `algorithm`, `primitive`, `parameter_set_identifier`, `key_size`, `bom_ref`, `oid`, `nist_quantum_security_level` | various \| null | (CycloneDX-flavored, unused at MVP 0.1) |
| `protocol` | string | `"tls"` |
| `protocol_version` | string \| null | E.g. `"TLSv1.3"` |
| `negotiated_group` | string \| null | The group this finding is about |

### `ScanSummary` (`summary`)

| Field | Type | Notes |
|---|---|---|
| `target` | string | Mirrors `target.locator` |
| `finding_count` | int | Number of findings |
| `highest_severity` | string \| null | Highest severity across all findings |
| `readiness` | string | The rolled-up readiness verdict |
| `failure_category` | string \| null | The canonical reason the scan didn't succeed; `null` on success |

## Sample (truncated)

```json
{
  "schema_version": "qureddy.scan.v1",
  "scan": {
    "scan_id": "scan-7c4a8d09e3b1",
    "started_at": "2026-04-26T22:00:00.123Z",
    "completed_at": "2026-04-26T22:00:00.456Z",
    "scanner_name": "tls",
    "scanner_version": "0.1.0",
    "status": "completed",
    "total_attempts": 2
  },
  "target": {
    "original_input": "www.google.com",
    "host": "www.google.com",
    "port": 443,
    "sni": "www.google.com",
    "scheme": "tls",
    "locator": "tls://www.google.com:443"
  },
  "dependencies": [
    {
      "name": "openssl",
      "path": "/opt/homebrew/opt/openssl@3/bin/openssl",
      "version": "3.5.6",
      "supports_tls13_groups": true,
      "supports_x25519mlkem768": true,
      "failure_category": null
    }
  ],
  "assets": [
    { "id": "asset-...", "asset_type": "tls.endpoint", "locator": "tls://www.google.com:443", ... }
  ],
  "evidence": [
    { "id": "ev-...", "evidence_type": "tls.negotiation", "negotiated_group": "X25519MLKEM768", ... },
    { "id": "ev-...", "evidence_type": "tls.negotiation", "negotiated_group": "X25519", ... }
  ],
  "findings": [
    { "id": "finding-...", "rule_id": "tls.hybrid.negotiated_x25519mlkem768", "readiness": "transitional_hybrid", ... },
    { "id": "finding-...", "rule_id": "tls.classical.negotiated_x25519", "readiness": "quantum_vulnerable", ... }
  ],
  "summary": {
    "target": "tls://www.google.com:443",
    "finding_count": 2,
    "highest_severity": "low",
    "readiness": "transitional_hybrid",
    "failure_category": null
  }
}
```

## Related

- [Reference: CLI options](cli.md) — `--format json`
- [Reference: Exit codes](exit-codes.md) — when JSON is and isn't produced
- [Reference: Failure categories](failure-categories.md) — the enum values you'll see in `summary.failure_category` and `evidence[].failure_category`
- [How-to: Capture machine-readable output for CI](../how-to/json-output-for-ci.md) — `jq` recipes against this schema
