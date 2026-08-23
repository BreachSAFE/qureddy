# JSON output reference

`qureddy scan tls TARGET --format json` and
`qureddy scan ssh TARGET --format json` emit the same top-level
`qureddy.scan.v1` contract. TLS and SSH populate different evidence,
dependency, and protocol fields.

## Contents

1. [Document contract](#1-document-contract)
2. [Top-level fields](#2-top-level-fields)
3. [Scan metadata](#3-scan-metadata)
4. [Target](#4-target)
5. [Dependencies](#5-dependencies)
6. [Assets](#6-assets)
7. [Evidence](#7-evidence)
8. [Probe result](#8-probe-result)
9. [Findings](#9-findings)
10. [Summary](#10-summary)
11. [Enumerated values](#11-enumerated-values)
12. [SSH example](#12-ssh-example)
13. [Stability rules](#13-stability-rules)
14. [Related documentation](#14-related-documentation)

## 1. Document contract

Machine mode writes one UTF-8 JSON document and a trailing newline to standard
output. The top-level keys appear in this order:

```text
schema_version, scan, target, dependencies, assets, evidence, findings, summary
```

The order of nested object fields is not a consumer contract. Standard output
remains parseable on successful and typed failed scans. Use the process exit
code to distinguish completion from failure.

## 2. Top-level fields

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | string | Always `qureddy.scan.v1` |
| `scan` | object | Run identity, timing, producer, and status |
| `target` | object | Normalized endpoint |
| `dependencies` | array | Local collector dependencies; empty for SSH |
| `assets` | array | Endpoint assets represented in QuReddy's scan model |
| `evidence` | array | Observations and failed observation attempts |
| `findings` | array | Rule interpretations linked to evidence |
| `summary` | object | Rolled-up readiness and failure state |

## 3. Scan metadata

| Field | Type | Meaning |
| --- | --- | --- |
| `scan_id` | string | Per-run identifier |
| `started_at` | RFC 3339 date-time string | UTC start time |
| `completed_at` | RFC 3339 date-time string | UTC completion time |
| `scanner_name` | string | `tls` or `ssh` |
| `scanner_version` | string | Installed QuReddy version |
| `status` | string | `completed` or the top-level failure category |
| `total_attempts` | integer | Number of scanner probe attempts represented |

Identifiers and timestamps are intentionally different across runs.

## 4. Target

| Field | Type | TLS | SSH |
| --- | --- | --- | --- |
| `original_input` | string | Raw command argument | Raw command argument |
| `host` | string | Normalized hostname or IP | Normalized hostname or IP |
| `port` | integer `1..65535` | Default `443` | Default `22` |
| `sni` | string or null | Hostname, override, or null for an IP | null |
| `scheme` | string | `tls` | `ssh` |
| `locator` | string | Canonical `tls://host:port` | Canonical `ssh://host:port` |

## 5. Dependencies

TLS emits one local OpenSSL dependency record. SSH emits an empty array.

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | `openssl` |
| `path` | string or null | Resolved local executable |
| `version` | string or null | Parsed OpenSSL version |
| `supports_tls13_groups` | boolean | Capability command returned a TLS 1.3 group list |
| `supports_x25519mlkem768` | boolean | Required hybrid group appeared in the list |
| `failure_category` | string or null | Local capability failure |

This record describes the scanner host. It is not the remote endpoint's TLS
implementation identity.

## 6. Assets

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Per-run asset identifier |
| `asset_type` | string | `tls.endpoint` or `ssh.endpoint` |
| `locator` | string | Canonical target locator |
| `display_name` | string | Endpoint display name |
| `protocol` | string | `tls` or `ssh` |
| `protocol_version` | string or null | Observed version when assigned at asset level |
| `algorithm` | string or null | Algorithm name when assigned at asset level |
| `primitive` | string or null | Primitive classification when known |
| `parameter_set_identifier` | string or null | Standard parameter identifier when known |
| `key_size` | integer or null | Key size when observed |
| `negotiated_group` | string or null | Negotiated group when assigned at asset level |
| `bom_ref` | string or null | Cross-format reference when assigned |
| `oid` | string or null | Object identifier when observed |
| `nist_quantum_security_level` | integer `0..5` or null | Security level when established |

Null means that the scan did not establish the value at this model location.
It is not a favorable or unfavorable result.

## 7. Evidence

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Per-run evidence identifier |
| `asset_id` | string | Reference to `assets[].id` |
| `evidence_type` | string | Producer-defined evidence class |
| `observation_type` | enum | How the fact was obtained |
| `source` | string | QuReddy producer module |
| `protocol` | string | `tls` or `ssh` |
| `protocol_version` | string or null | Observed protocol version |
| `cipher_suite` | string or null | Observed cipher suite |
| `negotiated_group` | string or null | Negotiated or offered group |
| `probe_role` | string or null | `hybrid_readiness` or `classical_control` for relevant TLS probes |
| `expected_group` | string or null | Group requested by a TLS probe |
| `probe_result` | object or null | Local OpenSSL invocation record |
| `failure_category` | string or null | Failure that prevented or qualified observation |
| `confidence` | enum | `high`, `medium`, or `low` |
| `notes` | array of strings | Bounded human-readable annotations |

The internal typed certificate observation is intentionally excluded from
this JSON contract. Certificate facts appear through public evidence and
finding fields and through the CycloneDX certificate component.

## 8. Probe result

`probe_result` is present for OpenSSL subprocess evidence.

| Field | Type | Meaning |
| --- | --- | --- |
| `command` | object | Executable, argument array, timeout, and redaction flag |
| `return_code` | integer | Local process exit code |
| `stdout_sha256` | string | Digest of complete standard output |
| `stderr_sha256` | string | Digest of complete standard error |
| `stdout_excerpt` | string | Bounded diagnostic excerpt |
| `stderr_excerpt` | string | Bounded diagnostic excerpt |
| `duration_ms` | integer | Observed process duration |
| `attempt_number` | integer | One-based attempt number |
| `failure_category` | string or null | Classified process failure |

`command` contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `executable` | string | Resolved local OpenSSL path |
| `args` | array of strings | Argument vector without the executable |
| `timeout_seconds` | integer | Probe timeout |
| `redacted` | boolean | Whether sensitive arguments were removed |

The parser's internal input field is excluded from serialized JSON.

## 9. Findings

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Per-run finding identifier |
| `asset_id` | string | Reference to `assets[].id` |
| `evidence_ids` | non-empty array | References to supporting evidence |
| `rule_id` | string | Stable rule identifier |
| `finding_type` | string | Finding class |
| `title` | string | Short interpretation |
| `description` | string | Interpretation and consequence |
| `severity` | enum | `critical`, `high`, `medium`, `low`, or `info` |
| `readiness` | enum | Readiness interpretation |
| `confidence` | enum | `high`, `medium`, or `low` |
| `algorithm` | string or null | Interpreted algorithm |
| `primitive` | string or null | Interpreted primitive |
| `parameter_set_identifier` | string or null | Parameter identifier |
| `key_size` | integer or null | Key size |
| `protocol` | string | `tls` or `ssh` |
| `protocol_version` | string or null | Protocol version |
| `negotiated_group` | string or null | Group linked to the finding |
| `bom_ref` | string or null | Cross-format reference |
| `oid` | string or null | Object identifier |
| `nist_quantum_security_level` | integer `0..5` or null | Established security level |

## 10. Summary

| Field | Type | Meaning |
| --- | --- | --- |
| `target` | string | Canonical target locator |
| `finding_count` | integer | Number of findings |
| `highest_severity` | enum or null | Highest finding severity |
| `readiness` | enum | Rolled-up readiness |
| `failure_category` | string or null | Canonical top-level failure reason |

## 11. Enumerated values

`observation_type`:

```text
negotiated
offered
observed
inferred
not_offered
not_testable
```

`readiness`:

```text
quantum_vulnerable
classically_weak
transitional_hybrid
quantum_safe
unknown
not_applicable
```

Failure values are listed in the
[failure category reference](failure-categories.md).

## 12. SSH example

This is a valid illustrative document. IDs and timestamps are fixed examples,
not a captured current posture for the target.

```json
{
  "schema_version": "qureddy.scan.v1",
  "scan": {
    "scan_id": "scan-example",
    "started_at": "2026-07-27T00:00:00Z",
    "completed_at": "2026-07-27T00:00:01Z",
    "scanner_name": "ssh",
    "scanner_version": "0.2.51",
    "status": "completed",
    "total_attempts": 1
  },
  "target": {
    "original_input": "ssh.example",
    "host": "ssh.example",
    "port": 22,
    "sni": null,
    "scheme": "ssh",
    "locator": "ssh://ssh.example:22"
  },
  "dependencies": [],
  "assets": [
    {
      "id": "asset-example",
      "asset_type": "ssh.endpoint",
      "locator": "ssh://ssh.example:22",
      "display_name": "ssh.example:22",
      "protocol": "ssh",
      "protocol_version": null,
      "algorithm": null,
      "primitive": null,
      "parameter_set_identifier": null,
      "key_size": null,
      "negotiated_group": null,
      "bom_ref": null,
      "oid": null,
      "nist_quantum_security_level": null
    }
  ],
  "evidence": [
    {
      "id": "ev-example",
      "asset_id": "asset-example",
      "evidence_type": "ssh.kex",
      "observation_type": "offered",
      "source": "qureddy.scanners.ssh.probe",
      "protocol": "ssh",
      "protocol_version": "2.0",
      "cipher_suite": null,
      "negotiated_group": "sntrup761x25519-sha512",
      "probe_role": null,
      "expected_group": null,
      "probe_result": null,
      "failure_category": null,
      "confidence": "high",
      "notes": [
        "PQ hybrid KEX offered: sntrup761x25519-sha512"
      ]
    }
  ],
  "findings": [
    {
      "id": "finding-example",
      "asset_id": "asset-example",
      "evidence_ids": [
        "ev-example"
      ],
      "rule_id": "ssh.kex.hybrid_offered",
      "finding_type": "ssh.kex.hybrid",
      "title": "SSH offers post-quantum hybrid key exchange (sntrup761x25519-sha512)",
      "description": "Server offers a PQ hybrid KEX group; protects against harvest-now-decrypt-later.",
      "severity": "info",
      "readiness": "transitional_hybrid",
      "confidence": "high",
      "algorithm": "sntrup761x25519-sha512",
      "primitive": null,
      "parameter_set_identifier": null,
      "key_size": null,
      "protocol": "ssh",
      "protocol_version": null,
      "negotiated_group": "sntrup761x25519-sha512",
      "bom_ref": null,
      "oid": null,
      "nist_quantum_security_level": null
    }
  ],
  "summary": {
    "target": "ssh://ssh.example:22",
    "finding_count": 1,
    "highest_severity": "info",
    "readiness": "transitional_hybrid",
    "failure_category": null
  }
}
```

## 13. Stability rules

Breaking changes require a new `schema_version`. Version 1 may add optional
nested fields. Consumers must:

- select fields by name;
- accept additional nested fields;
- tolerate null optional values;
- resolve `asset_id` and `evidence_ids` instead of assuming array position;
- use the process exit code for scan completion;
- preserve `unknown` and `not_testable`.

## 14. Related documentation

- [CLI reference](cli.md)
- [Failure categories](failure-categories.md)
- [Exit codes](exit-codes.md)
- [CBOM output](cbom.md)
- [Machine output in CI](../how-to/json-output-for-ci.md)
