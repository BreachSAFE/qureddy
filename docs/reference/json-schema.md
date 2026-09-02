# JSON and JSONL output reference

[![Diátaxis reference](https://img.shields.io/badge/Di%C3%A1taxis-reference-1f6feb?style=flat-square)](https://diataxis.fr/reference/)

`qureddy scan tls TARGET --format json` and
`qureddy scan ssh TARGET --format json`, and
`qureddy scan ike TARGET --format json` emit the same top-level
`qureddy.scan.v1` contract. TLS, SSH, and IKE populate different evidence,
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
13. [JSONL projection](#13-jsonl-projection)
14. [Stability rules](#14-stability-rules)
15. [Related documentation](#15-related-documentation)

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
| `scanner_name` | string | `tls`, `ssh`, or `ike` |
| `scanner_version` | string | Installed QuReddy version |
| `status` | string | `completed` or the top-level failure category |
| `total_attempts` | integer | Number of scanner probe attempts represented |

Identifiers and timestamps are intentionally different across runs.

## 4. Target

| Field | Type | TLS | SSH | IKE |
| --- | --- | --- | --- | --- |
| `original_input` | string | Raw command argument | Raw command argument | Raw command argument |
| `host` | string | Normalized hostname or IP | Normalized hostname or IP | Normalized hostname or IP |
| `port` | integer `1..65535` | Default `443` | Default `22` | Default `500` |
| `sni` | string or null | Hostname, override, or null for an IP | null | null |
| `scheme` | string | `tls` | `ssh` | `ike` |
| `locator` | string | Canonical `tls://host:port` | Canonical `ssh://host:port` | Canonical `ike://host:port` |

## 5. Dependencies

TLS emits one local OpenSSL dependency record. IKE emits one external-tool record for
`ike-scan`. SSH emits an empty array.

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

The IKE dependency uses `name`, `path`, `version`, and `failure_category`. It does not
carry OpenSSL capability fields.

## 6. Assets

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | Per-run asset identifier |
| `asset_type` | string | `tls.endpoint`, `ssh.endpoint`, or `ike.endpoint` |
| `locator` | string | Canonical target locator |
| `display_name` | string | Endpoint display name |
| `protocol` | string | `tls`, `ssh`, or `ike` |
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
| `protocol` | string | `tls`, `ssh`, or `ike` |
| `protocol_version` | string or null | Observed protocol version |
| `cipher_suite` | string or null | Observed cipher suite |
| `algorithm` | string or null | Exact algorithm name for a named observation |
| `primitive` | string or null | Primitive classification when known |
| `parameter_set_identifier` | string or null | Standard parameter identifier when known |
| `nist_quantum_security_level` | integer `0..5` or null | Security level when established |
| `negotiated_group` | string or null | Negotiated or offered group |
| `handshake_signature` | string or null | Live TLS CertificateVerify signature algorithm |
| `handshake_hash` | string or null | Hash reported for the live TLS CertificateVerify signature |
| `key_bits` | positive integer or null | Observed ephemeral public-key size |
| `certificate` | object or absent | Typed leaf-certificate facts for observed `tls.cert.signature` evidence |
| `probe_role` | string or null | `hybrid_readiness` or `classical_control` for relevant TLS probes |
| `expected_group` | string or null | Group requested by a TLS probe |
| `ike_group_id` | integer `0..65535` or absent | Exact IKE transform identifier when reported by the tool |
| `probe_result` | object or null | Local probe invocation record |
| `failure_category` | string or null | Failure that prevented or qualified observation |
| `confidence` | enum | `high`, `medium`, or `low` |
| `notes` | array of strings | Bounded human-readable annotations |

Named SSH KEX, host-key, cipher, and MAC evidence populates `algorithm`.
Recognized algorithms also populate the classification fields. Classical
signatures and key exchange use NIST level `0`; symmetric ciphers and MACs
leave that field null because the PQC category does not apply. Unknown names
retain their exact identity and leave classification fields null.

Named IKE encryption, integrity, PRF, and key-exchange evidence also populates
`algorithm`. The optional `ike_group_id` preserves the numeric IKE transform
identifier without introducing an IKE-only output model. It is absent from TLS,
SSH, and IKE records where the tool did not report an identifier. Stock
`ike-scan` observations are lower-trust discovery evidence: they do not prove
peer authentication, IKE_AUTH completion, Child-SA creation, or an installed SA.

The `certificate` object is present only when the TLS certificate probe
produces an observed leaf certificate. Other evidence records omit the field.
Its public fields are:

| Field | Type | Meaning |
| --- | --- | --- |
| `subject` | string | Leaf certificate subject distinguished name |
| `issuer` | string | Issuer distinguished name |
| `not_valid_before` | RFC 3339 string or null | Validity start; null when OpenSSL text is unparseable |
| `not_valid_after` | RFC 3339 string or null | Validity end; null when OpenSSL text is unparseable |
| `serial_number` | string | Certificate serial number |
| `signature_algorithm` | string | Issuer signature algorithm over the leaf certificate |
| `public_key_algorithm` | string or null | Leaf subject-public-key algorithm |
| `public_key_bits` | positive integer or null | Leaf subject-public-key size |
| `is_self_signed` | boolean or null | Verified self-signature state; null means the check was unavailable |
| `is_post_quantum_signature` | boolean | Whether the issuer signature is a recognized PQ signature |

QuReddy derives this public object from its internal certificate observation.
The CBOM renderer consumes the same observation, so JSON and CycloneDX fields
have one acquisition source.

## 8. Probe result

`probe_result` is present for local subprocess evidence, including OpenSSL and
stock `ike-scan` probes.

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
| `executable` | string | Resolved local probe executable path |
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
| `protocol` | string | `tls`, `ssh`, or `ike` |
| `protocol_version` | string or null | Protocol version |
| `negotiated_group` | string or null | Group linked to the finding |
| `bom_ref` | string or null | Cross-format reference |
| `oid` | string or null | Object identifier |
| `nist_quantum_security_level` | integer `0..5` or null | Established security level |

Key-exchange findings populate `primitive`, `parameter_set_identifier`, and
`nist_quantum_security_level` from QuReddy's protocol-neutral classifier when
the negotiated or representative offered group is recognized. Classical key
agreement and key transport use level `0`. Recognized post-quantum KEM parameter
sets use their assigned NIST category. An unknown group remains null instead of
receiving a fabricated classification.

## 10. Summary

| Field | Type | Meaning |
| --- | --- | --- |
| `target` | string | Canonical target locator |
| `finding_count` | integer | Number of findings |
| `highest_severity` | enum or null | Highest finding severity |
| `readiness` | enum | Rolled-up readiness |
| `failure_category` | string or null | Canonical top-level failure reason |
| `interpretation` | object or null | Evidence-derived posture interpretation |

`summary.interpretation` contains the legacy `effective` readiness plus two
independent risk windows:

| Field | Values | Meaning |
| --- | --- | --- |
| `hndl_exposure` | `protected`, `protected_defeasible`, `at_risk`, `unknown` | Harvest-now-decrypt-later exposure |
| `hygiene_status` | `ok`, `action_needed`, `weak`, `unknown` | Present-day protocol and primitive hygiene |

The existing `effective` field remains unchanged for compatibility. The two
additional fields prevent a present-day hygiene finding from hiding a
post-quantum negotiation, or vice versa.

The `display` object is the CISO-facing wording for the same evidence. It is
derived by QuReddy and is safe to show directly in dashboards; consumers that
need stable filtering should continue to use the enum fields above.

| Field | Meaning |
| --- | --- |
| `display.overall_status` | Plain-language rollup, such as `Hybrid PQC protection with hardening required` |
| `display.quantum_protection` | What PQC key-exchange evidence was observed |
| `display.future_quantum_risk` | HNDL/downgrade interpretation in plain language |
| `display.current_hygiene` | Present-day protocol hardening interpretation |
| `display.evaluation` | Evidence-backed, protocol-neutral CISO evaluation object |
| `display.evaluation.summary` | Plain-language endpoint assessment |
| `display.evaluation.hndl_risk` | Explicit future Harvest-Now, Decrypt-Later risk statement |
| `display.evaluation.protection` | Observed post-quantum protection level |
| `display.evaluation.hardening` | Present-day hardening conclusion |
| `display.evaluation.recommended_action` | Evidence-backed next action |
| `display.evaluation.observed_facts` | Flat list of algorithms and certificate facts observed by the adapter |

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
    "scanner_version": "<installed-version>",
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
      "algorithm": "sntrup761x25519-sha512",
      "primitive": "kem",
      "parameter_set_identifier": "sntrup761",
      "nist_quantum_security_level": 2,
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
      "primitive": "kem",
      "parameter_set_identifier": "sntrup761",
      "key_size": null,
      "protocol": "ssh",
      "protocol_version": null,
      "negotiated_group": "sntrup761x25519-sha512",
      "bom_ref": null,
      "oid": null,
      "nist_quantum_security_level": 2
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

## 13. JSONL projection

`--format jsonl` projects the same canonical `ScanResult` into one compact JSON
object per finding followed by exactly one `scan_summary` object. The summary
preserves `scan.status` as `status`, including `completed`, `no_response`, and
`rejected`; consumers must not infer lifecycle state from `failure_category`.

JSONL is a streaming projection, not a lossless copy of the JSON document. It
does not emit standalone evidence records. Finding records retain their linked
identity and cryptographic fields, while the final summary carries scan identity,
producer, status, target, readiness, severity, finding count, failure category,
and canonical interpretation.

## 14. Stability rules

Breaking changes require a new `schema_version`. Version 1 may add optional
nested fields. Consumers must:

- select fields by name;
- accept additional nested fields;
- tolerate null optional values;
- resolve `asset_id` and `evidence_ids` instead of assuming array position;
- use the process exit code for scan completion;
- preserve `unknown` and `not_testable`.

## 15. Related documentation

- [CLI reference](cli.md)
- [Failure categories](failure-categories.md)
- [Exit codes](exit-codes.md)
- [CBOM output](cbom.md)
- [Machine output in CI](../how-to/json-output-for-ci.md)
