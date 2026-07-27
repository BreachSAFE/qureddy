# Reference: Failure categories

The `FailureCategory` enum is QuReddy's typed failure surface. Every probe, parser verdict, and summary failure carries one of these values. The same enum drives:

- The `summary.failure_category` field in JSON output
- The `--retry-on` flag's allowlist
- The exit code mapping (categories prefixed `LOCAL_OPENSSL_` map to exit 3; the rest to exit 2)

## Routing diagram

```mermaid
flowchart LR
    fail([Failure]) --> kind{Detected where?}

    kind -->|capability check| local["LOCAL_OPENSSL_MISSING<br/>LOCAL_OPENSSL_BROKEN<br/>LOCAL_OPENSSL_VERSION_UNREADABLE<br/>LOCAL_OPENSSL_TOO_OLD<br/>LOCAL_OPENSSL_LACKS_GROUP"]
    kind -->|scan / probe<br/>(subprocess + stderr)| probe_cat["TARGET_SCAN_FAILED<br/>TARGET_CONNECT_FAILED<br/>TLS_HANDSHAKE_FAILED<br/>SNI_REQUIRED_OR_WRONG<br/>MIDDLEBOX_OR_MTU_FAILURE"]
    kind -->|parser| parse_cat["PARSE_NO_GROUP<br/>PARSE_AMBIGUOUS<br/>UNEXPECTED_GROUP"]

    local --> exit3[Exit 3<br/>local dependency]
    probe_cat --> exit2[Exit 2<br/>target failed]
    parse_cat --> exit2

    local -.->|never retryable| not_retry[Not in<br/>--retry-on allowlist]
    probe_cat -.->|TARGET_CONNECT_FAILED<br/>TLS_HANDSHAKE_FAILED<br/>MIDDLEBOX_OR_MTU_FAILURE<br/>retryable| retry[--retry-on allowlist]
    probe_cat -.->|SNI_REQUIRED_OR_WRONG<br/>not retryable| not_retry
    parse_cat -.->|PARSE_NO_GROUP<br/>retryable| retry
    parse_cat -.->|PARSE_AMBIGUOUS<br/>UNEXPECTED_GROUP<br/>not retryable| not_retry
```

## The values

| Category | Source | Triggers exit | Retryable | Meaning |
|---|---|---|---|---|
| `local_openssl_missing` | capability check | 3 | no | `openssl` binary not found at any expected path. Resolution: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on PATH. |
| `local_openssl_broken` | capability check | 3 | no | OpenSSL exists and is executable, but exits nonzero during capability detection. The binary or its linked libraries are unusable. |
| `local_openssl_version_unreadable` | capability check | 3 | no | OpenSSL exits successfully but its version output cannot be parsed. Confirm the binary is OpenSSL-compatible and prints a standard `openssl version` line. |
| `local_openssl_too_old` | capability check | 3 | no | OpenSSL is below 3.5.0. Hybrid PQ groups landed in 3.5. |
| `local_openssl_lacks_group` | capability check | 3 | no | OpenSSL 3.5+ is present but doesn't list `X25519MLKEM768` as a TLS 1.3 group. The build was compiled without PQ support. |
| `target_scan_failed` | scan | 2 | no | A typed scan error occurred before QuReddy could assign a more specific target, TLS, or parser category. The original error is preserved in the result note. |
| `target_connect_failed` | probe | 2 | **yes** | TCP-level failure: connection refused, DNS lookup failed, network unreachable, no route to host, operation timed out. |
| `tls_handshake_failed` | probe | 2 | **yes** | TLS handshake failed for an unidentified reason. Generic fallback when stderr doesn't match a more specific pattern. |
| `sni_required_or_wrong` | probe | 2 | no | Server returned `unrecognized_name` or required SNI was missing. Re-run with `--sni`. |
| `middlebox_or_mtu_failure` | probe | 2 | **yes** | Connection reset, broken pipe, message-too-long, fragmentation needed, premature close. Often signals a middlebox dropping large hybrid PQ ClientHellos that exceed the path MTU. |
| `parse_no_group` | parser | 2 | **yes** | OpenSSL completed the handshake but the `-brief` output didn't include a parseable group line. Re-running often produces the line. |
| `parse_ambiguous` | parser | 2 | no | Conflicting group evidence (e.g., `Negotiated TLS1.3 group:` says one group, `Peer Temp Key:` says another). Not transient — investigate the OpenSSL output by hand. |
| `unexpected_group` | parser | 2 | no | Server selected a different group than the probe requested. The server is not honoring the offered groups list. |

## Retryable allowlist

Only four categories are valid for `--retry-on`. Local-capability failures are deliberately excluded — retrying them does nothing because the operator's environment hasn't changed:

```
target_connect_failed
tls_handshake_failed
middlebox_or_mtu_failure
parse_no_group
```

`--retry-on local_openssl_missing`, `--retry-on local_openssl_broken`, and `--retry-on local_openssl_version_unreadable` raise an error and exit 4.

## Local vs probe vs parser

The category prefix tells you where the failure was detected:

- **`local_openssl_*`** — detected by the capability check before any target probe runs. Exit 3.
- **`target_scan_*`, `target_connect_*`, `tls_*`, `sni_*`, `middlebox_*`** — detected during scan execution or by the probe (subprocess + stderr classification). Exit 2.
- **`parse_*`, `unexpected_*`** — detected by the parser after a successful probe. Exit 2.

## How `--retry-on` interacts

The retry loop uses the *first attempt's* failure category as the trigger. If attempt 1 fails with `target_connect_failed` (in `--retry-on`) and attempt 2 fails with `tls_handshake_failed` (also in `--retry-on`), the loop **stops** — the change in category is treated as a different failure, not the same transient.

This is deliberate. Two different failure modes back-to-back almost never reflect a flaky network; usually the second is informative about why the first happened.

## Mapping in JSON output

`summary.failure_category` is the canonical reason a scan didn't reach a clean `transitional_hybrid` or `quantum_vulnerable` finding. The summary preserves the *exact* category from the matching evidence record rather than collapsing local-capability failures and target-side probe failures into one bucket.

Local-capability failures take precedence over probe failures so a consumer can distinguish "your openssl is broken" from "the server we tried isn't reachable". Within each tier, the first matching evidence record wins.

## Related

- [Reference: CLI options](cli.md) — `--retry-on` syntax
- [Reference: Exit codes](exit-codes.md) — how categories map to exits
- [Reference: JSON output schema](json-schema.md) — where `failure_category` appears
