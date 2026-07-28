# Failure category reference

`FailureCategory` is the typed reason that a scan or probe did not produce a
clean observation. It appears in JSON and CBOM status metadata and determines
the process exit code. TLS retries accept a strict subset.

## Contents

- [Category table](#category-table)
- [SSH failure mapping](#ssh-failure-mapping)
- [TLS retry allowlist](#tls-retry-allowlist)
- [Retry behavior](#retry-behavior)
- [JSON and CBOM locations](#json-and-cbom-locations)
- [Related documentation](#related-documentation)

## Category table

| Value | Exit | Retryable | Meaning |
| --- | --- | --- | --- |
| `local_openssl_missing` | `3` | no | No OpenSSL executable resolved |
| `local_openssl_broken` | `3` | no | The selected executable or its linked runtime failed capability inspection |
| `local_openssl_version_unreadable` | `3` | no | Version output did not match supported OpenSSL syntax |
| `local_openssl_is_libressl` | `3` | no | The selected binary identified itself as LibreSSL |
| `local_openssl_too_old` | `3` | no | OpenSSL version is below 3.5.0 |
| `local_openssl_lacks_group` | `3` | no | OpenSSL does not list `X25519MLKEM768` as a TLS 1.3 group |
| `target_scan_failed` | `2` | no | The scanner caught a typed target failure without a more specific category |
| `target_connect_failed` | `2` | yes for TLS | DNS, TCP connection, route, refusal, or timeout failure |
| `tls_handshake_failed` | `2` | yes | TLS handshake failed without a more specific classification |
| `sni_required_or_wrong` | `2` | no | Target rejected missing or incorrect SNI |
| `middlebox_or_mtu_failure` | `2` | yes | Connection reset, premature close, broken pipe, or MTU related failure |
| `parse_no_group` | `2` | yes | Successful OpenSSL output omitted a parseable group |
| `parse_ambiguous` | `2` | no | Response contained conflicting group evidence or a malformed SSH KEXINIT |
| `unexpected_group` | `2` | no | TLS selected a group other than the requested group |

The `local_openssl_*` categories apply only to TLS. SSH does not resolve or run
OpenSSL.

## SSH failure mapping

The SSH probe maps socket and timeout causes to `target_connect_failed`.
Malformed identification or KEXINIT responses map to `parse_ambiguous`.

SSH exposes no retry options in version 0.2.8. An operator or calling system
may invoke the command again, but QuReddy does not retry SSH internally.

## TLS retry allowlist

`--retry-on` accepts only:

```text
target_connect_failed
tls_handshake_failed
middlebox_or_mtu_failure
parse_no_group
```

Unknown categories and non-retryable categories fail argument validation with
exit `4`. Local capability failures are not retryable because waiting does not
change the selected OpenSSL installation.

## Retry behavior

The first TLS probe result selects the triggering category. QuReddy retries
only when that category is in both the built-in allowlist and the operator's
`--retry-on` set.

Retries stop when:

- a probe succeeds;
- the failure category changes;
- the configured number of additional attempts is exhausted.

`--retries` accepts `0..3`. `--retry-delay` accepts `0.0..10.0` seconds.
Supplying a positive retry count without `--retry-on` exits `4`.

## JSON and CBOM locations

JSON can contain a category in:

- `scan.status`;
- `summary.failure_category`;
- `dependencies[].failure_category`;
- `evidence[].failure_category`;
- `evidence[].probe_result.failure_category`.

The summary is the canonical top-level reason. More specific records preserve
where the failure arose.

CBOM stores the scan state in CycloneDX metadata properties:

```text
qureddy:scan.status
qureddy:scan.failure_category
```

The failure property is absent when no top-level failure category exists.

## Related documentation

- [CLI options](cli.md)
- [Exit codes](exit-codes.md)
- [JSON output](json-schema.md)
- [CBOM output](cbom.md)
- [Install and troubleshoot](../how-to/install.md)
