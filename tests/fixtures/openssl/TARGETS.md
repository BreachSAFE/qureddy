# TLS Test Targets

Live targets used by two things:

1. **Fixture capture** — recorded outputs from these targets get saved here, under `tests/fixtures/openssl/`, and parser unit tests consume them.
2. **Network-dependent tests** — per `docs/contributors/coding-rules.md`, every test runs every time, including tests that hit real targets. Those tests connect to the targets below directly. There is no "smoke" carve-out and no skip-by-default.

Targets in this file are the canonical set the suite hits. When CI fails because a target is unreachable, investigate before re-running; that is a real signal, not noise.

## Contents

1. [PQ-deployed](#1-pq-deployed-should-negotiate-x25519mlkem768)
2. [Classical baseline](#2-classical-baseline-should-negotiate-x25519-not-hybrid)
3. [SNI handling](#3-sni-handling)
4. [Edge cases](#4-edge-cases--badsslcom-suite)
5. [Failure categories](#5-failure-categories--fixture-mapping)
6. [Fixture capture protocol](#6-fixture-capture-protocol)

## 1. PQ-deployed (should negotiate `X25519MLKEM768`)

| Target | Notes |
|---|---|
| `pq.cloudflareresearch.com` | Cloudflare Research's explicit PQ test endpoint. Primary positive fixture source. |
| `www.cloudflare.com` | Cloudflare flipped PQ to default site-wide; should negotiate hybrid. |
| `www.google.com` | Google rolled out X25519MLKEM768 to most properties; varies by region/edge. |
| `www.facebook.com` | Meta enabled hybrid PQ at the load balancer. |
| `kms.us-east-1.amazonaws.com` | AWS KMS PQ TLS rollout (Nov 2025). Important for the financial-services positioning story. |

## 2. Classical baseline (should negotiate `X25519`, not hybrid)

| Target | Notes |
|---|---|
| `example.com` | RFC 2606 reserved. Stable baseline that will not negotiate PQ. |
| `www.example.org` | RFC 2606 reserved. Useful if it stays on classical TLS. |

## 3. SNI handling

| Target | Invocation | Tests |
|---|---|---|
| `1.1.1.1` | `qureddy scan tls 1.1.1.1:443 --sni one.one.one.one` | `--sni` flag against an IP target. |

## 4. Edge cases — `badssl.com` suite

The canonical TLS edge-case test surface. Stable, public, exhaustive.

### TLS-version edge cases (in scope)

These fail at the TLS layer and are observable without certificate chain parsing.

| Target | Tests | Expected category |
|---|---|---|
| `tls-v1-0.badssl.com:1010` | Forces TLS 1.0 only | `tls_handshake_failed` (we require TLS 1.3) |
| `tls-v1-1.badssl.com:1011` | Forces TLS 1.1 only | `tls_handshake_failed` |
| `tls-v1-2.badssl.com:1012` | Forces TLS 1.2 only | `tls_handshake_failed` (we require TLS 1.3) |

### Certificate-chain targets

These targets exercise certificate-chain validity and certificate observations in the current TLS scanner.

| Target | Tests at cert-scanner stage |
|---|---|
| `expired.badssl.com` | Expired certificate finding |
| `self-signed.badssl.com` | Self-signed cert chain finding |
| `untrusted-root.badssl.com` | Cert signed by an untrusted CA |
| `wrong.host.badssl.com` | Common-name / SAN mismatch |
| `revoked.badssl.com` | OCSP-revoked cert |

The scanner records certificate problems as findings, not as workarounds via `verify=False`.

## 5. Failure categories — fixture mapping

Every failure category enumerated by the scanner needs at least one captured fixture. Suggested target for each:

| Failure category | Capture from |
|---|---|
| `local_openssl_missing` | Synthesize: rename `openssl` binary or set `--openssl /nonexistent`. |
| `local_openssl_too_old` | Synthesize: point `--openssl` at an older OpenSSL binary if available. |
| `local_openssl_lacks_group` | Use the `openssl_lacks_group` fixture with an OpenSSL 3.6.3 version banner and no hybrid group. |
| `target_connect_failed` | A non-routable host like `192.0.2.1:443` (RFC 5737 TEST-NET-1). |
| `tls_handshake_failed` | `tls-v1-0.badssl.com:1010`. |
| `sni_required_or_wrong` | A virtual-hosted target that 421s without correct SNI. |
| `middlebox_or_mtu_failure` | Hard to reproduce reliably; capture opportunistically if encountered. |
| `parse_no_group` | Synthesize by editing a captured trace, or use a target with unusual output. |
| `parse_ambiguous` | Synthesize by editing a captured fixture. |
| `unexpected_group` | Synthesize: scan with `-groups secp256r1` and check parser rejects it. |

## 6. Fixture capture protocol

1. Run the documented probe command against the target.
2. Save raw output to `tests/fixtures/openssl/<descriptive_name>.txt`.
3. Redact anything host-specific that the parser doesn't need (cert PEM bodies, IP addresses in cert subjects).
4. Add a one-line comment at the top of the fixture noting source target and date captured.
5. Reference the fixture from a test in `tests/test_tls_parse.py`.

After fixture capture, all unit tests run offline forever. Re-capture only if OpenSSL output format changes between versions.
