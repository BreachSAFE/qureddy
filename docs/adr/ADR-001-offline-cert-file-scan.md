# ADR-001: Offline certificate-file scan (`qureddy scan cert <file>`)

**Status:** Proposed (not shipped) as of 2026-07-27
**Relates to:** Public
[issue #7](https://github.com/breachsafe/qureddy/issues/7) delivered live leaf
certificate signature observation. This ADR proposes a separate offline
certificate file command.

---

## Context

QuReddy 0.2.0 scans live TLS and SSH endpoints. The TLS scan observes the leaf
certificate signature algorithm. It does not provide the proposed
`qureddy scan cert <file>` offline command.

The two axes differ in what they *need*:
- **Key exchange** is a property of a *live handshake* — it inherently requires an endpoint.
- **Certificate signature** is a property of a *file* — it does NOT require a server. You can
  answer "is this certificate post-quantum?" from the PEM/DER alone.

Users frequently have a cert file and no running server (a cert exported from a CA, a file
shared for review, a cert pulled from config). Requiring them to stand up a TLS server just
to check the cert's algorithm is unnecessary friction.

## Decision

Add an **offline cert-file scan command**:

```
qureddy scan cert <path-to-cert.pem|der>
```

It runs `openssl x509 -in <file> -noout -text`, feeds the output to the existing
`parse_certificate_signature()`, and reports the cert axis only:

- algorithm (e.g. `ML-DSA-87`), post-quantum? (bool), canonical name, OID (RFC 9881 §2),
  NIST level (2/3/5), and a readiness verdict for the **authentication** axis.

It does **NOT** report key exchange (there is no handshake) and does **NOT** validate trust
or the chain (detection only, same scope as #7).

## Why this is a small, high-value add

- The hard part (`cert_sig.py` parser) already exists and is tested (#7). This command is a
  thin CLI wrapper + `openssl x509 -text` on a file — no handshake, no new parsing.
- No new dependency (parses OpenSSL text, per the scanner's discipline).
- Better UX than the endpoint path for the cert axis: "drop me a cert, I'll tell you if it's
  PQC." Lets a reviewer check a QuCert-minted demo cert with one command, no server.
- Strengthens the diagnose→remediate→confirm loop: after QuCert mints a cert, you can
  confirm it's PQC directly from the file before deploying it anywhere.

## Scope / non-goals

- Cert axis only (signature algorithm). No KEX (requires a live endpoint — stays in
  `scan tls`).
- No trust/chain/path validation (RFC 5280 §6) — detection only.
- DER + PEM input both accepted (let OpenSSL auto-detect `-inform`, or sniff).
- Reuse the same model fields / readiness vocabulary as the endpoint scan so output is
  consistent across `scan tls` and `scan cert`.

## Open questions
1. Output: full per-cert detail vs. a one-line verdict for scripting? (lean: both, `--format`.)
2. Multiple certs in one file (a chain/bundle): scan the leaf only, or each? (lean: leaf,
   note the others.)
3. Should `scan tls` and `scan cert` share a common cert-axis renderer? (yes — DRY.)

## Decision: record now, build after #7's endpoint path lands.
Issue #7 wires cert detection into the live `scan tls` path first (matches today's model);
this offline `scan cert` command is the fast follow that reuses the same parser. File a
GitHub issue referencing this ADR when scheduling.
