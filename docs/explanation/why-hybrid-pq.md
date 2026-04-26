# Why hybrid post-quantum?

QuReddy probes for `X25519MLKEM768` — a hybrid of X25519 (classical elliptic curve) and ML-KEM-768 (post-quantum lattice). It does not probe for pure ML-KEM. This page explains why the hybrid construction exists and what "transitional" means as a readiness verdict.

## The two threats hybrid defends against

A pure post-quantum (PQ) key exchange protects against a future quantum computer. A pure classical key exchange protects against today's classical attackers. A hybrid construction combines both, so a session is secure if **either** primitive holds.

This matters because PQ algorithms are young. ML-KEM was standardized as [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) in August 2024. It is the result of a six-year NIST competition and the surviving design from the CRYSTALS-Kyber submission, but six years is short by cryptographic standards. AES had decades of analysis before deployment; RSA has had four decades; ECC almost three. ML-KEM has had less than ten.

The conservative position is: trust ML-KEM enough to **add** it as a defense, not enough to **replace** classical primitives yet. Hybrid is the conservative position.

## What hybrid actually means at the protocol layer

A hybrid TLS 1.3 key exchange sends two key shares in the ClientHello — one X25519 share and one ML-KEM-768 share. The server combines both shared secrets through a KDF into a single session key. An attacker has to break both X25519 *and* ML-KEM-768 to recover the session key. There is no fallback path that uses only one of them.

Concretely, `X25519MLKEM768`'s combined secret is derived as roughly:

```
combined_secret = HKDF-Extract(salt=0, ikm = X25519_shared || MLKEM768_shared)
```

(The exact KDF construction is in [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/) for HPKE-style hybrids and the in-progress [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) for TLS 1.3 specifically.)

If quantum computing breaks elliptic curve cryptography in 2035, the X25519 half of past hybrid sessions becomes recoverable. The ML-KEM-768 half does not. The session key remains secret.

If a flaw is discovered in ML-KEM-768 in 2027 (the more pressing concern, given the algorithm's youth), the X25519 half still protects sessions captured today.

## Why X25519 + ML-KEM-768 specifically

Of the standardized hybrids, `X25519MLKEM768` is the IETF's currently-converging choice. It pairs a well-understood classical primitive with the smallest of the standardized ML-KEM parameter sets. ML-KEM-768 corresponds to NIST security level 3 — roughly equivalent to AES-192. Sufficient for general-purpose web TLS; the larger parameter sets (ML-KEM-1024 at level 5) are reserved for higher-stakes applications.

Other named hybrids (`SecP256r1MLKEM768`, `SecP384r1MLKEM1024`) exist but `X25519MLKEM768` is what major TLS implementations (OpenSSL 3.5+, Cloudflare, Google) have converged on for default deployments in 2025–2026.

QuReddy will report any of these as `transitional_hybrid`; it specifically probes for `X25519MLKEM768` because that's what reachable test endpoints actually deploy today.

## What the readiness verdicts mean

The readiness vocabulary mirrors the conservative position:

| Verdict | What it means | When it fires |
|---|---|---|
| `quantum_safe` | Pure PQ — no classical primitive in the key exchange | Not seen in the wild at MVP 0.1; reserved for future state |
| `transitional_hybrid` | Hybrid (classical + PQ together) | The current best-practice deployment; what Google and Cloudflare ship |
| `quantum_vulnerable` | Pure classical key exchange | The default state for most servers in 2026 |
| `classically_weak` | Broken classical primitive (RSA-1024, MD5 cert sig, etc.) | Reserved for MVP 0.2 cert-chain analysis |
| `unknown` | Couldn't probe (local capability or target unreachable) | Operator's environment or target connectivity |
| `not_applicable` | Scan doesn't apply to this asset | Reserved |

`transitional_hybrid` is *not* the final destination. It's the right answer for **now** — until ML-KEM has had enough deployment exposure to justify pure-PQ defaults, and until certificate chains migrate to ML-DSA or SLH-DSA signatures.

## Why "transitional" and not "ready"

A `transitional_hybrid` server still has a classical certificate chain (RSA-2048 or ECDSA P-256 signatures). A future quantum attacker can:

1. Recover the cert's private key from a captured signature (Shor's algorithm against ECDSA, factoring against RSA)
2. Forge a new cert in the server's name
3. Run an active man-in-the-middle attack against present-day TLS sessions

So `transitional_hybrid` protects **session secrecy** against harvest-now-decrypt-later attacks (see [HNDL](hndl.md)) but does not protect against a future quantum attacker actively impersonating the server. Full PQ readiness requires both PQ key exchange (hybrid is sufficient) **and** PQ signatures throughout the certificate chain.

QuReddy at MVP 0.1 only checks the key exchange. Cert-chain analysis lands at MVP 0.2. Until then, the readiness verdict reflects key-exchange posture only, and the recommendation copy explicitly notes that the cert chain remains classical.

## Why this matters now and not in 2035

The deployment timeline is driven by [HNDL](hndl.md): an attacker recording today's TLS traffic to decrypt it after a quantum breakthrough. The quantum breakthrough may be 2035 or 2045 or never. The traffic recording is happening now. Hybrid PQ key exchange is the only defense that protects sessions captured **today**. Waiting until quantum computers exist to deploy hybrid is too late by definition — the harvest happened years ago.

This is why responsible TLS operators (Cloudflare, Google, Apple, Meta) deployed hybrid PQ in 2024–2025, before any quantum threat materialized. The migration is forward-looking by design.

## Related

- [Harvest now, decrypt later (HNDL)](hndl.md) — the threat model that drives the timeline
- [Threat model and scope](threat-model.md) — what QuReddy assumes, what it doesn't try to defend against
- [Reference: Failure categories](../reference/failure-categories.md) — the `unknown` verdict's two failure modes (local vs target)
- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final) — the standard
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — the TLS 1.3 hybrid construction
