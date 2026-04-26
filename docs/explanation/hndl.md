# Harvest now, decrypt later (HNDL)

HNDL is the threat model that gives PQ migration its timeline. It explains why responsible operators deployed hybrid post-quantum key exchange in 2024–2025 instead of waiting for quantum computers to actually exist.

## The threat in one paragraph

A passive attacker records encrypted network traffic today. Twenty years from now, when a sufficiently powerful quantum computer becomes available, the attacker decrypts the recorded traffic. **The attack succeeds because the harvest happened today and the decryption happens tomorrow.** Anything captured before key-exchange algorithms migrated to post-quantum primitives becomes plaintext on the day the quantum machine boots.

## Who actually does this

State-level intelligence services have been documented to record encrypted traffic at-scale for forensic and signals-intelligence purposes. The Snowden disclosures (2013) confirmed bulk capture programs at NSA and GCHQ. The capture infrastructure exists; the storage cost has fallen by an order of magnitude per decade since. Recording 100 PB/year of TLS metadata is well within the budget of any G20 intelligence agency.

The attacker doesn't need to know what's interesting at capture time. Storage is cheap; computation is the constraint. A quantum computer changes the computation cost from "infeasible forever" to "feasible in batch." Once that flip happens, every captured session is worth running through the new attack.

## Why classical key exchange is uniquely vulnerable

TLS 1.3 with X25519 negotiates an ephemeral shared secret using the elliptic-curve Diffie-Hellman protocol. The ephemeral shared secret protects the session key for that one connection. The math:

1. Client and server each generate a random scalar (`a`, `b`) and exchange the corresponding curve points (`aG`, `bG`).
2. Both compute the shared secret `abG` from each other's public point.
3. The session key is derived from `abG` via HKDF.
4. The ephemeral scalars `a` and `b` are wiped after the handshake.

The attacker captures the public exchange (`aG` and `bG` go over the wire in plaintext) plus the encrypted session traffic. To recover the session key, the attacker must compute `abG` from `aG` and `bG` alone. This is the **elliptic curve discrete logarithm problem (ECDLP)**, and Shor's algorithm solves it in polynomial time on a sufficiently large quantum computer.

A 2048-bit RSA key has the same problem against Shor's: the captured ClientKeyExchange (TLS 1.2) contains the encrypted pre-master secret, and Shor factors the RSA modulus to recover it.

The only defense is a key exchange whose security does not reduce to a problem Shor's algorithm solves. ML-KEM (FIPS 203) is one such construction.

## Why "now" matters more than "when"

Three properties combine to make HNDL urgent regardless of the quantum-computer timeline:

**Sessions captured today are vulnerable forever.** TLS 1.3 has perfect forward secrecy for the session key — once the handshake completes and `a` and `b` are wiped, the session key cannot be recovered without either the server's long-term key or the ephemeral exchange. A quantum computer recovers the ephemeral exchange. There is no defense applicable retroactively.

**The migration window precedes the threat by years.** TLS deployments take time. Server software, CDN edges, browser support, certificate authorities, intermediate proxies — the whole stack has to migrate. Even if a quantum computer arrives in 2040, the migration must complete by ~2030 to avoid a window where the harvest is already done but the defense is not yet deployed.

**Sensitive data has retention requirements.** Healthcare records, financial transactions, intelligence cables, classified communications — all of these have retention requirements measured in decades. A 30-year-old captured TLS session is still sensitive when decrypted.

The classic NIST framing: **`Storage Time + Migration Time > Time to Quantum Computer`** is the inequality that triggers urgency. If your data is sensitive for 30 years, your migration takes 5 years, and quantum computers arrive in 25 years — you're already too late.

## What hybrid PQ actually defends

Hybrid PQ key exchange (X25519MLKEM768) protects the **session secret** against HNDL. An attacker who captures a hybrid session today and runs it through Shor's algorithm in 2045 recovers the X25519 half of the shared secret but not the ML-KEM-768 half. The session key, derived from both, remains secret.

This is the *forward-secrecy guarantee at quantum scale.* It is the entire point of deploying hybrid PQ before quantum computers exist.

What hybrid PQ does **not** defend:

- **Server impersonation.** The cert chain is still classical (RSA / ECDSA signatures). A quantum attacker can recover the cert's private key from a captured signature and impersonate the server in a future *active* attack. Hybrid PQ key exchange does not affect this.
- **Sessions captured before the hybrid deployment.** Switching to hybrid in 2026 doesn't retroactively protect 2024 traffic.
- **Endpoints under attacker control.** HNDL is a *passive* threat model. An attacker who controls an endpoint sees plaintext directly; no key exchange protects against compromise.

These are out of scope. QuReddy reports key-exchange readiness; the cert-chain analysis lands at MVP 0.2.

## The timeline that matters for QuReddy operators

| Year | What happened | Implication |
|---|---|---|
| 2013 | Snowden disclosures confirm bulk capture | The harvest is already happening |
| 2016 | NIST PQC competition announced | The migration target exists |
| 2022 | Cloudflare ships X25519+Kyber experimentally | Production-grade hybrid arrives |
| 2024 | NIST publishes FIPS 203 (ML-KEM), 204 (ML-DSA), 205 (SLH-DSA) | Standardization completes |
| 2024–2025 | Cloudflare, Google, Apple deploy hybrid PQ at scale | Major operators commit |
| 2025 | OpenSSL 3.5 ships with X25519MLKEM768 support | Tooling parity reached |
| 2026 | QuReddy MVP 0.1 ships | This tool exists |
| ~2030 | Cryptographically-relevant quantum computer ETA (median NIST estimate) | The threat materializes |
| ~2030+ | Captured 2026 traffic is decrypted | The harvest pays off |

The "now" in "harvest **now**, decrypt later" refers to the second column. The "later" refers to the third. The window between them is when migration must happen.

## Related

- [Why hybrid post-quantum?](why-hybrid-pq.md) — the design call that defends against HNDL
- [Threat model and scope](threat-model.md) — what QuReddy assumes about the attacker
- [NIST IR 8413 — PQC migration timeline](https://csrc.nist.gov/pubs/ir/8413/upd1/final) — the conservative public estimate
- [Cloudflare Research: Defending against future threats](https://blog.cloudflare.com/post-quantum-for-all/) — operator perspective
