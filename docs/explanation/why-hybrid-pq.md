# Why hybrid post-quantum key exchange

[![Diátaxis explanation](https://img.shields.io/badge/Di%C3%A1taxis-explanation-8250df?style=flat-square)](https://diataxis.fr/explanation/)

QuReddy's TLS readiness probe requests `X25519MLKEM768`, which combines
classical X25519 with ML-KEM-768. The SSH scanner recognizes offered hybrid
families containing `mlkem768x25519` or `sntrup761x25519`. Hybrid deployment
adds post-quantum confidentiality while retaining a classical component.

## Contents

1. [Threats addressed](#1-threats-addressed)
2. [Why combine two primitives](#2-why-combine-two-primitives)
3. [Why ML-KEM-768 and X25519](#3-why-ml-kem-768-and-x25519)
4. [Readiness vocabulary](#4-readiness-vocabulary)
5. [Key exchange and authentication](#5-key-exchange-and-authentication)
6. [Why collection starts now](#6-why-collection-starts-now)
7. [Related documentation](#7-related-documentation)

## 1. Threats addressed

Classical elliptic-curve key exchange is vulnerable to Shor's algorithm on a
sufficiently capable quantum computer. ML-KEM is standardized in
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) and is not based on the
same mathematical problem.

Hybrid key exchange derives session key material from both a classical and a
post-quantum contribution. The security goal is that session confidentiality
survives when at least one approved contribution remains secure.

## 2. Why combine two primitives

Replacing a mature classical primitive immediately would make the new
post-quantum primitive the only protection. A hybrid combines migration
protection with continued classical protection.

This is a transition posture, not proof that every aspect of the connection is
post-quantum. Protocol authentication can remain classical even when key
exchange is hybrid.

## 3. Why ML-KEM-768 and X25519

ML-KEM-768 is the middle ML-KEM parameter set in FIPS 203. X25519 is the
classical component used by the TLS group that QuReddy requests.

QuReddy does not choose a target's production configuration. It tests the
named group supported by its OpenSSL collector and reports the actual
negotiation. SSH reports recognized hybrid algorithms from the server's offer
instead of forcing a choice.

An algorithm name in a handshake is an observation. It is not proof that the
remote software or cryptographic module has a FIPS validation.

## 4. Readiness vocabulary

| Value | Meaning |
| --- | --- |
| `transitional_hybrid` | A recognized classical plus post-quantum key exchange was negotiated or offered |
| `quantum_vulnerable` | The observed key exchange posture was classical only |
| `classically_weak` | A separately observed classical weakness takes rollup precedence |
| `quantum_safe` | Reserved for evidence establishing a pure post-quantum posture |
| `unknown` | Collection could not establish a posture |
| `not_applicable` | The readiness question does not apply to the asset |

`transitional_hybrid` is narrower than `quantum_safe`. It states the observed
transition mechanism.

## 5. Key exchange and authentication

Hybrid key exchange protects session key establishment against harvest now,
decrypt later exposure. TLS authentication can still depend on classical
certificate signatures. SSH host keys can remain classical, and a weak host
key offer can produce `classically_weak`.

The TLS scanner observes the leaf certificate signature algorithm but does not
validate the chain. It does not claim that all certificates, keys, signatures,
or application data paths are post-quantum.

## 6. Why collection starts now

An adversary can retain encrypted traffic before a cryptographically relevant
quantum computer exists. A future capability could affect the confidentiality
of traffic captured under vulnerable key exchange today.

Deployment and evidence collection therefore precede the future threat.
QuReddy measures the current endpoint posture so an operator can identify the
migration gap without treating a forecast date as a prerequisite.

## 7. Related documentation

- [Harvest now, decrypt later](hndl.md)
- [Threat model](threat-model.md)
- [JSON readiness values](../reference/json-schema.md#enumerated-values)
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)
