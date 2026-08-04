# Harvest now, decrypt later

Harvest now, decrypt later (HNDL) is the confidentiality risk that gives
post-quantum key exchange migration its present-day timeline. An adversary can
retain encrypted traffic now and attempt decryption when a later capability
breaks the original key exchange.

## Contents

1. [Threat sequence](#1-threat-sequence)
2. [Why ephemeral classical exchange is affected](#2-why-ephemeral-classical-exchange-is-affected)
3. [Why migration cannot wait](#3-why-migration-cannot-wait)
4. [What hybrid exchange protects](#4-what-hybrid-exchange-protects)
5. [What it does not protect](#5-what-it-does-not-protect)
6. [How QuReddy uses this model](#6-how-qureddy-uses-this-model)
7. [Related documentation](#7-related-documentation)

## 1. Threat sequence

The HNDL sequence is:

1. an adversary records an encrypted session and its public handshake data;
2. the adversary stores those bytes;
3. a later cryptanalytic capability breaks the classical key exchange;
4. the adversary derives the historical session secret and attempts
   decryption.

The target data must remain sensitive long enough for the later step to
matter. The required protection date therefore depends on data lifetime and
migration time, not only on a forecast for quantum hardware.

## 2. Why ephemeral classical exchange is affected

TLS 1.3 X25519 creates an ephemeral shared secret. Destroying the ephemeral
private values provides forward secrecy against later compromise of a
long-term certificate key.

A sufficiently capable quantum computer changes the assumption for the
elliptic-curve discrete logarithm problem itself. The captured public exchange
can then become useful even though the ephemeral private values were erased.
Forward secrecy against classical long-term key compromise is not the same as
post-quantum confidentiality.

## 3. Why migration cannot wait

Protection added after a session was captured cannot change that historical
session. An operator needs the post-quantum contribution in place before the
sensitive traffic crosses the network.

Migration also takes time across clients, servers, proxies, load balancers,
inspection systems, and operational policy. Evidence about current
negotiation is needed before scheduling that work.

## 4. What hybrid exchange protects

A correctly designed hybrid key exchange combines classical and post-quantum
secret contributions. Breaking the classical contribution later should not be
enough to derive the session key while the post-quantum contribution remains
secure.

For TLS, QuReddy requests `X25519MLKEM768` and records the negotiated group.
For SSH, it records recognized hybrid key exchanges in the server offer. These
are endpoint observations, not a proof about every connection path.

## 5. What it does not protect

Hybrid key exchange does not by itself protect:

- sessions captured before hybrid deployment;
- data available in plaintext at a compromised endpoint;
- future active impersonation through vulnerable authentication;
- certificate trust, hostname, revocation, or chain validation;
- traffic on another endpoint or path;
- application data stored outside the protected session.

Authentication migration and key exchange migration are related but separate
work.

## 6. How QuReddy uses this model

QuReddy treats a recognized hybrid key exchange as
`transitional_hybrid`. Classical-only key exchange is
`quantum_vulnerable`. Collection failure remains `unknown`.

The scanner reports observations and findings. It does not estimate a quantum
computer date, calculate data sensitivity, select a business deadline, or
perform remediation.

## 7. Related documentation

- [Why hybrid post-quantum](why-hybrid-pq.md)
- [Threat model](threat-model.md)
- [NIST post-quantum cryptography project](https://csrc.nist.gov/projects/post-quantum-cryptography)
