<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->
# VPN readiness: scanning IPsec, OpenVPN, and WireGuard

How QuReddy assesses the three VPN families for insecure and quantum-vulnerable
cryptography, why each needs a different approach, and what is provably out of
reach. Spike design behind `scan vpn <type>` (BreachSAFE/qureddy#732, #733,
#737, #742).

## Contents

1. [The problem](#1-the-problem)
2. [The three families are not symmetric](#2-the-three-families-are-not-symmetric)
3. [OpenVPN: native ClientHello through the control channel](#3-openvpn-native-clienthello-through-the-control-channel)
4. [WireGuard: silent by design](#4-wireguard-silent-by-design)
5. [Base tier vs Enterprise tier](#5-base-tier-vs-enterprise-tier)
6. [Why not nmap, veepin-as-dependency, or tshark](#6-why-not-nmap-veepin-as-dependency-or-tshark)
7. [Evidence](#7-evidence)

## 1. The problem

A plain TLS scanner sees an HTTPS server. It does not see the crypto inside a
VPN tunnel. A legacy VPN gateway running TLS 1.0 and 3DES, or classical-only key
exchange, is invisible to it. VPN readiness closes that gap: reach the
negotiation inside the tunnel and rate it against the same crypto policy used
for TLS.

## 2. The three families are not symmetric

| Family | Wire | Crypto model | Approach |
|---|---|---|---|
| IPsec / IKE | UDP 500/4500 | negotiated (enumerable transforms) | ike-scan (existing) |
| OpenVPN | UDP/TCP 1194 | negotiated TLS inside a control channel | native ClientHello probe |
| WireGuard | UDP 51820 | one fixed suite, no negotiation | fingerprint + fixed verdict |

IPsec and OpenVPN negotiate, so they are scannable. WireGuard does not
negotiate and is silent to strangers, so it is not.

## 3. OpenVPN: native ClientHello through the control channel

OpenVPN is not a raw TLS server. It wraps the TLS handshake in its own reliable
control channel (opcode, session id, ACK array, packet id). So a raw TLS
ClientHello never reaches it. The probe speaks just enough OpenVPN:

1. `HARD_RESET_CLIENT_V2` -> the server answers `HARD_RESET_SERVER_V2`
   (confirms OpenVPN).
2. a hand-built TLS ClientHello, offering weak suites, is sent inside a
   `P_CONTROL_V1` packet.
3. the server's control packets are collected and ACKed until the ServerHello
   arrives; the negotiated version and cipher are read off the wire.

Two properties make this valuable:

- **Native ClientHello.** The ClientHello is built by hand, so it can offer and
  observe suites that OpenSSL 3.5.7 compiled out (3DES, RC4, NULL, EXPORT). This
  is the same blind spot as the direct-TLS native probe, inside a VPN tunnel.
- **Unauthenticated.** The ServerHello arrives before client-certificate
  verification, so no credentials are needed to read the negotiated crypto.

The `_client_hello()` and ServerHello-parse logic is shared with the direct-TLS
native probe; only the control-channel framing is OpenVPN-specific.

## 4. WireGuard: silent by design

WireGuard uses the fixed Noise_IKpsk2 suite (Curve25519, ChaCha20-Poly1305,
BLAKE2s). It has no crypto agility, so there is nothing to enumerate, and it
answers nothing to a party it does not already know:

- an init with an invalid `mac1` is dropped (mac1 requires the responder's
  public key);
- an init with a **valid** `mac1` is also dropped, because the Noise handshake
  fails unless the responder already holds the initiator's static public key.

Both were confirmed against a live local WireGuard. So an unauthenticated
scanner is structurally locked out, and `SILENT` is inconclusive (WireGuard or a
filtered port), never "not WireGuard". The base verdict is therefore fixed:
Curve25519 key establishment is quantum-vulnerable, unless a `psk2` PSK or
Rosenpass overlay is present, which is unobservable without provisioning.

## 5. Base tier vs Enterprise tier

| | Base (unauthenticated) | Enterprise (provisioned) |
|---|---|---|
| Access | none | customer-supplied config / credentials |
| IPsec | ike-scan negotiation observation | same, plus scoped context |
| OpenVPN | ServerHello read (works unauthenticated) | same |
| WireGuard | fingerprint + fixed verdict | complete the handshake, report `hndl_hedge` (psk2 / rosenpass / none) |

The Enterprise tier exists because WireGuard's one meaningful variable, whether
the deployment is quantum-hedged, is observable only as a provisioned peer. The
customer authorizes access the same way they would for a pentest. A scanner
cannot self-provision.

## 6. Why not nmap, veepin-as-dependency, or tshark

- **nmap** cannot scan the UDP VPN ports without root, and even then reports
  service presence, not the negotiated crypto. It was removed as a dependency
  (#703).
- **veepin** (MIT, Go) is the reference for the OpenVPN control framing and the
  WireGuard client handshake. The base OpenVPN probe ports its framing to pure
  Python; the Enterprise WireGuard handshake wraps veepin as a sidecar (it needs
  a tun). It is a reference and an optional sidecar, not a hard dependency.
- **tshark** has correct dissectors and is the development verifier and an
  optional local wire-view. It is passive, needs root, and cannot initiate a
  handshake, so it is not the collector.

## 7. Evidence

- OpenVPN, live against a local insecure server: negotiated `TLS1.0` /
  `0x0035` (AES256-CBC-SHA) -> `insecure: true`. The server random even carried
  the RFC 8446 `DOWNGRD` sentinel.
- WireGuard, live against a `wg show`-verified local server: invalid-mac1 and
  valid-mac1 inits both `SILENT`; a provisioned client completed the handshake
  in 4ms, and the server's `latest-handshakes` distinguished the provisioned
  peer from an unprovisioned one.
- nmap: `-sU` requires root; TCP fallback reports `1194/tcp closed openvpn` from
  its port database, no crypto.
