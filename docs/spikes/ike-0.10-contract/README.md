<!-- SPDX-License-Identifier: Apache-2.0 -->

# IKE 0.10 contract spike: evidence and handoff

Spike evidence for the 0.10.0 IKE contract freeze. **This directory contains no
production code.** Everything here is a generator, a generated artifact, or a
packet capture, retained so a reviewer can re-derive a claim without re-running
the lab.

## Contents

1. [What is settled](#1-what-is-settled)
2. [What is NOT RUN](#2-what-is-not-run)
3. [Artifacts](#3-artifacts)
4. [Reproducing](#4-reproducing)
5. [Where the rest of the evidence lives](#5-where-the-rest-of-the-evidence-lives)

## 1. What is settled

Four findings, each with a citation or a captured packet behind it.

### 1.1 IANA status and RFC 8247 requirement are independent axes

A catalog carrying one status field produces wrong findings:

| Algorithm | ID | IANA status | RFC 8247 |
|---|---:|---|---|
| `ENCR_NULL` | 11 | `current` | **MUST NOT** `rfc8247:296` |
| `ENCR_3DES` | 3 | `current` | **MAY** `rfc8247:294` |
| `ENCR_DES` | 2 | `deprecated` | **MUST NOT** `rfc8247:295` |

IANA never marks `ENCR_NULL` deprecated. `AlgorithmStatus` alone is insufficient
and the catalog carries both fields.

### 1.2 Binding rules must be discriminated by IKE version

From `capture/ike-lab.pcap`, 12 dissected ISAKMP packets:

| Check | IKEv1 | IKEv2 |
|---|---|---|
| initiator identity echoed | required (cookie) | required (SPI) |
| responder identity non-zero | **yes** on Informational | **no**, zero is legal for a stateless error |
| exchange type equals request | **no**, error arrives as Informational (5) | yes |
| message ID equals request | **no**, independent per `rfc2408:3176` | yes |
| response flag | not in the v1 header | `0x20` set, `rfc7296:4122` |

Frame 6 is a `NO-PROPOSAL-CHOSEN` reply: the request was Identity Protection (2)
with message ID `0x00000000`; the response is Informational (5) with message ID
`0xb0175f38` and a non-zero responder cookie. Frames 8, 10 and 12 are IKEv2
stateless errors carrying responder SPI `0000000000000000` while being valid
bound responses.

**A single version-agnostic binding rule gives the wrong verdict in three of
five response rows.**

### 1.3 Silence has at least three distinct causes

UDP counters on the responders confirmed delivery while they replied with
nothing. Their own logs give the reason:

| Peer | Responder log | Scanner sees |
|---|---|---|
| `ike-main` | `ikev1: no acceptable IKE proposal offered` | silence, exit 0 |
| `ike-aggressive` | `ignoring exchange type 2 while awaiting 4` | silence, exit 0 |
| `ike-aggressive` under `-2` | `ignoring exchange type 34` | silence, exit 0 |

`ike-aggressive` is an Aggressive-Mode responder; a Main-Mode probe can never
reach it. That is a scheduling gap, not a peer fault, and it belongs in coverage
as a separate row rather than one `unknown`.

### 1.4 ike-scan is a corroborator, not an oracle

`ike-scan 1.9.5` exits **0** for silence, for explicit rejection, and for a live
answering peer alike. Its default proposal, read from the responder log, offers
`ENCR_DES`, `AUTH_HMAC_MD5_96` and `PRF_HMAC_MD5`, all **MUST NOT** in RFC 8247.

## 2. What is NOT RUN

Stated plainly so nothing here is mistaken for coverage.

| Spike output | Status |
|---|---|
| Algorithm catalog | **done** |
| Binding matrix | **partial**, no retry state diagram |
| Proposal/transform tuple matrix | **NOT RUN** |
| Payload and notification parsing table | **NOT RUN** |
| IKEv1/IKEv2 NAT-T evidence | **NOT RUN**, zero NAT-T packets captured |
| Live peer matrix | **partial**, no Aggressive Mode, no accepted tuple |
| PQC/ADDKE design for 0.14 | **NOT RUN** |
| Coverage manifest | **NOT RUN** |
| JSON/JSONL/Rich/CBOM projections | **NOT RUN** |

**The blocking gap is a completed, accepted negotiation on the wire.** Every
packet captured here is an error or silence. Without an accepted tuple there is
no tuple matrix, no payload table beyond error notifies, and no projections.

## 3. Artifacts

| Path | What |
|---|---|
| `catalog/gen_catalog.py` | builds the catalog from the pinned IANA snapshots; no network |
| `catalog/add_rfc8247.py` | adds the independent RFC 8247 requirement axis |
| `catalog/ike-catalog.json` | 332 entries, IKEv1 118 and IKEv2 214 |
| `capture/ike-lab.pcap` | 12 ISAKMP packets, IKEv1 and IKEv2, five peers |

Catalog provenance is embedded per row: registry file, canonical source URL,
the registry's own `updated` value, and its SHA-256. The RFC 8247 axis likewise
records its canonical URL and SHA-256. The generators reject missing or changed
inputs rather than silently generating from a different snapshot.

```
ikev2-parameters.xml  updated=2026-07-16  sha256=9bf17e07cfe8bba7a5c249bd882873077f480d0f968b47c64ae3e6b7f096dd6b
ipsec-registry.xml    updated=2024-12-06  sha256=5f84b390027091816f48942f0ad9a5402491ae658c0585481c6f4d1ceaeae3f0
rfc8247.txt                               sha256=e1e6a86cfddcb2ebbe39ba1c2cf5516b8cb5f39fd0d53dea468a522a3b7a7250
```

## 4. Reproducing

```bash
# Run from the QuReddy repository root. Set BREACHSAFE_COMMON_DIR to a local
# corpus containing the exact snapshots listed above.
: "${BREACHSAFE_COMMON_DIR:?set this to the breachsafe-common checkout}"
SPIKE_DIR=docs/spikes/ike-0.10-contract
uv run --locked python "$SPIKE_DIR/catalog/gen_catalog.py" \
  --corpus-dir "$BREACHSAFE_COMMON_DIR/standards/rfc/iana-ike" \
  --output "$SPIKE_DIR/catalog/ike-catalog.json"
uv run --locked python "$SPIKE_DIR/catalog/add_rfc8247.py" \
  --rfc-path "$BREACHSAFE_COMMON_DIR/standards/rfc/rfc8247/rfc8247.txt" \
  --catalog "$SPIKE_DIR/catalog/ike-catalog.json"

# capture, from a container on the lab bridge
tshark -r "$SPIKE_DIR/capture/ike-lab.pcap" -Y isakmp -T fields \
  -e frame.number -e ip.src -e isakmp.ispi -e isakmp.rspi \
  -e isakmp.version -e isakmp.exchangetype -e isakmp.flags -e isakmp.messageid
```

### Two traps that cost real time

**Never use `str.splitlines()` on an RFC.** The files contain form feeds, which
Python treats as line breaks and `grep -n` does not. RFC 8247 is 1086 lines to
Python and 1068 to grep, so citations drift by up to 19 lines. **111 of 129
corpus `.txt` files contain form feeds.** Use `split("\n")`.

**The two IANA files use different element names.** `ikev2-parameters.xml` uses
`<description>`; `ipsec-registry.xml` uses `<name>`. A parser matching only one
silently drops an entire IKE version and still produces a plausible catalog.

**IKEv1 Phase 1 attributes live in `ipsec-registry.xml`.** `isakmp-registry.xml`
holds ESP and AH transforms, which are Child-SA and out of scope for an
unauthenticated scan.

## 5. Where the rest of the evidence lives

| Evidence | Location |
|---|---|
| Frozen contract | `docs/architecture/ike-scanner-adr.md` §4.1, merged in #611 and corrected in #612 |
| Catalog results and the three generator defects | issue #550 |
| ike-scan oracle comparison | issues #552, #553, #563 |
| Wire-verified binding matrix | issues #552, #553, #597 |
| Delta against `src/` | issues #463, #473, #539, #549 |
| Phase 0 lab, run `20260831T104450Z` | the private lab repo, not this one |
