<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# Wallet scanner: architecture views

Leveled data flow diagrams and structural views for `qureddy scan wallet`. The decisions these
views illustrate live in [the wallet scanner ADR](wallet-scanner-adr.md); this file carries the
diagrams so the ADR stays a record of choices and their reasons.

## Contents

1. [Notation](#1-notation)
2. [Context diagram](#2-context-diagram)
3. [Level 0](#3-level-0)
4. [Level 1: assemble observations](#4-level-1-assemble-observations)
5. [Layer view](#5-layer-view)
6. [Component view](#6-component-view)
7. [Sequence: one Bitcoin scan](#7-sequence-one-bitcoin-scan)
8. [Process swimlane: every call and where it is captured](#8-process-swimlane-every-call-and-where-it-is-captured)
9. [Packet capture](#9-packet-capture)
10. [Data model](#10-data-model)
11. [Trust boundaries](#11-trust-boundaries)
12. [References](#12-references)

## 1. Notation

Yourdon and Gane-Sarson, four element types, per
`breachsafe-architecture-review/references/data-flow-diagrams.md`.

```text
[ rectangle ]        external entity   outside the boundary of what is designed
( rounded )          process           named with a verb phrase
=== open box ===     data store        data at rest
----label---->       data flow         labelled with what the data is
- - - - - - -        trust boundary    a dashed line the flow crosses
```

A decision diamond or a control-flow construct would make this a flowchart, which answers the
sequence of control. A DFD answers the path of data.

## 2. Context diagram

The whole scanner as one process, every external entity around it.

```text
                    - - - - - -  T1 operator to tool  - - - - - -

  [ Operator ] ----account identifier---->(                          )
               <---exposure report--------(   Assess wallet key      )
               <---crypto inventory-------(   exposure               )
                                           ^        ^           |
        - - - - - -  T2 host to public internet - - | - - - - - | - - - -
                     |            |                 |           |
         ledger facts|            |account state    |     run artefacts
                     |            |                 |           v
  [ Chain indexer ]--+            |                 |   === Run directory ===
    mempool.space                 |                 |
    blockstream.info              |            leaf certificate
                                  |                 |
  [ RPC node ]--------------------+        [ Indexer TLS endpoint ]
    ethereum-rpc.publicnode.com
    rpc.ankr.com
```

Every external entity is a third party. The scanner originates no data of its own beyond the
identifier the operator supplies.

## 3. Level 0

```text
  [ Operator ]
        | account identifier
        v
  ( 1 Decode address )----script class, network, curve------------------+
        |  reaches no network                                           |
        | validated account                                             |
        v                                                               |
  - - - - - - - - -  T2 host to public internet  - - - - - - - - - - -  |
        |                                                               |
        +--account query--->[ Chain indexer ]----ledger facts-----+      |
        +--account query--->[ RPC node ]--------account state-----+      |
        +--handshake------->[ Indexer TLS ]-----leaf certificate--+      |
                                                                  v      v
                                              ( 2 Assemble observations )
                                                    |            |
                published keys, signatures, counts  |            | transcripts, certificate
                                                    v            v
                                        ( 3 Scan signing defects )
                                                    |
                                        scan result |
                                                    v
                                        ( 4 Render projections )
                                                    |
              +-------------+-------------+---------+---------+----------------+
              v             v             v                   v                v
          rich text     scan.json    scan.cdx.json       scan.jsonl     certificate.pem
              +-------------+---------=== Run directory ===--------------+
```

Process 1 sits outside the trust boundary on purpose. It answers with no network, so an
unreachable indexer still yields the script class, and the chain rows read `not tested` in place
of a default.

## 4. Level 1: assemble observations

Only process 2 is decomposed. It earns it: this is where a claim's observation type is decided,
which is the contract the whole ADR exists to hold.

```text
        ledger facts                    account state
             |                               |
             v                               v
  ( 2.1 Read output scripts )      ( 2.4 Classify account )
             | p2pk, multisig, v1_p2tr        | 0x            -> eoa
             |                                | 23B 0xef0100  -> delegated
             v                                | anything else -> contract
  ( 2.2 Recover public keys )                 |
             | vin[].witness[1] and scriptsig |
             | pushes of 02|03 + 32B, 04 + 64B|
             v                                v
  ( 2.3 Decide observation type )<------------+
             |
     +-------+---------------+------------------+
     v       v               v                  v
  OBSERVED   INFERRED     NOT_TESTABLE      coverage bound
  key bytes  spent count  a lane failed     the page is
  were read  or protocol  or no evidence    smaller than
             rules        was produced      the total
```

Balance check: the flows into 2.1, 2.2 and 2.4 are exactly the `ledger facts` and `account state`
flows entering process 2 at Level 0, and the flow out of 2.3 is the `published keys, signatures,
counts` flow leaving it.

## 5. Layer view

```text
  cli  ------>  output  ------>  scanners  ------>  core
                                    ^
                  collectors -------+   adapter, imports core only
```

`lint-imports` enforces the direction over 126 files and 399 dependencies. The wallet package
sits under `scanners`, so it imports `core` and the standard library. An early draft placed the
`WALLET_SIGNATURE_EVIDENCE` constant in `output`, which the contract refused, so the constant
lives in `core.vocabulary` where both layers reach it.

## 6. Component view

```text
  NEW                             EXTENDED                 REUSED UNTOUCHED
  --------------------------      -------------------      --------------------------
  scanners/wallet/                output/cbom.py     +2     add_algorithm_assets
    address.py    indexer.py      cbom_components.py +2     add_algorithm_component
    ethereum.py   keccak.py       jsonl.py          +12     select_by_evidence_type
    profiles.py   scanner.py      console/_tables.py +22    signature_algorithm_properties
  output/cbom_wallet.py    38     core/vocabulary.py  +1    build_probe_result
  cli/wallet.py                   core/models.py     +24    fetch_certificate_pem
  tests/live/test_live_wallet.py  scanners/common/          parse_certificate
                                    rollup.py         +2    evidence_from_certificate
                                                            render_json, render_jsonl
                                                            render_rich, _render_bundle
                                                            _execute_scan
                                                            build_scan_metadata
                                                            build_scan_summary
                                                            build_endpoint_asset
                                                            validate_output_bundle.py
```

`output/cbom_wallet.py` mirrors `cbom_ssh.py`: a per-protocol module that selects its own
evidence and hands it to the shared asset loop. That is the seam the output layer already
defines for a protocol, so extending it rebuilds nothing.

## 7. Sequence: one Bitcoin scan

```text
  Operator    cli/wallet    WalletScanner    indexer    TLS probe    output/
     |            |              |              |           |           |
     |--ADDRESS-->|              |              |           |           |
     |            |--decode------|              |           |           |
     |            |  a failed checksum exits 4 before any network call  |
     |            |--ScanTarget->|              |           |           |
     |            |              |--GET /address--->        |           |
     |            |              |<--chain_stats----        |           |
     |            |              |--GET /txs------->        |           |
     |            |              |<--transaction page        |          |
     |            |              |--s_client--------------->|           |
     |            |              |<--leaf PEM---------------|           |
     |            |              |--Counter over r values   |           |
     |            |<--ScanResult-|              |           |           |
     |            |--render------------------------------------------->|
     |<--rich, json, cbom, jsonl, certificate.pem-----------------------|
```

## 8. Process swimlane: every call and where it is captured

The sequence above collapses the capture step. This view puts it back, so a reader sees which
lane owns each call and where its transcript becomes evidence.

```text
 cli/wallet     WalletScanner     indexer.py       mempool.space      evidence
 ------------ | --------------- | -------------- | ---------------- | --------------
  ADDRESS     |                 |                |                  |
    |         |                 |                |                  |
  decode -----+-- a failed checksum exits 4 before any packet leaves +--------------
    |         |                 |                |                  |
  ScanTarget->|                 |                |                  |
              | fetch(subject)->|                |                  |
              |                 | bases()        |                  |
              |                 |  |  QUREDDY_ESPLORA_URL replaces the defaults,
              |                 |  |  with no fallback to a public indexer
              |                 |  v             |                  |
              |                 | #01 GET /api/address/{a} -------->|
              |                 |                | 200, 284 B, 1789 ms
              |                 |<- chain_stats -|                  |
              |                 | record HttpExchange ------------->| evidence 1
              |                 |                |                  |  wallet.http
              |                 |                |                  |  ProbeResult
              |                 |                |                  |  sha256, curl -v
              |                 | #02 GET /api/address/{a}/txs ---->|
              |                 |                | 200, 112 KB, 1766 ms
              |                 |<- 50 txs ------|                  |
              |                 | record HttpExchange ------------->| evidence 2
              |                 | harvest:       |                  |
              |                 |   vout scriptpubkey_type          |
              |                 |   vin prevout address match       |
              |                 |   witness[1] public key           |
              |                 |   witness[0] DER to r and s       |
              |<- ChainFacts ---|                |                  |
              |                 |                |                  |
              | s_client -------+----------------+-> mempool.space:443 TLS
              |<- leaf PEM -----+----------------+------------------| evidence 3
              |                 |                |                  |  tls.cert.signature
              |                 |                |                  |  certificate_pem
              | Counter over r values            |                  | evidence 4+
              |                 |                |                  |
              |- ScanResult --->|                |                  |
  render <----|                 |                |                  |
```

Ethereum runs the same shape over three JSON-RPC posts, each captured the same way:

```text
  #01 POST eth_getTransactionCount   publicnode.com   200, 391 ms   wallet.http
  #02 POST eth_getCode               publicnode.com   200, 298 ms   wallet.http
  #03 POST eth_getBalance            publicnode.com   200, 295 ms   wallet.http
```

The JSON-RPC envelope travels in `request_body`, so the transcript shows what was asked as well
as what came back. All three post to one URL, and the console's `Commands run` panel
deduplicates on the rendered command, so `HttpExchange.operation` carries the JSON-RPC method
into the command line and keeps the three calls three lines.

`scripts/wallets_comprehensive.sh` runs every profile in
`src/qureddy/scanners/wallet/profiles.py` at `--format rich -vvv` on screen, with a mutated
checksum as the last case to prove the offline gate still exits 4 before a packet leaves.

### Failover

The swimlane collapses a loop. Each attempt records its own exchange, so a failover is visible
in the trace in place of being inferred from a changed hostname.

```text
  for base in bases():
      #01 GET /address --> mempool.space      200  -+-> use this base, stop
                                              fail -+
                       --> blockstream.info   200  ---> use this base, stop
                                              fail ---> reachable is False, and every
                                                        chain row reads not tested
```

## 9. Packet capture

No packet capture runs. A prototype captured one with `dumpcap` and the capture was dropped
here for two reasons.

The payload is TLS, so a capture evidences that a session with that endpoint took place during
the scan window. It does not attribute individual encrypted records to individual HTTP calls,
and another process talking to the same indexer in the same window is captured too. The
`ProbeResult` transcript carries what the capture cannot: the request line, every header, the
body that was parsed, the timing, and a sha256 over the stream shown.

Capture also needs a privilege this engine otherwise avoids. On macOS a `/dev/bpf` device is
required, the pool is small, and an orphaned `dumpcap` holds one until it is reaped, which is a
failure the prototype hit.

Capture is worth externalizing in place of dropping outright. A wrapper that starts a capture, runs
`qureddy scan wallet --output-dir`, stops the capture, and drops `scan.pcap` beside the other
artefacts produces the same bundle with no privilege inside the scanner and no second code path
in it:

```text
  dumpcap -i <iface> -f "host <indexer ip> and port 443" -w run/scan.pcap &
  qureddy scan wallet <address> --output-dir run/
  kill the capture
```

The run directory contract already accommodates the file, and
`features/scan/panes.py` in the application layer already renders a `scan.pcap` when one is
present, so the wrapper needs nothing from this repository.

## 10. Data model

```text
  INTERNAL, dataclass, dies in the scanner    ON THE WIRE, frozen pydantic

  DecodedAddress --+                          ScanResult
  ChainFacts ------+                            +-- ScanMetadata
  HttpExchange ----+--> folded into -->          +-- ScanTarget    subject is the one new field
  Signature -------+                            +-- Asset[]
  AccountFacts ----+                            +-- Evidence[]     observation_type, probe_result
                                                +-- Finding[]      severity, readiness
                                                +-- ScanSummary    nist levels
```

New structures reaching a consumer: none. New fields: one, optional, excluded when unset, so
`tls`, `ssh` and `ike` serialization is byte identical.

Each internal field reaches the wire through a model that already existed:

| Internal | Reaches the wire as |
|---|---|
| `DecodedAddress.script` | `Asset.asset_type`, and the `script.type` finding |
| `ChainFacts.public_keys` | one finding per key, `Evidence.observation_type` OBSERVED |
| `ChainFacts.spent_txo_count` | the `key.published` finding at INFERRED when no key was read |
| `ChainFacts.transactions_examined` | the coverage finding required by C4 |
| `HttpExchange` | `Evidence.probe_result`, built by `build_probe_result` |
| `Signature.r` | the nonce finding at `Readiness.CLASSICALLY_WEAK` |
| the leaf certificate | `Evidence.certificate_record` and `certificate_pem` |

## 11. Trust boundaries

| Boundary | Crossed by | Note |
|---|---|---|
| T1 operator to tool | the account identifier in, the report out | the identifier is a public ledger entry, and the operator supplies it |
| T2 host to public internet | the account, disclosed to a third-party indexer | `QUREDDY_ESPLORA_URL` and `QUREDDY_ETH_RPC` each replace the public defaults, so an internal node keeps the account inside the operator's boundary |
| T3 tool to OpenSSL | a subprocess with a list-form argv and no shell | the capability gate decides which binary is usable |
| T4 tool to disk | the run directory, including `certificate.pem` | written only when `--output-dir` is given |

T2 is the boundary that matters. Every flow crossing it is a candidate STRIDE entry point, and
enumerating those threats belongs to `breachsafe-security-audit`. This document draws the
boundary and stops there.

## 12. References

- `breachsafe-architecture-review/references/data-flow-diagrams.md`, notation and leveling.
- [Wallet scanner ADR](wallet-scanner-adr.md), the decisions these views illustrate.
- [Data model](data-model.md), generated from the source by `scripts/gen_data_model.py`.
- `scripts/validate_output_bundle.py`, the cross-format conformance validator.
