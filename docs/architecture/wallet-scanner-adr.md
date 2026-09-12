<!--
SPDX-FileCopyrightText: 2026 BreachSAFE
SPDX-License-Identifier: Apache-2.0
-->

# ADR: Wallet scanner, and the claims a wallet finding may make

**Status:** Proposed

## Contents

1. [Context](#1-context)
2. [The seven defects this specification exists to stop](#2-the-seven-defects-this-specification-exists-to-stop)
3. [Decision](#3-decision)
4. [Claims contract](#4-claims-contract)
5. [Module layout](#5-module-layout)
6. [Data structures and their relationships](#6-data-structures-and-their-relationships)
7. [Call graph and parameter injection](#7-call-graph-and-parameter-injection)
8. [Subject model](#8-subject-model)
9. [Bitcoin lane](#9-bitcoin-lane)
10. [Ethereum lane](#10-ethereum-lane)
11. [Signing defects](#11-signing-defects)
12. [Hard-coded addresses](#12-hard-coded-addresses)
13. [CLI surface](#13-cli-surface)
14. [Alternatives considered](#14-alternatives-considered)
15. [Consequences](#15-consequences)
16. [Acceptance gates](#16-acceptance-gates)
17. [Anti-pattern check](#17-anti-pattern-check)
18. [Revisit when](#18-revisit-when)
19. [References](#19-references)

## 1. Context


A wallet holds a key on the same curve families QuReddy already grades. Bitcoin and Ethereum
both sign with secp256k1, which meets no NIST post-quantum category, so every account on either
chain carries `nistQuantumSecurityLevel` 0. That value is constant and therefore uninteresting
on its own. What varies per account, and what a scan can measure, is whether the public key has
been published on chain, because that is the input Shor's algorithm requires.

A prototype of this scanner shipped in the itsqday application layer during
2026-09-07. It worked, and its defects were uniform in kind: the architecture held, and the
claims drifted. Every defect found in review was a statement the output made that the evidence
did not support. This ADR therefore fixes the claims contract first and treats the architecture
as settled, because the architecture is a reuse of `ScanResult`.

## 2. The seven defects this specification exists to stop


Each was found in the prototype by a human reader, and each passed a green test suite.

| # | Defect | Shape |
|---|---|---|
| 1 | A `T1/T2/T4/TC/NT` exposure ladder invented in-repo, rendered beside the NIST scale | invented vocabulary reads as normative |
| 2 | A packet capture described as proving the JSON crossed the network | over-claim; the payload is TLS |
| 3 | Five of six demo addresses recalled from model memory, one an arbitrary third party's live wallet | unsourced constant |
| 4 | A log line promising the body was stored verbatim while storage capped at 4 MB | artefact claim contradicted the artefact |
| 5 | Ethereum `key.published` marked observed while the lane reads no key bytes | inference labelled as observation |
| 6 | `txs[:25]` sliced a mempool-first array and reported "25 transactions" | silent, undisclosed sampling |
| 7 | Explanatory prose accumulating in rendered output across four rounds | narration displacing data |

Defects 1, 3 and 5 are the same failure: a claim with no source. Defects 2, 4 and 6 are the same
failure: a claim wider than the evidence. Defect 7 is the surface those two hide behind.

## 3. Decision


Add a `wallet` scanner under `scanners/wallet/` and a `qureddy scan wallet` subcommand. Produce a
`ScanResult`, so `output/` renders rich, JSON, JSONL and CycloneDX with no change to that layer.

Introduce no grading scale. The engine already carries `nist_quantum_security_level` (0 to 5) on
`Asset`, `Evidence`, `Finding` and `ScanSummary`, and already carries `ObservationType` and
`Readiness`. A wallet finding uses those and adds none.

## 4. Claims contract


This section is normative for the wallet scanner. A finding that breaks a rule here is a defect
even when every test passes.

| # | Rule |
|---|---|
| C1 | Every finding states a value, the lane that produced it, and the expression the value came from. |
| C2 | `ObservationType.OBSERVED` requires that the scanner read the bytes it reports. A conclusion drawn from protocol rules is `INFERRED`. |
| C3 | Absent evidence is `NOT_TESTABLE`. A lane that did not run yields `NOT_TESTABLE`, and a `false` is reserved for a measured negative. |
| C4 | Whenever a result rests on a bounded sample, the bound is a finding of its own, carrying the size examined and the size available. |
| C5 | The scanner asserts no severity scale, readiness value, or security level beyond those already defined in `core/vocabulary.py` and the NIST categories quoted in `core/pqc`. |
| C6 | Every address compiled into the source carries a re-runnable check that establishes what it is. |
| C7 | A claim about an artefact matches the artefact. A cap, a truncation, or a filter is recorded next to the data it shaped. |
| C8 | Rendered output carries values and their sources. Explanation belongs in this document. |

C2 has teeth on the Ethereum lane specifically. That lane reads account state, never key
material, so its exposure conclusion is `INFERRED` in every case.

## 5. Module layout


New modules sit under `scanners/wallet/`. Every other layer is reused unchanged.

```text
src/qureddy/
  cli/
    main.py          reused   scan_app, the subcommand attaches here
    _options.py      reused   FormatOpt, OutputDirOpt, VerboseOpt
    _render.py       reused   _render, _render_bundle, _prepare_output_dir
    _execute.py      reused   _execute_scan
    _errors.py       reused   EXIT_OK, EXIT_USAGE, _fail
    __init__.py      edited   one import registers the command
    wallet.py        new      command body
  output/            reused   console/, json, jsonl, cbom and 13 emitters. No edit.
  scanners/
    common/          reused   posture, rollup, finding_types
    wallet/          new
      address.py       offline decode, checksum enforced
      indexer.py       Esplora REST
      keccak.py        Keccak-256 for EIP-55
      ethereum.py      JSON-RPC account state
      scanner.py       assembles ScanResult
  core/
    models.py        edited   btc and eth schemes, ScanTarget.subject
    vocabulary.py    reused   ObservationType, Readiness, Severity, Confidence
    contracts.py     reused   Scanner[SubjectT] is already generic
    logging.py       reused   start_run_logging
```

`import-linter` enforces the direction, and gate G6 covers the new package:

```text
cli  ->  output  ->  scanners  ->  core
                         ^
        scanners/wallet -+   imports core only
```

## 6. Data structures and their relationships


Three dataclasses live inside the scanner and reach no consumer. They are folded into the
models that already exist, so the only structure crossing the boundary is `ScanResult`.

```text
INTERNAL, dataclass, never serialized        ON THE WIRE, pydantic, frozen

DecodedAddress                               ScanResult
  address script network                       schema_version "qureddy.scan.v1"
  scheme curve key_in_output                   scan         -> ScanMetadata
  witness_version program_length               target       -> ScanTarget
  encoding error                               dependencies -> RuntimeDependency tuple
                                               assets       -> Asset tuple
ChainFacts                                     evidence     -> Evidence tuple
  reachable source error                       findings     -> Finding tuple
  tx_count funded_txo_count                    summary      -> ScanSummary
  spent_txo_count balance_satoshi
  output_scripts public_keys                 ScanTarget
  signatures                                   original_input host port sni
  transactions_examined                        scheme in {tls ssh ike btc eth}
  transactions_confirmed                       subject          the one new field
  transactions_mempool                         locator == scheme://host:port
  inputs_examined truncated
                                             Asset
Signature                                      id asset_type locator display_name
  txid r s                                     algorithm primitive key_size
                                               bom_ref oid
                                               nist_quantum_security_level 0 to 5

                                             Evidence
                                               observation_type
                                                 OBSERVED INFERRED NOT_TESTABLE
                                               source probe_result confidence notes

                                             Finding
                                               severity readiness
                                               evidence_ids, at least one
                                               rule_id finding_type title description
```

Where each internal field lands:

| Internal | Reaches the wire as |
|---|---|
| `DecodedAddress.script` | `Asset.asset_type`, and the `script.type` finding |
| `DecodedAddress.scheme`, `.curve` | `Asset.algorithm`, `Asset.primitive` |
| `ChainFacts.public_keys` | one `Asset` per key, `Evidence.observation_type = OBSERVED` |
| `ChainFacts.spent_txo_count` | the `key.published` finding at `INFERRED` when no key was read |
| `ChainFacts.transactions_examined`, `.tx_count` | the coverage finding required by C4 |
| `ChainFacts.reachable = False` | every dependent finding at `NOT_TESTABLE`, per C3 |
| `Signature.r` | the nonce-reuse finding at `Readiness.CLASSICALLY_WEAK` |

## 7. Call graph and parameter injection


```text
qureddy scan wallet ADDRESS --type --format --output-dir -v
   |
   +-> cli/wallet.py :: scan_wallet_cmd
         |
         +-> start_run_logging(verbosity, json_logs, quiet, log)      core.logging
         |
         +-> _parse_wallet_target(ADDRESS, --type)
         |      +- address.decode(ADDRESS)            -> DecodedAddress
         |      +- ScanTarget(host=indexer_host, port=443,
         |                    scheme=btc|eth,
         |                    subject=ADDRESS,
         |                    locator=scheme://host:443)
         |
         +-> _prepare_output_dir(--output-dir)                        cli._render
         |
         +-> _execute_scan(scanner, target, timeout, machine_format)  cli._execute
         |      |
         |      +-> WalletScanner.scan(target, timeout_seconds)
         |            |
         |            +- btc -> indexer.fetch(target.subject, timeout)  -> ChainFacts
         |            |     +- bases()      reads QUREDDY_ESPLORA_URL
         |            |     +- GET /address/:a
         |            |     +- GET /address/:a/txs
         |            |          +- _harvest -> public_keys, Signature list
         |            |
         |            +- eth -> ethereum.fetch(target.subject, timeout) -> EthFacts
         |            |     +- rpcs()       reads QUREDDY_ETH_RPC
         |            |     +- eth_getCode, eth_getTransactionCount, eth_getBalance
         |            |
         |            +- scan_defects(signatures)  -> Counter over r
         |            +- assemble Asset, Evidence, Finding, ScanSummary
         |                  +-------------------------> ScanResult
         |
         +-> _render(result, --format, verbose, stream, --output-dir)  cli._render
                +- rich  -> output/console/
                +- json  -> output/json.py
                +- jsonl -> output/jsonl.py
                +- cbom  -> output/cbom.py and 13 emitters
```

Four values enter from outside and every one of them is declared:

| Injection | Enters at | Effect |
|---|---|---|
| `ADDRESS` | `_parse_wallet_target` | becomes `ScanTarget.subject` |
| `--type` | `_parse_wallet_target` | sets `ScanTarget.scheme`, overriding the address form |
| `QUREDDY_ESPLORA_URL` | `indexer.bases()` | replaces the public defaults, with no fallback |
| `QUREDDY_ETH_RPC` | `ethereum.rpcs()` | replaces the public defaults, with no fallback |

Both environment overrides replace the defaults. An operator pointing the
scanner at an internal node does so to keep the account inside a boundary, and a fallback to a
public indexer would disclose the account the setting exists to protect.

## 8. Subject model


A wallet scan contacts an indexer and asks about an account, so the endpoint and the subject are
different identifiers. `ScanTarget` gains one optional field:

```text
host      mempool.space          the endpoint contacted
port      443
scheme    btc                    joins tls, ssh, ike in SUPPORTED_SCHEMES
locator   btc://mempool.space:443   unchanged meaning: the endpoint
subject   bc1q...                the account examined
```

`subject` is excluded from serialization when unset, so `tls`, `ssh` and `ike` output stays byte
for byte what it was. A validator restricts `subject` to the schemes in `SUBJECT_SCHEMES`, so a
value on a `tls` target is rejected at construction instead of travelling as data no renderer
reads. `schema_version` stays `qureddy.scan.v1`, because the change is one optional field.

## 9. Bitcoin lane


Two lanes run, and their separation is what lets C3 hold.

**Offline.** Decode the address. Validate the base58check or bech32/bech32m checksum. Yield the
script class, the network, the signature scheme, and whether the address form implies the public
key sits in the output. Reaches no network, so it answers when the chain lane fails.

**Chain.** Esplora REST, `GET /address/:address` and `GET /address/:address/txs`.
`QUREDDY_ESPLORA_URL` replaces the public defaults so a self-hosted instance keeps the account
inside the operator's boundary.

Esplora's API.md documents the transaction endpoint as returning "up to 50 mempool transactions
plus the first 25 confirmed transactions", mempool first. Per C4 and C6 the whole returned page
is used, confirmed and mempool counts are reported apart, and the absence of `:last_seen_txid`
paging is itself a finding.

A public key counts as published when one of these holds:

| Condition | Observation type |
|---|---|
| A key was read from `vin[].witness[]` or a `scriptsig` push | `OBSERVED` |
| `vout[].scriptpubkey_type` is `p2pk`, `multisig` or `v1_p2tr` | `OBSERVED` |
| `chain_stats.spent_txo_count > 0` while the page yielded no key | `INFERRED` |
| The chain lane failed | `NOT_TESTABLE` |

The third row states what a bounded page supports: a spend publishes the key, and this run read
a sample that omitted it.

One limit belongs in the output. P2PK and bare-multisig outputs carry no address, and explorers
display the equivalent P2PKH string. The address page for such an account therefore omits its own
funding output, so the offline lane reports the P2PKH form while the key sits in the open. Block
0's coinbase is the canonical case. Until the lane walks funding transactions, a `p2pkh` address
whose funding output is `p2pk` yields `INFERRED` at best, and the coverage finding says why.

## 10. Ethereum lane


Three JSON-RPC calls: `eth_getCode`, `eth_getTransactionCount`, `eth_getBalance`.
`QUREDDY_ETH_RPC` replaces the defaults on the same reasoning as the Esplora override.

`eth_getCode` separates three account kinds:

| Result | Kind | Exposure |
|---|---|---|
| `0x` | externally owned | published when the nonce exceeds zero |
| 23 bytes beginning `0xef0100` | EIP-7702 delegated | published: the delegation was set by a signed authorization |
| anything else | contract | no externally owned key exists; owner and upgrade keys sit off this address and are `NOT_TESTABLE` |

The delegation indicator is unforgeable, because EIP-3541 bans deploying code beginning `0xef`.
Reading any non-empty code as a contract reports the most exposed class as keyless, which is the
prototype's defect 5 in its original form.

Every exposure conclusion on this lane is `INFERRED` per C2. The lane reads a nonce and a code
slot. It reads no key.

## 11. Signing defects


A repeated ECDSA nonce yields the private key by algebra from public data, with no quantum
computer. That is `Readiness.CLASSICALLY_WEAK`, distinct from the `QUANTUM_VULNERABLE` exposure
finding, and the two stay separate in the output.

| Detection | Source expression |
|---|---|
| Nonce reuse | `Counter(sig.r)` has a count above one |
| Low-entropy nonce | `r` is four bytes or fewer |

The scanner reports derivability. It computes no private key, and it makes no statement about a
balance, because Breitner and Heninger (FC 2019) found repeated-nonce addresses already swept by
bots that scan for exactly this. A finding that implies funds remain is a defect under C7.

## 12. Hard-coded addresses


Per C6, each address compiled into source or documentation carries a check.

| Address | Establishes | Check |
|---|---|---|
| `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa` | P2PK key on chain, shown under its P2PKH form | HASH160 of the block 0 coinbase public key, base58check with version `0x00` |
| `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0` | v1 witness program carrying an x-only key | BIP-350 valid vector, scriptPubKey `5120` followed by the secp256k1 generator x-coordinate |
| `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4` | published key, recoverable from a spend | BIP-173 §Examples declares the example key `0279be667e...`; the chain yields the same bytes |
| `0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045` | EIP-7702 delegated account | ENS registry `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`, `resolver.addr(namehash("vitalik.eth"))` |
| `0xdAC17F958D2ee523a2206206994597C13D831ec7` | contract account | `eth_call` `name()` returns `Tether USD`, `symbol()` `USDT`, `decimals()` 6 |

An address recalled without a check is removed. An address belonging to an identifiable third
party stays out of the source, because a public ledger entry is still that person's account.

## 13. CLI surface


```text
qureddy scan wallet ADDRESS [--type bitcoin|ethereum] [--format ...] [--output-dir DIR] [-v]
```

The address is positional, matching `scan tls`, `scan ssh` and `scan ike`. The chain follows
from the address form, and `--type` overrides it. Options beyond these five are deferred; the
two endpoint overrides are environment variables, which keeps a credentialed or internal
endpoint out of shell history.

## 14. Alternatives considered


| Alternative | Rejected because |
|---|---|
| Carry the account in `ScanTarget.host` | `host` validates as a hostname or IP literal, and widening it would weaken an invariant three protocol scanners rely on |
| Name the account in `locator` | Every existing consumer reads `locator` as the endpoint contacted; changing that meaning silently breaks them |
| Keep the scanner in the application layer | The collector emits a CBOM from a target identifier, which is the shape of every scanner here. Holding it outside means a second CBOM-producing path |
| Grade exposure on a scale defined here | Published estimates of exposed supply differ by roughly four times, so a scale would encode a contested judgement in a public engine. The application layer may grade; this layer measures |
| Prove request attribution from a packet capture | The payload is TLS. A capture evidences a session in a window, and attributing individual records to individual calls is beyond it |

## 15. Consequences


- `output/` renders every projection with no change, because the contract is `ScanResult`.
- `tls`, `ssh` and `ike` serialization is unchanged, since `subject` is excluded when unset.
- The engine gains a network client class it did not have, and with it a dependency on a
  third-party REST contract. Every failure returns data carrying a reason, so a lane fault is a
  `NOT_TESTABLE` finding instead of an exit.
- Coverage is one indexer page until `:last_seen_txid` paging lands, and C4 requires the output
  to say so on every run.
- An application layer consuming this result decides how to grade it.

## 16. Acceptance gates

Each gate maps to a rule it enforces. A gate with no test is `NOT RUN` and says so.

| Gate | Enforces | Requirement | Test |
|---|---|---|---|
| G1 | correctness | BIP-173 and BIP-350 valid vectors decode; every invalid vector is rejected | `test_wallet_address.py` |
| G2 | C6 | each address in the grounding table has a test recomputing its check | `test_wallet_profiles.py` |
| G3 | C1 | a finding lacking a source expression fails | `test_wallet_claims.py` |
| G4 | C2 | an Ethereum exposure finding asserting `OBSERVED` fails | `test_wallet_claims.py` |
| G5 | C3, C4 | a bounded sample without a coverage finding fails; an unreached lane yields `NOT_TESTABLE` and never `False` | `test_wallet_claims.py` |
| G6 | layering | `scanners/wallet` imports `core` only | `lint-imports` |
| G7 | compatibility | a `tls` scan's JSON is byte identical before and after the `subject` field | `test_wallet_schema.py` |
| G8 | C5 | the wallet modules define no severity, readiness, or level vocabulary of their own | `test_wallet_claims.py` |
| G9 | C7 | every cap, truncation, or filter has a finding recording it | `test_wallet_claims.py` |
| G10 | C8 | no rendered finding value exceeds a value plus its units | `test_wallet_claims.py` |
| G11 | contract | `just gates` passes: lint, format, typecheck, test, bandit, pip-audit, deptry, reuse | `just gates` |
| G12 | live | one real run per chain against mainnet produces a schema-valid `ScanResult` | `tests/live/` |

G3, G4, G5, G8, G9 and G10 are the machine-checkable form of the claims contract. Without them
§4 is advice, and the prototype demonstrated that advice does not hold.


## 17. Anti-pattern check

Run before the branch merges. Each row names the prototype defect it would have caught.

| # | Anti-pattern | Detect | Catches |
|---|---|---|---|
| A1 | A scale or label defined in this repo appearing beside a normative one | grep the wallet modules for tuple or dict literals mapping a name to a colour or rank | defect 1 |
| A2 | An artefact described more widely than its contents | read every string that names a file, and compare it against what that file holds | defects 2, 4 |
| A3 | A constant with no provenance | every address, key, and digest literal traces to §12 or to a spec citation | defect 3 |
| A4 | An inference labelled an observation | grep `OBSERVED` in the wallet modules, and confirm each has bytes read in the same function | defect 5 |
| A5 | A silent bound | grep for a slice or a limit constant, and confirm a coverage finding accompanies it | defect 6 |
| A6 | Prose in a rendered value | every `Finding.title` is a value and its unit; sentences live in `description` | defect 7 |
| A7 | A second mechanism beside an existing one | grep the verb before adding a helper: `parse_`, `decode_`, `fetch_`, `render_` | new |
| A8 | A gate that passes over bad input | revert one fix and confirm its gate turns red | new |
| A9 | A mocked lane standing in for a contract test | at least one test per chain reaches a real endpoint, marked live | new |
| A10 | A green suite over an unread input | for each assertion on a parsed value, confirm a test supplies that value from a fixture, with monkeypatched lanes counted separately | new |

A9 and A10 exist because the prototype's genesis-address defect passed a suite of 142 tests. The
suite asserted the classification logic with a monkeypatched lane, so it never saw that the real
lane supplies a different input.

## 18. Revisit when


- `:last_seen_txid` paging lands, which changes every coverage finding.
- BIP-360 activates on mainnet, adding a post-quantum output type with a category above zero.
- A second account-model chain is added, which tests whether §7 generalizes.

## 19. References


- Esplora HTTP API, `Blockstream/esplora/API.md`, address and transaction endpoints.
- BIP-173 and BIP-350, address encodings and their test vectors.
- EIP-7702, account code delegation; EIP-3541, the `0xef` deployment ban.
- EIP-55, mixed-case address checksum.
- NIST Post-Quantum Cryptography, Call for Proposals section 4.A.5, security strength categories.
- CycloneDX 1.6, `algorithmProperties.nistQuantumSecurityLevel`.
- Breitner and Heninger, Biased Nonce Sense, Financial Cryptography 2019.
- Brengel and Rossow, Identifying Key Leakage of Bitcoin Users, RAID 2018.
