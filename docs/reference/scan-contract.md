# Scanner contract

[![Architecture contract](https://img.shields.io/badge/QuReddy-architecture%20contract-8250df?style=flat-square)](https://github.com/BreachSAFE/qureddy/blob/main/docs/reference/scan-contract.md)

## Contents

1. [Current collection contract](#1-current-collection-contract)
2. [Dependency boundary](#2-dependency-boundary)
3. [Deferred extension](#3-deferred-extension)
4. [Result lifecycle](#4-result-lifecycle)
5. [Extension checklist](#5-extension-checklist)

## 1. Current collection contract

QuReddy currently routes TLS and SSH through a capability-based collector registry:

```text
CLI -> ScanSource -> CollectorRegistry
                       ├── NativeTLSCollector -> TLSScanner
                       └── NativeSSHCollector -> SSHScanner
                                      |
                                      v
                              CollectionResult
                                      |
                              semantic evaluation
                                      |
                         Rich / JSON / CBOM / JSONL
                                      |
                         Qurum / mint-oscal -> OSCAL
```

```mermaid
flowchart LR
    cli["CLI"] --> source["ScanSource"]
    source --> registry["CollectorRegistry"]
    registry --> tls["NativeTLSCollector"]
    registry --> ssh["NativeSSHCollector"]
    tls --> tls_scan["TLSScanner"]
    ssh --> ssh_scan["SSHScanner"]
    tls_scan --> result["CollectionResult"]
    ssh_scan --> result
    result --> evaluation["Semantic evaluation"]
    evaluation --> rich["Rich"]
    evaluation --> json["JSON / JSONL"]
    evaluation --> cbom["CycloneDX CBOM"]
```

`Collector` owns acquisition: a validated `ScanSource` enters and a
`CollectionResult` leaves. The result carries findings, evidence, provenance,
and a typed failure state. Semantic evaluation and output rendering stay
downstream. New output code must consume canonical core models and neutral
semantic facts rather than importing protocol-private scanner modules.

## 2. Dependency boundary

```text
Protocol adapter -> canonical core models -> posture/output adapters
       |                       |
       +-- owns protocol        +-- owns neutral semantic facts
           vocabulary
```

Protocol adapters own protocol vocabulary and raw collection. Shared policy and
outputs consume canonical models and neutral semantic facts. Output adapters do
not open sockets, invoke OpenSSL, or import protocol-private scanner modules.

## 3. Deferred extension

The registry is already the extension point. Add a collector only when a third
source is approved. TLS/OpenSSL group names remain TLS-owned, SSH algorithm names
remain SSH-owned, and only protocol-neutral facts belong in the shared layer.

External tools belong behind a collector-owned adapter. They do not introduce a
new output path or a second posture model.

`scan_ssh` remains as a compatibility function.  `SSHScanner` is a thin adapter
over that implementation, while `TLSScanner` implements the same seam directly.
The adapter is intentionally small and contains no scanning logic.

## 4. Result lifecycle

```mermaid
sequenceDiagram
    participant CLI
    participant R as Registry
    participant C as Collector
    participant S as Scanner or tool adapter
    participant E as Evaluator
    participant O as Output projection

    CLI->>R: select(ScanSource)
    R-->>CLI: Collector
    CLI->>C: collect(source)
    C->>S: execute acquisition
    S-->>C: observations or typed failure
    C-->>CLI: CollectionResult
    CLI->>E: evaluate(result)
    E-->>CLI: canonical ScanResult
    CLI->>O: render(scan_result)
    O-->>CLI: Rich, JSON, JSONL, or CBOM
```

The lifecycle has one canonical result. `--output-dir` invokes the projections
against that result; it does not repeat the network scan.

## 5. Extension checklist

| Change | Required location | Required proof |
| --- | --- | --- |
| New source kind | `core/contracts.py`, registry registration | deterministic selection and unsupported-source tests |
| New native collector | `collectors/` | typed failures, provenance, real CLI test |
| External tool | collector-owned adapter | version/timeout/exit-status capture and parser fixtures |
| New output format | `output/` and CLI format registry | parity with canonical findings and stream contract |
| New policy fact | protocol policy module | unit tests plus Rich/JSON/CBOM parity |

Do not add a source-specific output path. Do not make renderers import scanner
modules. Do not make a collector mutate another collector's result.
