# Scanner contract

## Contents

1. [Scanner contract](#scanner-contract)

QuReddy protocol scanners share a typed collection seam:

```text
CLI -> Scanner[ScanTarget]
      ├── TLSScanner -> ScanResult
      └── SSHScanner -> ScanResult
                         |
                         v
                 Rich / JSON / CBOM / JSONL
                         |
                 Qurum / mint-oscal -> OSCAL
```

`Scanner` owns only collection: a typed subject enters and the existing
`ScanResult` leaves.  Renderers and OSCAL conversion stay downstream, where
they already have the format-specific responsibilities.  This prevents a
future PKI scanner from copying output models or adding an OSCAL implementation
inside QuReddy.

`scan_ssh` remains as a compatibility function.  `SSHScanner` is a thin adapter
over that implementation, while `TLSScanner` implements the same seam directly.
The adapter is intentionally small and contains no scanning logic.
