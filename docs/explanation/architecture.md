<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture

How QuReddy's TLS scanner is wired together. This document is for contributors who want to understand the codebase's shape before changing it.

For *why* the architecture is what it is — design tradeoffs, alternatives considered — see the [ADR index](../contributors/adr/). For *what* the scanner outputs, see [JSON schema](../reference/json-schema.md). This document covers the *what is here* layer.

## Module map

```mermaid
flowchart TB
    subgraph cli ["src/qureddy/cli.py"]
        cli_main["main()"]
        cli_scan_tls["scan_tls()"]
        cli_main --> cli_scan_tls
    end

    subgraph core ["src/qureddy/core/"]
        models["models.py<br/>(Pydantic types)"]
        errors["errors.py<br/>(exception hierarchy)"]
        targets["targets.py<br/>(parse_target)"]
        policy["policy.py<br/>(MVP_POLICY rules)"]
        retry["retry.py<br/>(run_with_retries)"]
        logging_mod["logging.py<br/>(structlog config)"]
        status["status.py<br/>(constants)"]
    end

    subgraph scanners ["src/qureddy/scanners/tls/"]
        scanner["scanner.py<br/>TLSScanner"]
        probe["openssl_probe.py<br/>(subprocess discipline)"]
        parse["parse.py<br/>(parse_brief_output)"]
        classify["_classify.py<br/>(stderr → FailureCategory)"]
        evidence["_evidence.py<br/>(probe → Evidence)"]
        summary["_summary.py<br/>(roll-up to ScanSummary)"]
    end

    subgraph output ["src/qureddy/output/"]
        console["console.py<br/>(Rich renderer)"]
        json_out["json.py<br/>(JSON renderer)"]
        styles["_styles.py<br/>(color tables)"]
    end

    cli_scan_tls --> targets
    cli_scan_tls --> retry
    cli_scan_tls --> logging_mod
    cli_scan_tls --> scanner
    cli_scan_tls --> console
    cli_scan_tls --> json_out
    cli_scan_tls --> errors

    scanner --> probe
    scanner --> evidence
    scanner --> summary
    scanner --> policy
    scanner --> retry

    probe --> classify
    probe --> errors
    evidence --> parse

    console --> styles

    targets --> errors
    retry --> errors

    classify --> models
    parse --> models
    evidence --> models
    summary --> models
    policy --> models
    targets --> models
    retry --> models
    probe --> models
```

**Reading the graph:**

- **`core/`** is the foundation. Everything imports `models.py` (the Pydantic type layer). `errors.py` is the exception hierarchy. No `core/` module imports from `scanners/` or `output/` — strict downward dependency.
- **`scanners/tls/`** is the scan engine. `scanner.py` is the orchestrator; `openssl_probe.py` is the only place in the codebase that calls `subprocess` (single-call discipline per [coding-rules §7](../contributors/coding-rules.md)).
- **`output/`** is the renderer layer. Reads `ScanResult`, writes to a stream. Never reads `subprocess`, never raises domain exceptions.
- **`cli.py`** wires it all together at the top level. It is the only module that mixes scanner, output, and CLI parsing concerns.

## Scan flow

What happens when a user runs `qureddy scan tls www.google.com`:

```mermaid
sequenceDiagram
    participant U as User
    participant CLI as cli.scan_tls
    participant T as core.targets
    participant L as core.logging
    participant S as TLSScanner
    participant P as openssl_probe
    participant Pa as parse
    participant Po as core.policy
    participant Su as _summary
    participant R as output.console / output.json

    U->>CLI: qureddy scan tls www.google.com --format rich
    CLI->>L: configure_logging(verbosity=0)
    Note right of L: structlog binds stderr at config time<br/>(see #15)
    CLI->>T: parse_target("www.google.com")
    T-->>CLI: ScanTarget(host="www.google.com", port=443, sni="www.google.com")
    CLI->>S: TLSScanner(openssl_path=None, retry=RetryConfig())
    CLI->>S: .scan(target, timeout_seconds=30)

    S->>P: resolve_openssl_path(None)
    Note right of P: --openssl > QUREDDY_OPENSSL ><br/>shutil.which("openssl")
    P-->>S: "/path/to/openssl"
    S->>P: probe_capability(path)
    P->>P: openssl version<br/>openssl list -tls1_3 -tls-groups
    P-->>S: OpenSSLDependency(version=3.5.0, supports_x25519mlkem768=True)
    S->>P: raise_if_unusable(dep)
    Note right of S: raises LocalOpenSSL{Missing,TooOld,LacksGroup}<br/>if dep is unusable

    S->>P: run_hybrid_probe(host, port, sni, group=X25519MLKEM768)
    Note right of P: Wrapped in run_with_retries<br/>(retry-on allowlist applies)
    P-->>S: ProbeResult(stdout, stderr, returncode, ...)
    S->>P: run_classical_probe(host, port, sni, group=X25519)
    P-->>S: ProbeResult

    loop Each ProbeResult
        S->>Pa: parse_brief_output(stdout, expected_group)
        Pa-->>S: ParsedNegotiation(negotiated_group, protocol_version, ...)
        S->>S: evidence_from_probe(...) → Evidence
    end

    S->>Po: classify_evidence(asset, evidence_list)
    Note right of Po: Walks MVP_POLICY rules<br/>each rule: AND of conditions
    Po-->>S: list[Finding]

    S->>Su: build_summary(target, findings, evidence)
    Su-->>S: ScanSummary(readiness, finding_count, failure_category)
    S-->>CLI: ScanResult(scan, target, dependencies, assets, evidence, findings, summary)

    CLI->>R: render_rich(result, sys.stdout) or render_json(result, sys.stdout)
    R-->>U: stdout output
    CLI->>U: typer.Exit(code=0|2|3|4)
```

**Key invariants:**

- **The CLI never calls `subprocess` directly.** All process spawning goes through `openssl_probe`. If you find `subprocess.run` outside that file, it's a bug per [coding-rules §7](../contributors/coding-rules.md).
- **Capability check happens before any probe runs.** `_check_capability` raises `LocalOpenSSL*` exceptions if the binary is missing, too old, or lacks the hybrid group — those exit with code 3 and skip the probe phase entirely.
- **Hybrid and classical probes both run unconditionally.** The classical probe is the control — its purpose is to detect "server prefers PQ when offered both" vs "server only knows classical."
- **Parsing is fixture-driven and stream-aware.** The parser anchors on ServerHello-derived lines (`Negotiated TLS1.3 group:` / `Peer Temp Key:`) and ignores ClientHello-derived noise.
- **Findings are produced by policy.** The hardcoded `MVP_POLICY` table in `core/policy.py` defines the four rules; each rule fires once per matching evidence. No YAML loading, no plugin system at MVP 0.1.

## Output stream contract

A scan emits two streams. They are not interchangeable.

```mermaid
flowchart LR
    subgraph proc ["qureddy process"]
        scan["Scan logic"]
        scan -->|"structured fields"| logger["structlog logger"]
        scan -->|"ScanResult"| renderer["Rich or JSON renderer"]
    end

    logger -->|"warnings, info,<br/>debug, errors"| stderr["stderr (fd 2)"]
    renderer -->|"JSON or Rich tables"| stdout["stdout (fd 1)"]

    stdout -->|"qureddy ... | jq"| consumer1["JSON consumer"]
    stdout -->|"qureddy ... | tee log.txt"| consumer2["Display capture"]
    stderr -->|"2> qureddy.log"| consumer3["Log capture"]
    stderr -->|"shows in terminal"| user["Operator"]
```

**The contract:**

- **stdout = scan results only.** Nothing else. JSON output must be parseable by `json.loads(stdout)`. Rich output is the only thing on stdout in `--format rich` mode.
- **stderr = everything else.** Logs, progress, warnings, errors, capability messages, retry signals.
- **`2>&1` merges them** at the OS level, after our process has written. Tools that combine streams will see logs interleaved with output — that's expected.

**Bug class this prevents:** if a logger inadvertently binds `sys.stdout` (or if structlog's writer is captured at the wrong moment, as in [issue #15](https://github.com/paul007ex/qureddy/issues/15)), JSON consumers downstream get `JSONDecodeError`. The contract is "no log line ever lands on stdout, period." Reviewers reject any change that violates this.

## Failure category routing

The scanner produces a `FailureCategory` enum value when something goes wrong. The category determines:

1. **Exit code** the CLI returns
2. **Whether the failure is retryable** under `--retry-on`
3. **What rule the policy fires** to produce the user-visible finding

```mermaid
flowchart TD
    fail([Failure occurred]) --> kind{What kind?}

    kind -->|Local OpenSSL issue| local[LOCAL_OPENSSL_*]
    kind -->|TCP/handshake failed| target[TARGET_CONNECT_FAILED<br/>TLS_HANDSHAKE_FAILED<br/>SNI_REQUIRED_OR_WRONG<br/>MIDDLEBOX_OR_MTU_FAILURE]
    kind -->|Parser couldn't classify| parse[PARSE_NO_GROUP<br/>PARSE_AMBIGUOUS<br/>UNEXPECTED_GROUP]

    local --> rule_local[Rule: tls.hybrid.not_testable<br/>severity: INFO<br/>readiness: UNKNOWN]
    target --> rule_probe[Rule: tls.hybrid.probe_failed<br/>severity: INFO<br/>readiness: UNKNOWN]
    parse --> rule_probe

    rule_local --> exit3[Exit code 3<br/>local dependency]
    rule_probe --> exit2[Exit code 2<br/>target failed]

    target -.->|in default<br/>retry allowlist| retry_yes[Retryable]
    parse -.->|PARSE_NO_GROUP only| retry_yes
    local -.->|never retryable| retry_no[Not retryable]
```

**The retryable allowlist** lives in `core/retry.py` as `RETRYABLE_CATEGORIES`. A user can opt into retries with `--retry-on <category>,<category>` but only categories on the allowlist are accepted; passing a non-allowlisted category fails with exit 4 (usage error).

**Why local failures aren't retryable:** an OpenSSL binary that's missing/too-old/lacking-the-group will not fix itself by waiting and trying again. The retry budget is for transient network conditions, not for client-side configuration problems.

## Where to read next

| If you want to... | Read |
|---|---|
| understand a specific module's role | the module's docstring (every file in `src/qureddy/` has one) |
| follow the JSON output schema | [json-schema.md](../reference/json-schema.md) |
| see all CLI flags | [cli.md](../reference/cli.md) |
| see the exit-code contract | [exit-codes.md](../reference/exit-codes.md) |
| understand a `FailureCategory` value | [failure-categories.md](../reference/failure-categories.md) |
| change the code | [coding-rules.md](../contributors/coding-rules.md) first |
| review someone else's change | [the review apparatus](review-process.md) (TODO) and the `python-oss-crypto-reviewer` skill |
| add a new scanner (MVP 0.2+) | the `mvp-implement` skill |
