<!-- SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0 -->

# Architecture

QuReddy has two endpoint scanners behind one typed result model. The TLS path
uses local OpenSSL subprocesses. The SSH path uses a direct socket. Rich, JSON,
and CycloneDX renderers consume the same `ScanResult` and do not perform
collection.

## Contents

1. [Component map](#1-component-map)
2. [Dependency direction](#2-dependency-direction)
3. [TLS scan flow](#3-tls-scan-flow)
4. [SSH scan flow](#4-ssh-scan-flow)
5. [Output flow](#5-output-flow)
6. [Evidence boundary](#6-evidence-boundary)
7. [Failure routing](#7-failure-routing)
8. [Related documentation](#8-related-documentation)

## 1. Component map

```mermaid
flowchart TB
    subgraph cli ["src/qureddy/cli/"]
        main["main.py"]
        tls_cli["scan.py"]
        ssh_cli["ssh.py"]
        execute["_execute.py"]
        render["_render.py"]
        errors["_errors.py"]
    end

    subgraph core ["src/qureddy/core/"]
        models["models.py"]
        targets["targets.py"]
        policy["policy.py"]
        retry["retry.py"]
        status["status.py"]
        certificate["certificate.py"]
    end

    subgraph tls ["src/qureddy/scanners/tls/"]
        tls_scanner["scanner.py"]
        openssl_probe["openssl_probe/"]
        legacy["legacy_probe.py"]
        cert_probe["cert_probe.py"]
        tls_parse["parse.py"]
        tls_summary["_summary.py"]
    end

    subgraph ssh ["src/qureddy/scanners/ssh/"]
        ssh_scanner["scanner.py"]
        ssh_probe["probe.py"]
        ssh_classify["classify.py"]
    end

    subgraph output ["src/qureddy/output/"]
        rich["console/"]
        json["json.py"]
        cbom["cbom.py"]
        semantics["cbom_semantics.py"]
    end

    main --> tls_cli
    main --> ssh_cli
    tls_cli --> execute
    ssh_cli --> execute
    execute --> tls_scanner
    execute --> ssh_scanner
    execute --> render

    tls_scanner --> openssl_probe
    tls_scanner --> legacy
    tls_scanner --> cert_probe
    tls_scanner --> tls_parse
    tls_scanner --> tls_summary
    tls_scanner --> policy
    tls_scanner --> retry

    ssh_scanner --> ssh_probe
    ssh_scanner --> ssh_classify

    tls_cli --> targets
    ssh_cli --> targets
    tls_scanner --> models
    ssh_scanner --> models
    cert_probe --> certificate

    render --> rich
    render --> json
    render --> cbom
    cbom --> semantics
    rich --> models
    json --> models
    cbom --> models
```

## 2. Dependency direction

The dependency direction is:

```text
CLI orchestration
    -> target parsing and scanner selection
    -> TLS or SSH collection
    -> typed evidence and findings
    -> Rich, JSON, or CBOM rendering
```

`core` owns shared types, target invariants, retry configuration, status, and
policy. Scanner modules produce `ScanResult`. Output modules read that result
and write to a caller-supplied stream.

Renderers do not open sockets, run OpenSSL, or refetch certificates. CBOM uses
the certificate observation captured during the TLS scan.

## 3. TLS scan flow

```mermaid
sequenceDiagram
    participant C as CLI
    participant T as Target parser
    participant S as TLS scanner
    participant O as OpenSSL probes
    participant P as Policy and summary
    participant R as Renderer

    C->>T: parse TLS target and SNI
    T-->>C: normalized ScanTarget
    C->>S: scan target
    S->>O: resolve and check OpenSSL
    O-->>S: local dependency evidence
    S->>O: hybrid TLS 1.3 probe
    S->>O: classical TLS 1.3 control
    S->>O: legacy protocol sweep
    S->>O: leaf certificate probe
    O-->>S: parsed observations and typed failures
    S->>P: classify evidence and roll up summary
    P-->>S: findings and ScanSummary
    S-->>C: ScanResult
    C->>R: render selected format
```

Every OpenSSL invocation uses an argument vector, an explicit timeout, and
captured streams. Capability inspection happens before target handshakes.
Failures remain typed as local dependency, target, TLS, or parse categories.

The TLS scan can contain partial evidence. Certificate collection, forced key
exchange probes, and legacy protocol probes are separate operations. One
successful operation does not erase another operation's failure.

## 4. SSH scan flow

```mermaid
sequenceDiagram
    participant C as CLI
    participant T as Target parser
    participant S as SSH scanner
    participant P as SSH socket probe
    participant R as Renderer

    C->>T: parse SSH or SFTP endpoint
    T-->>C: normalized ScanTarget
    C->>S: scan target
    S->>P: connect with timeout
    P-->>S: server identification and KEXINIT offer
    S->>S: classify key exchange and host keys
    S-->>C: ScanResult
    C->>R: render selected format
```

The probe does not authenticate, invoke an SSH client, open a channel, or
modify the endpoint. It reads the cleartext offer and closes the socket.

## 5. Output flow

```mermaid
flowchart LR
    result["ScanResult"] --> rich["Rich renderer"]
    result --> json["JSON renderer"]
    result --> cbom["CycloneDX 1.7 renderer"]
    cbom --> semantic["semantic validation"]
    rich --> stdout["stdout"]
    json --> stdout
    semantic --> stdout
    diagnostics["diagnostic logging"] --> stderr["stderr"]
```

Standard output contains the selected result format. Diagnostic logs and
operator hints use standard error.

JSON and CBOM default to quiet logging. Successful machine scans without an
explicit verbosity flag leave standard error empty. Typed failure paths still
emit a structured document. The CLI suppresses its courtesy hint when the
operating system has merged standard error into standard output, preserving
one parseable default machine stream.

Explicit verbosity requests diagnostics. A caller that requests `-v`, `-vv`,
or `-vvv` must keep the streams separate.

## 6. Evidence boundary

Raw network and subprocess text crosses a parser boundary before it becomes
typed evidence. Findings reference that evidence. The summary rolls findings
and failures up without replacing their source records.

The local OpenSSL dependency is collector provenance. It is never remote
implementation identity. CycloneDX represents the endpoint as the metadata
root, local tools under metadata tool provenance, and positively observed
cryptographic assets as components provided by the endpoint.

## 7. Failure routing

| Failure class | Scanner | Exit | Retry |
| --- | --- | --- | --- |
| Local OpenSSL capability | TLS | `3` | never |
| Target connection | TLS and SSH | `2` | TLS allowlist only |
| TLS handshake or middlebox | TLS | `2` | selected allowlist categories |
| Parse failure | TLS and SSH | `2` | TLS `parse_no_group` only |
| Usage or target syntax | TLS and SSH | `4` | never |
| Unhandled internal error | process | `70` | never |

The exact categories and retry state machine are documented in the
[failure category reference](../reference/failure-categories.md).

## 8. Related documentation

- [JSON output](../reference/json-schema.md)
- [CycloneDX CBOM output](../reference/cbom.md)
- [CLI reference](../reference/cli.md)
- [Contributor coding rules](../contributors/coding-rules.md)
