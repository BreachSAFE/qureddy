# TLS service profiles

[![Diátaxis reference](https://img.shields.io/badge/Di%C3%A1taxis-reference-1f6feb?style=flat-square)](https://diataxis.fr/reference/)

This page defines the planned service-profile contract for `qureddy scan tls`.
The current released scanner supports direct TLS. The profile names and behavior
below are design and calibration targets tracked by [#577](https://github.com/BreachSAFE/qureddy/issues/577),
[#578](https://github.com/BreachSAFE/qureddy/issues/578), and [#590](https://github.com/BreachSAFE/qureddy/issues/590).
They are not claims that every profile is available in the current release.

## Contents

1. [Scope](#1-scope)
2. [Profile model](#2-profile-model)
3. [Profile catalog](#3-profile-catalog)
4. [Evidence contract](#4-evidence-contract)
5. [Source requirements](#5-source-requirements)
6. [Execution boundary](#6-execution-boundary)
7. [Failure and coverage states](#7-failure-and-coverage-states)
8. [Application integration](#8-application-integration)
9. [Verification requirements](#9-verification-requirements)
10. [Related references](#10-related-references)

## 1. Scope

TLS service profiles select the application-layer transition that occurs before
the TLS handshake. A profile does not identify a host, infer a service from a
port, or establish application authentication.

The endpoint remains a `ScanTarget`:

```text
host, port, SNI, scheme
```

The scan request carries the acquisition profile separately:

```text
TLSScanRequest
  ├── ScanTarget
  └── TLSProfileRef
```

Direct TLS begins with TLS records. STARTTLS profiles begin with a
service-specific cleartext exchange and then transition to TLS. Each service
defines its own greeting, upgrade command, identity field, refusal behavior,
and certificate context.

## 2. Profile model

The profile catalog is immutable and versioned. It contains declarative
connection rules; it does not contain socket state machines or protocol codecs.

```python
class TLSProfileRef(BaseModel):
    id: str
    version: str


class TLSConnectionProfile(BaseModel):
    id: str
    transport: Literal["tcp"]
    upgrade: Literal["direct", "starttls"]
    openssl_starttls_mode: str | None
    accepts_application_identity: bool
    application_identity_label: str | None
    allows_sni: bool
    certificate_policy: str
```

`ScanTarget` must remain backward compatible. Omitting a profile selects the
existing direct-TLS behavior.

The profile identifier is recorded in scan metadata and evidence so QuReddy
App can distinguish, for example, LDAP StartTLS on port 389 from direct LDAPS
on port 636.

## 3. Profile catalog

The following table records the proposed vocabulary and the required wire mode.
Port numbers are examples only. They never select a profile automatically.

| Profile | TLS entry path | Application identity | Evidence boundary |
| --- | --- | --- | --- |
| `direct` | TLS from the first application byte | none | Direct TLS negotiation and certificates |
| `postgresql` | PostgreSQL SSLRequest, then TLS | none | Upgrade outcome and TLS evidence |
| `postgresql-direct` | Direct TLS | none | Direct TLS evidence; no PostgreSQL inference from the port |
| `mysql` | MySQL capability exchange, then CLIENT_SSL | none | Upgrade outcome and TLS evidence |
| `mariadb` | OpenSSL `mysql` mode | none | Requires independent MariaDB live validation |
| `openldap` | LDAP StartTLS ExtendedRequest | none | Upgrade outcome and TLS evidence |
| `ldaps` | Direct TLS | none | Direct TLS evidence on an LDAPS deployment |
| `smtp` | EHLO, then STARTTLS | EHLO identity | SMTP upgrade and TLS evidence |
| `imap` | IMAP greeting, then STARTTLS | none | IMAP upgrade and TLS evidence |
| `pop3` | POP3 greeting, then STLS | none | POP3 upgrade and TLS evidence |
| `ftp` | FTP `AUTH TLS` | none | Explicit control-channel upgrade |
| `ftps` | Direct TLS | none | Implicit TLS; not an FTP STARTTLS exchange |
| `xmpp` | Client-to-server XML stream, then STARTTLS | XMPP stream domain | Client stream and TLS evidence |
| `xmpp-server` | Server-to-server XML stream, then STARTTLS | XMPP federation domain | Federation stream and TLS evidence |
| `lmtp` | LHLO, then STARTTLS | LHLO identity | LMTP upgrade and TLS evidence |
| `nntp` | NNTP greeting, then STARTTLS | none | NNTP upgrade and TLS evidence |
| `sieve` | ManageSieve greeting, then STARTTLS | none | Sieve upgrade and TLS evidence |
| `irc` | IRC registration, then STARTTLS | implementation-specific | Requires independent calibration |
| `telnet` | Artifact-dependent mode | implementation-specific | Unavailable until source and live behavior agree |

`postgresql` means the explicit PostgreSQL upgrade profile. A deployment that
starts TLS immediately uses `postgresql-direct` or the existing `direct` profile.
`ftp` and `ftps` are intentionally separate because explicit `AUTH TLS` and
implicit TLS have different pre-handshake behavior.

## 4. Evidence contract

Every profile produces the same canonical `ScanResult` shape. Profile-specific
facts are observations attached to the shared result.

The result records, when available:

- target and selected profile;
- local OpenSSL path, version, and capability output;
- application upgrade requested and observed;
- SNI and application identity values, kept as separate fields;
- selected TLS version, group, cipher suite, signature, and certificates;
- attempt number, timeout, duration, and failure category;
- evidence references and output provenance.

An OpenSSL nonzero exit is not, by itself, proof that a server refused STARTTLS.
The evaluator must distinguish an explicit refusal, an unavailable local mode,
an ambiguous diagnostic, a timeout, and no response.

CBOM output records observed cryptographic assets. It does not claim that the
application authenticated successfully or that a database, mail system, or
directory is secure.

## 5. Source requirements

Each supported profile requires an immutable source record containing the source
URI, document revision, retrieval date, SHA-256, license status, and exact
section anchors.

| Profile family | Primary source |
| --- | --- |
| SMTP | RFC 3207 |
| IMAP and POP3 | RFC 2595 plus the base protocol specification |
| FTP | RFC 4217 |
| XMPP | RFC 6120 and applicable federation requirements |
| LDAP | RFC 4511, section 4.14 |
| LMTP | RFC 2033 plus its TLS semantics |
| NNTP | RFC 4642 |
| ManageSieve | RFC 5804 |
| Implicit mail TLS | RFC 8314 where cited |
| PostgreSQL | Versioned PostgreSQL protocol and TLS documentation |
| MySQL | Versioned Oracle MySQL protocol and TLS documentation |
| MariaDB | Versioned MariaDB documentation, independently |
| IRC | Specification or maintained implementation for the tested server |
| Telnet | Applicable TLS option specification plus OpenSSL source behavior |

OpenSSL `s_client(1)` is the source for the pinned executable's `-starttls`,
`-name`, `-servername`, `-showcerts`, and `-quic` behavior. Artifact help proves
local capability. It does not prove endpoint interoperability.

The source-corpus custody requirements and claim dictionary are tracked in
[#577](https://github.com/BreachSAFE/qureddy/issues/577). Until the corpus is
committed or represented by immutable metadata, line references to a local
standards checkout remain unverified.

## 6. Execution boundary

OpenSSL owns the application upgrade for modes it implements. QuReddy owns
target validation, profile validation, bounded process execution, evidence
normalization, evaluation, and output projection.

```text
TLS profile
  -> shared OpenSSL argument builder
  -> TLS 1.3 probes
  -> legacy protocol probes
  -> certificate probe
  -> shared evaluator
  -> one ScanResult
  -> Rich | JSON | JSONL | CBOM
```

The argument builder must be the only production location that adds
`-starttls`, `-name`, or `-servername`. Profile branches must not construct
their own subprocess commands.

TDS/MSSQL is outside this boundary because OpenSSL has no TDS STARTTLS mode.
It requires a separate, explicitly scoped `PRELOGIN` adapter tracked by
[#581](https://github.com/BreachSAFE/qureddy/issues/581).

## 7. Failure and coverage states

Profile support is not inferred from a successful TCP connection or a port.

| State | Meaning |
| --- | --- |
| `accepted` | A real configured service reached the TLS handshake through the requested profile |
| `upgrade_refused` | The service explicitly refused the requested transition |
| `unavailable` | The local OpenSSL artifact lacks the requested mode |
| `unknown` | Timeout, filtering, incomplete diagnostics, or ambiguous behavior |
| `not_tested` | The profile is cataloged but no attempt was scheduled |
| `conflicting` | Artifact, source, and live behavior disagree |

The scanner must not convert `unknown`, `unavailable`, or `not_tested` into a
favorable security result. A profile that succeeds in direct TLS says nothing
about its STARTTLS counterpart.

## 8. Application integration

QuReddy App can expose profiles as tabs under its TLS section without creating
separate scanner implementations:

```text
TLS
├── Direct TLS
├── PostgreSQL
├── MySQL
├── MariaDB
├── OpenLDAP StartTLS
├── LDAPS
├── SMTP
├── IMAP
├── POP3
├── FTP AUTH TLS
└── FTPS
```

Each tab supplies a profile identifier and renders the same result contract.
The application must not infer a profile from the port or silently retry a
different acquisition mode.

## 9. Verification requirements

Before a profile is advertised as supported, its issue must provide:

1. the pinned OpenSSL path, version, digest, and mode capability;
2. a real configured server implementation and version;
3. a successful live upgrade through the installed wheel and container;
4. an explicit refusal or unavailable case;
5. separate SNI and application-identity checks where applicable;
6. timeout and malformed-diagnostic handling;
7. identical evidence identifiers across Rich, JSON, JSONL, and CBOM;
8. documentation and link checks.

Current calibration is uneven. PostgreSQL, MySQL, and SMTP have recorded live
OpenSSL observations. IMAP and POP3 remain unverified. MariaDB requires its own
server proof. IRC and Telnet require independent calibration. No profile in
this page should be treated as shipped until its acceptance issue closes.

## 10. Related references

- [CLI reference](cli.md)
- [JSON output reference](json-schema.md)
- [CBOM reference](cbom.md)
- [Scanner contract](scan-contract.md)
- [STARTTLS source and provenance issue #577](https://github.com/BreachSAFE/qureddy/issues/577)
- [Shared OpenSSL execution issue #578](https://github.com/BreachSAFE/qureddy/issues/578)
- [Service reachability milestone #590](https://github.com/BreachSAFE/qureddy/issues/590)
- [TDS/MSSQL issue #581](https://github.com/BreachSAFE/qureddy/issues/581)

