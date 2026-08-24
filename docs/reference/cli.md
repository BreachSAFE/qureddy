# CLI reference

This page records the installed `qureddy 0.2.55` command surface. Option names,
defaults, accepted values, exit codes, and environment variables match the
release candidate help output.

## Contents

1. [Root command](#1-root-command)
2. [`qureddy scan`](#2-qureddy-scan)
3. [`qureddy scan ssh`](#3-qureddy-scan-ssh)
4. [`qureddy scan tls`](#4-qureddy-scan-tls)
5. [Target syntax](#5-target-syntax)
6. [Output formats](#6-output-formats)
7. [Output streams](#7-output-streams)
8. [Exit codes](#8-exit-codes)
9. [Environment variables](#9-environment-variables)
10. [Related documentation](#10-related-documentation)

## 1. Root command

```text
qureddy [OPTIONS] COMMAND [ARGS]...
```

| Option | Meaning |
| --- | --- |
| `-V`, `--version` | Print the version line and exit |
| `-h`, `--help` | Print root help and exit |

| Command | Meaning |
| --- | --- |
| `help` | Print root help and exit |
| `scan` | Select the TLS or SSH endpoint scanner |

The version line is:

```text
BreachSAFE QuReddy 0.2.55 -- https://www.breachsafe.ai
```

## 2. `qureddy scan`

```text
qureddy scan [OPTIONS] COMMAND [ARGS]...
```

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Print scan group help and exit |

| Command | Meaning |
| --- | --- |
| `tls` | Scan a TLS endpoint |
| `ssh` | Scan an SSH or SFTP endpoint |

## 3. `qureddy scan ssh`

```text
qureddy scan ssh [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required SSH target; see [target syntax](#5-target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--format` | `rich`, `json`, or `cbom` | `rich` | Select output; repeated values use the last occurrence |
| `--output`, `-o` | path | standard output | Write the rendered document to a file instead of standard output; standard output stays empty; a path that cannot be opened exits `4` |
| `--output-dir` | directory | none | Run one scan and write correlated `scan.json` and `scan.cdx.json`; cannot be combined with `--output` |
| `--compact` | flag | off | Minify `--format json` or `cbom` to a single line; no effect on `rich` |
| `--min-severity` | `critical`, `high`, `medium`, `low`, or `info` | none | Rich output only: hide findings below this severity; machine formats stay complete |
| `--timeout` | integer `1..300` | `8` | Socket timeout in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus traceability detail |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `--deterministic` | flag | off | Omit per-run identity (serial, timestamps, scan id and timing) so the CBOM or JSON is byte-identical across runs for content addressing |
| `-h`, `--help` | flag | n/a | Print SSH help and exit |

The SSH scanner reads the server identification and KEXINIT offer through a
direct socket. It does not run OpenSSL, authenticate, or open an SSH session.

Examples:

```bash
qureddy scan ssh github.com
qureddy scan ssh sftp.vendor.example:2222
qureddy scan ssh ssh://github.com:22 --format json
qureddy scan ssh sftp://sftp.vendor.example:2222 --format cbom
```

## 4. `qureddy scan tls`

```text
qureddy scan tls [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required TLS target; see [target syntax](#5-target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--sni` | text | target hostname | Override TLS Server Name Indication; required for IP targets that need a virtual host |
| `--openssl` | path | automatic | Select an OpenSSL 3.5.7 LTS binary |
| `--format` | `rich`, `json`, or `cbom` | `rich` | Select output; repeated values use the last occurrence |
| `--output`, `-o` | path | standard output | Write the rendered document to a file instead of standard output; standard output stays empty; a path that cannot be opened exits `4` |
| `--compact` | flag | off | Minify `--format json` or `cbom` to a single line; no effect on `rich` |
| `--min-severity` | `critical`, `high`, `medium`, `low`, or `info` | none | Rich output only: hide findings below this severity; machine formats stay complete |
| `--timeout` | integer `1..300` | `30` | Timeout for each probe in seconds |
| `--retry-on` | comma separated categories | none | Retry only the named allowlisted failure categories |
| `--retries` | integer `0..3` | `0` | Additional attempts; requires `--retry-on` |
| `--retry-delay` | float `0.0..10.0` | `1.0` | Delay between attempts in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus command traceability |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `--log` | path | standard error | Capture the run's structured logs to a file at INFO and above; honors `--json-logs`; standard output stays the `--format` data channel; a bad path exits `4` |
| `--deterministic` | flag | off | Omit per-run identity (serial, timestamps, scan id and timing) so the CBOM or JSON is byte-identical across runs for content addressing |
| `-h`, `--help` | flag | n/a | Print TLS help and exit |

`--timeout` applies to each capability, handshake, legacy protocol, and
certificate probe. Total wall time can exceed the option value.

Examples:

```bash
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls example.com --format json
qureddy scan tls example.com --format json --compact --output scan.json
qureddy scan tls example.com --output-dir evidence/run-001
qureddy scan tls example.com --min-severity medium
qureddy scan tls example.com --format cbom
qureddy scan tls example.com --openssl /absolute/path/to/openssl
qureddy scan tls flaky.example --retry-on tls_handshake_failed --retries 3
```

## 5. Target syntax

### TLS

Accepted forms:

```text
example.com
example.com:8443
tls://example.com
https://example.com:8443
1.1.1.1:443
[2001:db8::1]:443
```

TLS defaults to port `443`. Credentials, paths, query strings, fragments, and
foreign schemes are rejected before a probe runs. Use brackets around IPv6
when a port is present.

### SSH

Accepted forms:

```text
example.com
example.com:2222
ssh://example.com
sftp://example.com:2222
[2001:db8::1]:22
```

SSH defaults to port `22`. Only `ssh://` and `sftp://` schemes are accepted.
Credentials, paths, query strings, fragments, and foreign schemes are rejected
before DNS or socket access.

## 6. Output formats

| Value | Contract |
| --- | --- |
| `rich` | Human terminal report with optional color |
| `json` | QuReddy scan document with schema version `qureddy.scan.v1` |
| `cbom` | CycloneDX 1.7 CBOM containing positively observed cryptographic assets |

`json` and `cbom` are indented by default. `--compact` minifies either to a
single line for streaming to `jq` or a log shipper. `--min-severity` trims the
`rich` findings table only; the `json` and `cbom` documents always carry every
finding, so the machine-document contract holds regardless of the filter.

`--output-dir` is the evidence-bundle mode. It executes the scanner once and
writes both projections from the same in-memory result, preserving the same
`scan.scan_id`, timestamps, target, findings, and evidence. The bundle contains
`scan.json` (`qureddy.scan.v1`) and `scan.cdx.json` (CycloneDX 1.7).

## 7. Output streams

Human output and machine documents go to standard output. Diagnostic logs and
operator hints go to standard error.

For `json` and `cbom`, the default logging posture preserves one parseable
document on standard output. A successful machine scan without explicit
verbosity leaves standard error empty. On failures, standard output still
contains the structured result and standard error may contain an operator
hint.

Under shell-level `2>&1`, the default machine modes suppress the courtesy hint
so the merged stream remains parseable. Explicit `-v`, `-vv`, or `-vvv` logs
are diagnostics and must remain on a separate stream.

## 8. Exit codes

| Code | TLS | SSH | Meaning |
| --- | --- | --- | --- |
| `0` | yes | yes | Scan completed |
| `2` | yes | yes | Target connection, handshake, or parse failed |
| `3` | yes | no | Local OpenSSL is missing or unusable |
| `4` | yes | yes | Usage or configuration error |
| `70` | yes | process fallback | Internal QuReddy error |

See the [exit code reference](exit-codes.md) for branching examples.

## 9. Environment variables

| Variable | Scope | Meaning |
| --- | --- | --- |
| `QUREDDY_OPENSSL` | TLS | OpenSSL path used when `--openssl` is absent |
| `NO_COLOR` | Rich output and logs | Any value disables ANSI color |

OpenSSL selection order is `--openssl`, then `QUREDDY_OPENSSL`, then
`openssl` on `PATH`.

## 10. Related documentation

- [Install and troubleshoot](../how-to/install.md)
- [Exit codes](exit-codes.md)
- [Failure categories](failure-categories.md)
- [JSON output](json-schema.md)
- [CBOM output](cbom.md)
