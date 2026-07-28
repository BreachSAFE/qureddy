# CLI reference

This page records the installed `qureddy 0.2.11` command surface. Option names,
defaults, accepted values, exit codes, and environment variables match the
release candidate help output.

## Contents

- [Root command](#root-command)
- [`qureddy scan`](#qureddy-scan)
- [`qureddy scan ssh`](#qureddy-scan-ssh)
- [`qureddy scan tls`](#qureddy-scan-tls)
- [Target syntax](#target-syntax)
- [Output formats](#output-formats)
- [Output streams](#output-streams)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)
- [Related documentation](#related-documentation)

## Root command

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
BreachSAFE QuReddy 0.2.11 -- https://www.breachsafe.ai
```

## `qureddy scan`

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

## `qureddy scan ssh`

```text
qureddy scan ssh [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required SSH target; see [target syntax](#target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--format` | `rich`, `json`, or `cbom` | `rich` | Select output; repeated values use the last occurrence |
| `--timeout` | integer `1..300` | `8` | Socket timeout in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus traceability detail |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
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

## `qureddy scan tls`

```text
qureddy scan tls [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required TLS target; see [target syntax](#target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--sni` | text | target hostname | Override TLS Server Name Indication; required for IP targets that need a virtual host |
| `--openssl` | path | automatic | Select an OpenSSL 3.5 LTS or newer binary |
| `--format` | `rich`, `json`, or `cbom` | `rich` | Select output; repeated values use the last occurrence |
| `--timeout` | integer `1..300` | `30` | Timeout for each probe in seconds |
| `--retry-on` | comma separated categories | none | Retry only the named allowlisted failure categories |
| `--retries` | integer `0..3` | `0` | Additional attempts; requires `--retry-on` |
| `--retry-delay` | float `0.0..10.0` | `1.0` | Delay between attempts in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus command traceability |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `-h`, `--help` | flag | n/a | Print TLS help and exit |

`--timeout` applies to each capability, handshake, legacy protocol, and
certificate probe. Total wall time can exceed the option value.

Examples:

```bash
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls example.com --format json
qureddy scan tls example.com --format cbom
qureddy scan tls example.com --openssl /absolute/path/to/openssl
qureddy scan tls flaky.example --retry-on tls_handshake_failed --retries 3
```

## Target syntax

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

## Output formats

| Value | Contract |
| --- | --- |
| `rich` | Human terminal report with optional color |
| `json` | QuReddy scan document with schema version `qureddy.scan.v1` |
| `cbom` | CycloneDX 1.7 CBOM containing positively observed cryptographic assets |

## Output streams

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

## Exit codes

| Code | TLS | SSH | Meaning |
| --- | --- | --- | --- |
| `0` | yes | yes | Scan completed |
| `2` | yes | yes | Target connection, handshake, or parse failed |
| `3` | yes | no | Local OpenSSL is missing or unusable |
| `4` | yes | yes | Usage or configuration error |
| `70` | yes | process fallback | Internal QuReddy error |

See the [exit code reference](exit-codes.md) for branching examples.

## Environment variables

| Variable | Scope | Meaning |
| --- | --- | --- |
| `QUREDDY_OPENSSL` | TLS | OpenSSL path used when `--openssl` is absent |
| `NO_COLOR` | Rich output and logs | Any value disables ANSI color |

OpenSSL selection order is `--openssl`, then `QUREDDY_OPENSSL`, then
`openssl` on `PATH`.

## Related documentation

- [Install and troubleshoot](../how-to/install.md)
- [Exit codes](exit-codes.md)
- [Failure categories](failure-categories.md)
- [JSON output](json-schema.md)
- [CBOM output](cbom.md)
