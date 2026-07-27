# Reference: CLI options

This page enumerates every command, every option, every default, and every value the `qureddy` CLI accepts. Generated from the live help text against `qureddy 0.1.0`.

## Top-level

```
qureddy [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|---|---|
| `--help` | Show help and exit |

### Subcommands

| Command | Description |
|---|---|
| `scan` | Run scans |

## `qureddy scan`

```
qureddy scan COMMAND [OPTIONS] [ARGS]...
```

### Subcommands

| Command | Description |
|---|---|
| `tls` | Scan a TLS endpoint for post-quantum readiness |

## `qureddy scan tls`

```
qureddy scan tls [OPTIONS] TARGET
```

Scan a TLS endpoint for post-quantum readiness. Always runs two probes: one hybrid (`X25519MLKEM768`) and one classical control (`X25519`).

### Argument

| Argument | Type | Description |
|---|---|---|
| `TARGET` | text (required) | Target host[:port], URL, or IP. Examples: `www.google.com`, `www.google.com:443`, `https://www.google.com`, `1.1.1.1`, `[2001:db8::1]:443` |

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `--sni TEXT` | text | (none) | SNI override. Required for IP targets that need to address a specific virtual host. |
| `--openssl TEXT` | text | (auto) | Path to OpenSSL 3.5+ binary. Resolution order: `--openssl` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`. |
| `--format [rich\|json]` | enum | `rich` | Output format. `rich` for terminal panel, `json` for machine-readable. |
| `--timeout INTEGER` | int [1, 300] | `30` | Per-probe timeout in seconds. |
| `--retry-on TEXT` | text | (none) | Comma-separated retryable failure categories. See [Reference: Failure categories](failure-categories.md) for the allowlist. |
| `--retries INTEGER` | int [0, 3] | `0` | Additional retry attempts after the first probe. Requires `--retry-on`. |
| `--retry-delay FLOAT` | float [0.0, 10.0] | `1.0` | Seconds between retry attempts. |
| `-v`, `--verbose` | count | `0` | Verbosity. `-v` = INFO logs, `-vv` = DEBUG logs, `-vvv` = DEBUG + "Commands run" panel on stdout. Logs go to stderr. |
| `--json-logs` | flag | off | Emit logs as one JSON object per line on stderr. Use with log aggregators. |
| `-q`, `--quiet` | flag | off | Suppress non-error logs (raise level to ERROR). Mutually informative with `-v`; the latter wins for log routing. |
| `--help` | flag | — | Show help and exit. |

### Environment variables

| Variable | Effect |
|---|---|
| `QUREDDY_OPENSSL` | Path to OpenSSL binary (used when `--openssl` is not passed). |
| `NO_COLOR` | Any value (including the empty string) disables ANSI color in `rich` output and in stderr logs. Per [no-color.org](https://no-color.org). |

### Exit codes

See [Reference: Exit codes](exit-codes.md). Quick summary:

| Code | Meaning |
|---|---|
| 0 | Scan succeeded |
| 2 | Target scan failed |
| 3 | Local OpenSSL is missing or unsupported |
| 4 | Usage / configuration error |

### Examples

Basic scan:
```bash
qureddy scan tls www.google.com
```

JSON output:
```bash
qureddy scan tls www.google.com --format json
```

IP with custom SNI:
```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

Retry on transient handshake failures up to 3 times, 2s apart:
```bash
qureddy scan tls flaky.example.com --retry-on tls_handshake_failed --retries 3 --retry-delay 2
```

Use a specific OpenSSL build:
```bash
qureddy scan tls www.google.com --openssl /opt/homebrew/opt/openssl@3/bin/openssl
```

Show OpenSSL invocations on stdout (for traceability):
```bash
qureddy scan tls www.google.com -vvv
```

## `qureddy scan ssh`

```
qureddy scan ssh [OPTIONS] TARGET
```

`TARGET` accepts a hostname, `host:port`, bracketed IPv6, `ssh://host[:port]`,
or `sftp://host[:port]`. Endpoint URIs must not include credentials, paths,
query strings, or fragments. Foreign and unknown schemes are rejected with
exit code 4 before DNS or socket access.
