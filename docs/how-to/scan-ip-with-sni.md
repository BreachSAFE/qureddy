# Scan an IP target with a custom SNI

This guide covers scanning a TLS endpoint by IP address when you need to address a specific virtual host. Use it when you're scanning behind a load balancer, testing a non-default vhost, or auditing infrastructure where DNS doesn't resolve to the IP you want to hit.

## Contents

- [Prerequisites](#prerequisites)
- [Run the scan](#run-the-scan)
- [Verify the normalized target](#verify-the-normalized-target)
- [Inspect the OpenSSL arguments](#inspect-the-openssl-arguments)
- [Common variations](#common-variations)
- [Why SNI matters](#why-sni-matters)
- [Related documentation](#related-documentation)

## Prerequisites

- A working `qureddy` install ([tutorial](../tutorials/your-first-scan.md))
- The IP address you want to scan
- The hostname the server expects in the TLS SNI extension

## Run the scan

```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
```

QuReddy connects to `1.1.1.1` on port 443 and sends `one.one.one.one` as the SNI. Without `--sni`, an IP target sends no SNI at all and most servers refuse the handshake.

## Verify the normalized target

In the output, the `target` row shows what QuReddy actually scanned:

```
 target            tls://1.1.1.1:443
 sni               one.one.one.one
```

If the SNI line is missing or wrong, the flag was malformed — re-check the command.

## Inspect the OpenSSL arguments

If you need to verify the SNI made it onto the wire:

```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one -vvv
```

The "Commands run" panel shows the `-servername one.one.one.one` argument passed to `openssl s_client`.

## Common variations

**IPv4 with non-default port:**
```bash
qureddy scan tls 1.1.1.1:8443 --sni one.one.one.one
```

**IPv6 (use bracket notation):**
```bash
qureddy scan tls "[2606:4700:4700::1111]:443" --sni one.one.one.one
```

**JSON output** (when scripting):
```bash
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one --format json
```

## Why SNI matters

When you scan a hostname like `www.google.com`, the hostname doubles as the SNI. When you scan an IP, there's no hostname to use, so QuReddy sends no SNI by default.

Most modern web servers refuse to complete the handshake without a valid SNI — they don't know which virtual host's certificate to present. This is why an IP scan without `--sni` typically fails with `tls_handshake_failed` or `sni_required_or_wrong`. Specifying `--sni` tells QuReddy what to put in the TLS ClientHello so the server can route the request to the right vhost.

## Related documentation

- [Reference: CLI options](../reference/cli.md) — full `--sni` syntax
- [Reference: Failure categories](../reference/failure-categories.md) — what `sni_required_or_wrong` means and when it fires
