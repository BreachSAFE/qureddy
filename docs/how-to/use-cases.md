# Use cases and live examples

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

Use this guide to turn a specific cryptography or quantum-readiness question
into a QuReddy scan. The examples use public endpoints and read-only probes;
run them only when you are authorized to test the target.

## Contents

1. [Establish a public-edge baseline](#1-establish-a-public-edge-baseline)
2. [Find weak TLS exposure](#2-find-weak-tls-exposure)
3. [Check a STARTTLS upgrade](#3-check-a-starttls-upgrade)
4. [Review SSH and VPN negotiation](#4-review-ssh-and-vpn-negotiation)
5. [Review public wallet exposure](#5-review-public-wallet-exposure)
6. [Inventory directories and images](#6-inventory-directories-and-images)
7. [Save the evidence bundle](#7-save-the-evidence-bundle)
8. [Read the result](#8-read-the-result)

## 1. Establish a public-edge baseline

Start with a service you operate, then compare the result over time after
changing TLS configuration. These public endpoints are useful smoke targets:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls www.google.com --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls www.cloudflare.com --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls pq.cloudflareresearch.com --format rich
```

The Rich report shows the negotiated protocol, key exchange, certificate
signatures, readiness assessment, and probe limits. Use JSON when a pipeline
needs the complete canonical scan document:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls www.google.com --format json > google-tls.json
```

## 2. Find weak TLS exposure

BadSSL publishes deliberately weak services for controlled verification of
TLS scanners. These targets demonstrate protocol and cipher findings without
requiring credentials:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls tls-v1-2.badssl.com:1012 --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls tls-v1-1.badssl.com:1011 --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls tls-v1-0.badssl.com:1010 --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls rc4.badssl.com:443 --format rich
```

The result identifies the protocol and suite accepted by the endpoint and
attaches severity and CWE data to findings when the rule defines them. A weak
posture is still a completed scan; inspect the report and exit code together.

## 3. Check a STARTTLS upgrade

STARTTLS can leave a service looking healthy when only the direct TLS listener
has been checked. Probe the cleartext service port so QuReddy can record the
upgrade and the TLS session that follows it:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls smtp.gmail.com:587 --starttls smtp --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls imap.gmail.com:143 --starttls imap --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls pop.gmail.com:110 --starttls pop3 --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls jabber.org:5222 --starttls xmpp --format rich
```

Supported modes are SMTP, POP3, IMAP, FTP, XMPP, XMPP server, Telnet, IRC,
MySQL, PostgreSQL, LMTP, NNTP, Sieve, and LDAP. Use the cleartext service port
for the selected mode; see the [STARTTLS profile reference](../reference/starttls-profiles.md)
for the complete profile catalog and port guidance.

## 4. Review SSH and VPN negotiation

For SSH, review the server’s algorithm offer before changing an SSH policy or
retiring a classical fallback:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan ssh github.com --format rich
```

For IKE, inspect the responder’s transforms and explicit responses. The
`--nat-t` form sends the probe through the NAT-T listener:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan ike netherlands.hide.me --nat-t --format rich
```

SSH evidence comes from the server identification and KEXINIT offer. IKE
evidence comes from responder discovery and the stock `ike-scan` tool report;
the output keeps that evidence boundary visible.

## 5. Review public wallet exposure

Wallet scans help establish whether a public account has exposed signing key
material and how its account history is classified by the selected indexer:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan wallet 1A1zP1eP5Gefi2DMPTfTL5SLmv7DivfNa --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan wallet Ler4HNAEfwYhBmGXcFP2Po1NpRUEiK8km2 \
    --type litecoin --format rich
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan wallet 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045 --format rich
```

The report names the address type, public-key status, signatures examined,
nonce-reuse observations, balance returned by the indexer, and the source of
each value. Account state changes over time, so retain the JSON or CBOM when a
review needs a dated record.

## 6. Inventory directories and images

Use a directory scan before release to inventory artifact bytes such as
certificates, keystores, configuration, and binaries:

```console
$ docker run --rm -v "$PWD:/scan:ro" \
    docker.io/breachsafe/qureddy:latest scan dir /scan > artifacts.cdx.json
```

Use an image scan before deployment. The container needs read-only access to
the Docker socket so Theia can inspect the image layers:

```console
$ docker run --rm --group-add 0 \
    -v /var/run/docker.sock:/var/run/docker.sock:ro \
    docker.io/breachsafe/qureddy:latest \
    scan image nginx:latest > nginx.cdx.json
```

These lanes forward the CycloneDX document produced by CBOMkit Theia. The
output preserves Theia’s declared specification version and component model.

## 7. Save the evidence bundle

When a result will support a ticket, review, or repeat scan, write all
projections and diagnostics into one directory:

```console
$ docker run --rm docker.io/breachsafe/qureddy:latest \
    scan tls badssl.com:443 --output-dir evidence/badssl
```

For a local installation, increase diagnostic detail with `-vvv` and separate
the machine-readable result from the diagnostic log:

```console
$ qureddy scan tls badssl.com:443 --format json \
    --output-dir evidence/badssl -vvv --log evidence/badssl/run.log
```

The endpoint and wallet bundle contains `scan.json`, `scan.jsonl`,
`scan.cdx.json`, and `scan.rich.txt`, plus the run log when requested.

## 8. Read the result

Use these fields to triage a scan:

| Question | Result to inspect |
| --- | --- |
| Did QuReddy finish its work? | `scan.status` and the process exit code |
| What did the target accept or offer? | Evidence records and their runtime/source |
| Is quantum protection observed? | `summary.readiness`, HNDL interpretation, and key-exchange evidence |
| What needs remediation first? | Finding severity, rule, protocol, crypto value, and CWE when present |
| Can another system consume it? | `scan.json`, `scan.jsonl`, or `scan.cdx.json` |

An `UNKNOWN` or incomplete result is useful operational information: it tells
you which probe or dependency needs attention before treating the target as
assessed. See the [exit-code reference](../reference/exit-codes.md) and
[CBOM reference](../reference/cbom.md) for the complete contracts.

