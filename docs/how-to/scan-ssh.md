# How to scan an SSH / SFTP endpoint

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

`qureddy scan ssh` checks an SSH endpoint's post-quantum readiness. This is the
scanner for SFTP file-transfer endpoints; the harvest-now-decrypt-later
exposure for data moving over SSH.

## Contents

1. [Scan an endpoint](#1-scan-an-endpoint)
2. [OpenSSL is not required](#2-openssl-is-not-required)
3. [Machine output](#3-machine-output)
4. [Read the verdict](#4-read-the-verdict)
5. [Scan an allowlisted endpoint](#5-scan-an-allowlisted-endpoint)
6. [Related documentation](#6-related-documentation)

## 1. Scan an endpoint

```bash
qureddy scan ssh github.com
```

Default port is 22. For a non-standard SFTP port:

```bash
qureddy scan ssh sftp.vendor.example.com:2222
```

## 2. OpenSSL is not required

Unlike `scan tls`, the SSH scanner needs no OpenSSL binary. SSH transmits its
offered algorithms in the cleartext handshake, so QuReddy reads them with a
plain socket. The LibreSSL-on-macOS problem that affects `scan tls` does not
apply here.

## 3. Machine output

```bash
qureddy scan ssh github.com --format json > github-ssh.json
qureddy scan ssh github.com --format cbom > github-ssh.cbom.json
```

## 4. Read the verdict

| Readiness | Meaning |
|---|---|
| `transitional_hybrid` | PQ hybrid KEX offered (`mlkem768x25519` / `sntrup761x25519`); current best practice |
| `quantum_vulnerable` | classical KEX only; harvest-now-decrypt-later exposure |
| `classically_weak` | a deprecated/weak host key (e.g. `ssh-dss`) is offered; fix first |

QuReddy checks two axes: the **key exchange** (is a PQ hybrid group offered?)
and the **host key** (are the signature algorithms classical or weak?).

## 5. Scan an allowlisted endpoint

Vendor SFTP endpoints are usually IP-allowlisted; the far end only accepts
connections from your known addresses, and your inbound SFTP server only
accepts the vendor's. Run `qureddy scan ssh` **from inside your allowlisted
network** (a jump host / an allowlisted source IP), not from the public
internet, or the connection will be filtered.

## 6. Related documentation

- [How to generate a CBOM](generate-a-cbom.md)
- [CLI reference](../reference/cli.md)
