# How to scan an SSH / SFTP endpoint

`qureddy scan ssh` checks an SSH endpoint's post-quantum readiness. This is the
scanner for SFTP file-transfer endpoints — the harvest-now-decrypt-later
exposure for data moving over SSH.

## Scan an endpoint

```bash
qureddy scan ssh github.com
```

Default port is 22. For a non-standard SFTP port:

```bash
qureddy scan ssh sftp.vendor.example.com:2222
```

## No OpenSSL needed

Unlike `scan tls`, the SSH scanner needs no OpenSSL binary. SSH transmits its
offered algorithms in the cleartext handshake, so QuReddy reads them with a
plain socket. The LibreSSL-on-macOS problem that affects `scan tls` does not
apply here.

## Machine-readable output

```bash
qureddy scan ssh github.com --format json > github-ssh.json
qureddy scan ssh github.com --format cbom > github-ssh.cbom.json
```

## Reading the verdict

| Readiness | Meaning |
|---|---|
| `transitional_hybrid` | PQ hybrid KEX offered (`mlkem768x25519` / `sntrup761x25519`) — current best practice |
| `quantum_vulnerable` | classical KEX only — harvest-now-decrypt-later exposure |
| `classically_weak` | a deprecated/weak host key (e.g. `ssh-dss`) is offered — fix first |

QuReddy checks two axes: the **key exchange** (is a PQ hybrid group offered?)
and the **host key** (are the signature algorithms classical or weak?).

## Scanning your SFTP fleet

Vendor SFTP endpoints are usually IP-allowlisted — the far end only accepts
connections from your known addresses, and your inbound SFTP server only
accepts the vendor's. Run `qureddy scan ssh` **from inside your allowlisted
network** (a jump host / an allowlisted source IP), not from the public
internet, or the connection will be filtered.

## See also

- [How to generate a CBOM](generate-a-cbom.md)
- `qureddy scan ssh --help`
