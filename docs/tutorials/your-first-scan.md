# Your first PQ readiness scan

This tutorial walks you through installing QuReddy, running your first TLS scan, and reading the output. It takes about 10 minutes. By the end you will have:

- Installed `qureddy` from source
- Scanned a real post-quantum-enabled server
- Read the verdict, the per-probe findings, and the dependency information

You don't need to know post-quantum cryptography — the [Why hybrid post-quantum?](../explanation/why-hybrid-pq.md) explanation covers the concepts after you've seen the tool work.

## What you need

- Python 3.12 or newer (`python3 --version` to check)
- `git` and `uv` ([install uv](https://docs.astral.sh/uv/getting-started/installation/))
- OpenSSL 3.5 or newer (`openssl version` to check — Homebrew's `openssl@3` works on macOS)
- About 10 minutes
- A network connection (the tutorial scans a real server)

## Step 1 — Install QuReddy from source

```bash
git clone https://github.com/paul007ex/qureddy.git
cd qureddy
uv venv
source .venv/bin/activate
uv pip install -e .
```

Confirm the install:

```bash
qureddy --help
```

You should see the help text with a `scan` subcommand.

## Step 2 — Scan a PQ-enabled server

Cloudflare's frontends support hybrid post-quantum key exchange. Scan one:

```bash
qureddy scan tls www.cloudflare.com
```

The tool runs its probes — hybrid and classical key exchange, a legacy-protocol sweep, and a look at the certificate signature — then prints a verdict panel. You should see something like:

```
QuReddy 0.1.0 by BreachSAFE OSS

┏━ QuReddy scan: tls://www.cloudflare.com:443 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ READY — PQ hybrid X25519MLKEM768 negotiated                                  ┃
┃ Monitor; key exchange is PQ-hybrid but the certificate signature             ┃
┃ (ecdsa-with-SHA256) remains classical.                                       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛

 Scan details
 schema_version    qureddy.scan.v1
 status            completed
 readiness         transitional_hybrid
 protocol          TLSv1.3
 cipher_suite      TLS_AES_256_GCM_SHA384
 hybrid_probe      negotiated X25519MLKEM768
 classical_probe   negotiated X25519
 findings          4
 attempts          6
```

The big banner at the top is the at-a-glance verdict. Green border + "READY" means Cloudflare's TLS endpoint negotiates a hybrid post-quantum key exchange when the client offers it.

## Step 3 — Read the output

Three things to notice in the output:

**The readiness verdict** (`transitional_hybrid`)
The server negotiated `X25519MLKEM768` — a hybrid of X25519 (classical) and ML-KEM-768 (post-quantum). "Transitional" because the certificate signature is still classical (here `ecdsa-with-SHA256`), so a future quantum attacker could still impersonate the server by forging a cert. Hybrid key exchange protects the *session secret* against harvest-now-decrypt-later attacks.

**The two key-exchange probes** (hybrid + classical)
QuReddy always runs both. The hybrid probe asks for `X25519MLKEM768`; the classical probe asks for `X25519`. The classical probe is the *control* — it tells you what the server falls back to. A server that accepts only hybrid (rare today) and refuses classical is the strongest posture; a server that accepts both (most common in 2026) is `transitional_hybrid`.

**The findings count** (4)
One finding per observation that matched a policy rule — here the hybrid negotiation, the classical control, the classical TLS 1.2 fallback, and the classical certificate signature. All findings are visible in the JSON output (Step 5). If the server also offered a deprecated protocol like TLS 1.0 or 1.1, that would appear as an additional finding and the headline would add a `Protocol hygiene: ACTION NEEDED` line.

## Step 4 — Compare with a non-PQ server

Now scan a server that does not yet support hybrid PQ:

```bash
qureddy scan tls example.com
```

The verdict changes:

```
┏━ QuReddy scan: tls://example.com:443 ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ NOT READY — classical only (X25519)                                          ┃
┃ Plan PQ migration. Move TLS termination behind an edge that supports         ┃
┃ X25519MLKEM768, or upgrade to OpenSSL 3.5+ with PQ groups enabled.           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

Yellow border + "NOT READY" means the hybrid probe failed to negotiate. The classical probe succeeded (X25519), so the server itself works fine — it just hasn't enabled PQ yet. The recommendation gives concrete next steps.

## Step 5 — Get machine-readable output

For automation, ask for JSON:

```bash
qureddy scan tls www.google.com --format json
```

The output is a single JSON document with a locked top-level shape. The first 10 lines look like:

```json
{
  "schema_version": "qureddy.scan.v1",
  "scan": {
    "scan_id": "scan-...",
    "started_at": "2026-04-26T...",
    "completed_at": "2026-04-26T...",
    "scanner_name": "tls",
    "scanner_version": "0.1.0",
    "status": "completed",
    "total_attempts": 2
  },
```

The full schema is in [Reference: JSON output schema](../reference/json-schema.md).

## Step 6 — See what OpenSSL was asked to do

For traceability, run with three `-v` flags:

```bash
qureddy scan tls www.google.com -vvv
```

This adds a "Commands run" panel at the bottom showing the exact OpenSSL invocations:

```
Commands run (-vvv)
 $ /opt/homebrew/opt/openssl@3/bin/openssl s_client -connect www.google.com:443 -tls1_3 -groups X25519MLKEM768 -brief -servername www.google.com
     return_code=0 duration_ms=140 attempt=1
 $ /opt/homebrew/opt/openssl@3/bin/openssl s_client -connect www.google.com:443 -tls1_3 -groups X25519 -brief -servername www.google.com
     return_code=0 duration_ms=120 attempt=1
```

Use this when you want to verify what the scanner actually did, or to reproduce a probe by hand.

## What you've learned

- QuReddy installs from source via `uv pip install -e .`
- `qureddy scan tls <target>` runs two probes and prints a verdict
- Output formats: `--format rich` (default, terminal panel) or `--format json` (machine-readable)
- Verbosity flags: `-v` (INFO logs), `-vv` (DEBUG logs), `-vvv` (DEBUG + commands panel on stdout)
- Two readiness verdicts you've seen: `transitional_hybrid` (PQ available) and `quantum_vulnerable` (classical only)

## What to do next

- **Have a goal in mind?** → [How-to guides](../how-to/) for task-oriented recipes (scanning IPs, wiring into CI, etc.)
- **Want to understand the verdicts more deeply?** → [Why hybrid post-quantum?](../explanation/why-hybrid-pq.md) and [Harvest now, decrypt later](../explanation/hndl.md)
- **Looking up a specific flag or exit code?** → [Reference](../reference/)
