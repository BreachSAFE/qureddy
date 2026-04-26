---
name: write-test-fixture
description: Capture an OpenSSL output fixture for QuReddy's parser tests. Use when adding a new fixture under tests/fixtures/openssl/, when reproducing a parser failure case, or when extending test coverage of OpenSSL output shapes. The skill enforces capture protocol, redaction rules, and naming conventions.
---

# Skill: write-test-fixture

Operational protocol for capturing OpenSSL output and saving it as a test fixture under `tests/fixtures/openssl/`. Use when extending parser test coverage.

The point of this skill: fixtures must be **real captured output**, named consistently, redacted of host-specific noise, and referenced from a parser test. Made-up fixture content is forbidden.

## When you invoke this skill

You're in one of these situations:

1. **A new failure mode showed up** — the parser misclassified a real OpenSSL output, and you need the offending output as a fixture so a regression test can be added.
2. **A new positive case is needed** — a target type the parser hasn't seen yet (e.g., a new TLS 1.3 group string format from OpenSSL 3.6).
3. **A new failure category is being added** — every category in the `FailureCategory` enum needs at least one fixture demonstrating the parser detecting it.

## Targets that produce useful fixtures

See `tests/fixtures/openssl/TARGETS.md` for the canonical target list. Standard captures:

| Target | Use case |
|---|---|
| `pq.cloudflareresearch.com:443` | positive: hybrid PQ negotiation (`X25519MLKEM768`) |
| `www.cloudflare.com:443` | positive: hybrid (sometimes; verify) |
| `www.google.com:443` | positive: hybrid (region-dependent; verify) |
| `example.com:443` | negative: classical X25519 baseline |
| `1.1.1.1:443` (with `--sni one.one.one.one`) | SNI-against-IP normalization |
| `tls-v1-2.badssl.com:1012` | failure: `tls_handshake_failed` (TLS 1.2 only) |

Future cert-scanner targets (`expired.badssl.com`, `self-signed.badssl.com`, etc.) are NOT MVP 0.1 fixtures — see TARGETS.md.

## Capture protocol

### Step 1: Run the probe directly

```
openssl s_client \
  -connect <HOST>:<PORT> \
  -servername <SNI> \
  -tls1_3 \
  -groups <X25519MLKEM768 | X25519> \
  -brief </dev/null 2>&1
```

For SNI absent, omit the `-servername` argument entirely.

For trace-mode fixtures (only when `-brief` doesn't reveal the negotiated group):

```
openssl s_client \
  -connect <HOST>:<PORT> \
  -servername <SNI> \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -trace </dev/null 2>&1
```

### Step 2: Redact host-specific content

Before saving:

- **Strip the certificate body** (PEM block between `-----BEGIN CERTIFICATE-----` and `-----END CERTIFICATE-----`). The parser does not consume cert chains in MVP 0.1.
- **Strip the verify chain output** (lines starting with `verify return:` and the cert subject lines).
- **Redact IP addresses** to `<REDACTED_IP>` if they leak DNS-resolved IPs that drift over time.
- **Keep the negotiated group line, the protocol line, the cipher line.** These are what the parser reads.
- **Keep handshake-success/failure markers.** These are what the parser uses to disambiguate `parse_no_group` from a real handshake failure.

If you are capturing a trace fixture, keep the `ServerHello` `key_share` block intact; that's the line the parser reads in trace mode. Strip the `ClientHello` `supported_groups` lines (per CODING_RULES, offered ≠ negotiated).

### Step 3: Save with a canonical name

File names use the pattern `<positive-or-negative>_<output-form>_<group>.txt`:

- `brief_hybrid_x25519mlkem768.txt` — positive, brief mode, X25519MLKEM768 negotiated
- `brief_classical_x25519.txt` — negative, brief mode, classical X25519 negotiated
- `clienthello_only_hybrid.txt` — rejection case: trace shows X25519MLKEM768 in ClientHello but not in ServerHello key_share
- `parse_no_group.txt` — apparent successful handshake with no parseable group line
- `tls13_handshake_failed_tls12_only.txt` — failure case: server forced TLS 1.2

The first line of every fixture file is a single `# ` comment naming the source target and capture date:

```
# Captured from pq.cloudflareresearch.com:443 on 2026-04-26 with OpenSSL 3.5.1
Negotiated TLS1.3 group: X25519MLKEM768
...
```

### Step 4: Add a parser test that consumes the fixture

In `tests/test_tls_parse.py`, add a test that reads the fixture and asserts on the parser output:

```python
def test_parser_detects_hybrid_from_brief() -> None:
    fixture = (FIXTURES / "brief_hybrid_x25519mlkem768.txt").read_text()
    result = parse_negotiated_group(fixture)
    assert result.negotiated_group == "X25519MLKEM768"
    assert result.observation_type == ObservationType.NEGOTIATED
    assert result.failure_category is None
```

The test must reference the fixture by name. Tests using only inline string literals do not satisfy the fixture rule (per `docs/contributors/coding-rules.md` Rule 9.2).

### Step 5: Update the failure-category mapping in TARGETS.md

If this fixture maps to a previously-uncovered failure category, update `tests/fixtures/openssl/TARGETS.md` "Failure categories — fixture mapping" table.

## What you do not do

- **Do not invent fixture content.** Every fixture is captured from a real OpenSSL probe. Synthetic fixtures are acceptable only when fixtures are unavailable (e.g., the failure mode requires a target that doesn't exist) — and in that case, a top-of-file comment must explain why.
- **Do not commit certificate bodies.** Strip them. CODING_RULES Rule 8.5 forbids logging full PEMs; the same applies to test fixtures.
- **Do not commit private keys.** Ever. `.gitignore` should catch them; if a fixture file looks like it might contain key material, redact and re-verify before committing.
- **Do not capture from internal/private targets.** Use the public canonical targets from TARGETS.md.
- **Do not capture under a non-standard OpenSSL.** Use OpenSSL 3.5+ as documented in CODING_RULES. If a fixture needs to reproduce behavior on OpenSSL 3.4-or-older, name the OpenSSL version in the file's first-line comment.

## Output format

When you finish, report:

```
## Fixture Captured

**Target:** <host>:<port> (SNI: <sni or None>)
**OpenSSL version:** <version captured under>
**Fixture file:** tests/fixtures/openssl/<name>.txt
**File size:** N bytes (after redaction)
**Lines stripped:** [list — e.g., "12 lines of cert PEM, 4 verify return lines"]
**Failure category covered:** <category or "positive case">

**Parser test added:**
- File: tests/test_tls_parse.py
- Function: test_<name>
- Assertions: [list]

**TARGETS.md updated:** YES (added to <table>) / NO (existing category)

**Verification:**
- pytest tests/test_tls_parse.py::test_<name>: PASS / FAIL
```
