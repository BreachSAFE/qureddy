# Capturing subprocess-output fixtures for parser tests

Applies whenever a parser's real input is the output of an external tool run as a subprocess
(concretely, today: OpenSSL `s_client` output in QuReddy's TLS scanner) and you need a new
fixture to cover a positive case, a negative case, or a failure mode. The point: fixtures are
**real captured output**, named consistently, redacted of host-specific/sensitive content, and
referenced from an actual parser test. Invented fixture content is forbidden except in the one
narrow case noted below.

## When you need this

1. **A new failure mode showed up** — the parser misclassified real tool output, and you need
   the offending output captured as a fixture so a regression test can pin it.
2. **A new positive case is needed** — an input shape the parser hasn't seen yet (e.g. a new
   negotiated-group string format from a newer tool version).
3. **A new category in a fixed enum is being added** — each value in something like a
   `FailureCategory` enum should have at least one fixture demonstrating the parser detecting
   it.

## Where to find the canonical target/capture list

Repos with this pattern maintain a canonical list of safe capture targets (public endpoints,
not internal/private ones) — e.g. `tests/fixtures/openssl/TARGETS.md` in QuReddy. Read it
before capturing; it tells you which targets are already covered, which categories still need
a fixture, and which targets are explicitly out of scope for a given milestone.

## Capture protocol

### Step 1 — run the tool directly, don't simulate it

For an OpenSSL TLS probe, the direct-capture form looks like:

```
openssl s_client \
  -connect <HOST>:<PORT> \
  -servername <SNI> \
  -tls1_3 \
  -groups <GROUP> \
  -brief </dev/null 2>&1
```

Omit `-servername` entirely when there's no SNI to set. Use `-trace` instead of `-brief` only
when brief mode doesn't reveal the thing the parser needs to read (e.g. the negotiated group
line) — trace fixtures are larger and noisier, so prefer brief mode when it's sufficient.

### Step 2 — redact host-specific and sensitive content before saving

- Strip certificate bodies (the PEM block(s) between `BEGIN CERTIFICATE`/`END CERTIFICATE`)
  unless the parser under test actually consumes cert chains — if it doesn't, the cert body
  is pure noise (and a private-key-adjacent liability) in the fixture.
- Strip verify-chain output (`verify return:` lines and cert subject lines) unless directly
  relevant.
- Redact IP addresses that leak DNS-resolved addresses which drift over time, to
  `<REDACTED_IP>` or similar.
- Keep the lines the parser actually reads: negotiated-group line, protocol line, cipher
  line, handshake success/failure markers. These are what disambiguate a real parse failure
  from a genuine handshake failure — don't strip them by accident while redacting.
- For trace-mode fixtures: keep the `ServerHello`/`key_share` block intact (that's usually the
  line the parser reads in trace mode); strip `ClientHello`/`supported_groups` lines — what
  was *offered* is not what was *negotiated*, and keeping only the negotiated side in the
  fixture keeps that distinction sharp for anyone reading the fixture later.

### Step 3 — save with a canonical, descriptive name

A workable naming pattern: `<positive-or-negative>_<output-form>_<group-or-condition>.txt`,
e.g. `brief_hybrid_x25519mlkem768.txt` (positive, brief mode, hybrid group negotiated),
`brief_classical_x25519.txt` (negative/classical baseline), `parse_no_group.txt` (apparent
success but no parseable group line), `tls13_handshake_failed_tls12_only.txt` (failure case).
Follow whatever naming convention the repo's existing fixtures already use rather than
inventing a new one.

Every fixture's first line is a single `# ` comment naming the source target, capture date,
and tool version:

```
# Captured from pq.cloudflareresearch.com:443 on 2026-04-26 with OpenSSL 3.5.1
Negotiated TLS1.3 group: X25519MLKEM768
...
```

### Step 4 — add a parser test that references the fixture by name

```python
def test_parser_detects_hybrid_from_brief() -> None:
    fixture = (FIXTURES / "brief_hybrid_x25519mlkem768.txt").read_text()
    result = parse_negotiated_group(fixture)
    assert result.negotiated_group == "X25519MLKEM768"
    assert result.observation_type == ObservationType.NEGOTIATED
    assert result.failure_category is None
```

A test that only asserts against inline string literals does not satisfy the fixture
convention — the test must load the actual fixture file.

### Step 5 — update the coverage-mapping doc if one exists

If the repo tracks which fixture covers which failure category or use case (e.g. a table in
`TARGETS.md`), update it when the new fixture closes a gap.

## What you do not do

- **Do not invent fixture content.** Every fixture is captured from a real run of the tool.
  The one exception: a failure mode that requires a target which genuinely doesn't exist to
  capture from — in that case a synthetic fixture is acceptable *only* with a top-of-file
  comment explaining why it's synthetic and what real behavior it's standing in for.
- **Do not commit certificate bodies or private keys.** Strip them; if a fixture looks like it
  might contain key material, redact and re-verify before committing.
- **Do not capture from internal/private targets.** Use only the repo's public canonical
  target list.
- **Do not capture under a non-standard tool version** without naming that version explicitly
  in the fixture's first-line comment, if the fixture is meant to demonstrate version-specific
  behavior.

## Report format

```
## Fixture Captured

**Target:** <host>:<port> (SNI: <sni or None>)
**Tool version:** <version captured under>
**Fixture file:** <path>
**File size:** N bytes (after redaction)
**Lines stripped:** [what was removed and why]
**Failure category covered:** <category or "positive case">

**Parser test added:**
- File: <path>
- Function: <name>
- Assertions: [list]

**Coverage doc updated:** YES (<what>) / NO (<why not needed>)

**Verification:**
- <test command>: PASS / FAIL
```
