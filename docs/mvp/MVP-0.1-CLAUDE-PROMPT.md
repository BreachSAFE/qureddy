# MVP 0.1 — Claude Implementation Prompt

Milestone-scoped implementation prompt for MVP 0.1 (TLS scanner only). Layer this on top of the general session prompt at `docs/CLAUDE_DEVELOPER_PROMPT.md` — that prompt covers how to behave on this repo in general; this one covers what to build for MVP 0.1 specifically.

When MVP 0.2 starts, a `docs/mvp/MVP-0.2-CLAUDE-PROMPT.md` will live alongside this one.

---

You are implementing BreachSAFE QuReddy MVP 0.1.

Before writing code, read these files from disk:

- `CLAUDE.md`
- `docs/CODING_RULES.md`
- `AGENTS.md`
- `docs/OSS_STANDARDS.md`
- `docs/AGENT_ANTIPATTERNS.md`
- `docs/prd/MVP-0.1-PRD.md`
- `docs/mvp/MVP-0.1-PLAN.md`
- `docs/mvp/openssl-probing.md`
- `docs/mvp/acceptance-tests.md`
- `docs/architecture/0001-license-and-dependencies.md`
- `docs/architecture/0002-openssl-tls-probing.md`
- `docs/architecture/0003-evidence-and-findings.md`

Follow the coding standards in `docs/CODING_RULES.md` exactly. Before final response, audit the diff against `docs/AGENT_ANTIPATTERNS.md` and fix violations.

## Canonical naming

- Product: BreachSAFE QuReddy
- CLI command: `qureddy`
- Python package/import: `qureddy`
- Do not use `qready`.
- Do not use `qreddy`.

## MVP 0.1 scope

Implement one command:

```
qureddy scan tls TARGET
  [--sni NAME]
  [--openssl PATH]
  [--format rich|json]
  [--timeout SECONDS]
  [--retry-on CATEGORY[,CATEGORY...]]
  [--retries N]
  [--retry-delay SECONDS]
```

### Includes

- Parse and normalize a single TLS target.
- Check local OpenSSL capability.
- Run TLS 1.3 hybrid probe using OpenSSL 3.5+ subprocess.
- Detect whether `X25519MLKEM768` was actually negotiated.
- Run classical X25519 control probe.
- Emit native QuReddy JSON.
- Emit Rich terminal table.
- Add fixture-based parser tests.
- Add target normalization tests.
- Add OpenSSL boundary check script if not already present.

### Excludes

- sslyze
- nassl
- GPL/AGPL runtime dependencies
- Python `ssl`-based hybrid probing
- pyOpenSSL
- oqs-provider integration
- certificate chain parsing
- `cryptography` dependency unless absolutely needed
- CBOM
- HTML/PDF/CSV/Markdown reports
- YAML policies
- HNDL scoring
- SQLite persistence
- SSH/local/code/config scanners
- batch scanning
- Docker

## Dependency policy

- No sslyze.
- No nassl.
- No GPL or AGPL runtime dependencies.
- OpenSSL is an external system binary in MVP, not bundled.
- Runtime dependencies should be minimal: Typer, Rich, Pydantic, and `packaging` only if needed for version parsing.
- Any new dependency must satisfy `docs/CODING_RULES.md` dependency rules.

## OpenSSL boundary

All OpenSSL subprocess calls must live in:

```
src/qureddy/scanners/tls/openssl_probe.py
```

No other module may call `subprocess.run` with `openssl`.

## Retry semantics

The CLI accepts retry flags that apply to the scanner's interactions with the target:

- `--retry-on CATEGORY[,CATEGORY...]` — comma-separated failure categories. Any failure category from the enum below is accepted. No allowlist; the user decides what's worth retrying. Default: empty (no retries).
- `--retries N` — integer, max 10, default 0.
- `--retry-delay SECONDS` — float, default 1.0, max 60.

Behavior:

1. The first attempt always runs. Retries only fire if the first attempt produced a failure category in `--retry-on`.
2. Between attempts, sleep `--retry-delay` seconds.
3. If a retry attempt produces a *different* failure category than the one that triggered the retry, stop and report the new category. Do not keep retrying just because some failure happened.
4. If a retry attempt produces a non-failure outcome, the scan succeeds and reports that outcome. Earlier failures are recorded as evidence on the success result.
5. Retries do not apply to local capability failures (`local_openssl_missing`, `local_openssl_too_old`, `local_openssl_lacks_group`) in practice — these will return identical results on every attempt — but the CLI does not block the user from passing them. Document this in the help text: "Retrying deterministic failures (parse errors, capability checks) is allowed but typically pointless."
6. Validation:
   - `--retry-on` values must match a category in the failure-category enum exactly. Unknown categories are a usage error (exit code 4).
   - `--retries` and `--retry-delay` outside their bounds are a usage error (exit code 4).
   - `--retries N` without `--retry-on` is a usage error: "no retry categories specified."
7. Each retry attempt produces its own evidence record. The final result reports total attempt count.

The default behavior (no flags) is single-attempt, no retries.

## Subprocess rules

- Use `subprocess.run`.
- Pass args as a list.
- Never use `shell=True`.
- Set `timeout` explicitly.
- Capture stdout and stderr.
- Use `check=False` and inspect returncode manually.
- Support `--openssl PATH` and `QUREDDY_OPENSSL` environment override.

## OpenSSL capability check

Run:

```
openssl version
openssl list -tls1_3 -tls-groups
```

Required:

- OpenSSL version >= 3.5.0
- `X25519MLKEM768` present in TLS 1.3 group list

If OpenSSL is missing, too old, or lacks `X25519MLKEM768`, emit `UNKNOWN` readiness due to local dependency incapability. Do not report that the server is not PQ-ready.

## Probe commands

Primary hybrid probe:

```
openssl s_client \
  -connect HOST:PORT \
  -servername SNI \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -brief
```

Classical control probe:

```
openssl s_client \
  -connect HOST:PORT \
  -servername SNI \
  -tls1_3 \
  -groups X25519 \
  -brief
```

Trace fallback:

```
openssl s_client \
  -connect HOST:PORT \
  -servername SNI \
  -tls1_3 \
  -groups X25519MLKEM768 \
  -trace
```

Only use trace fallback when the summary output indicates a completed handshake but no negotiated group can be parsed.

## Positive hybrid evidence

Accept only these summary forms:

```
Negotiated TLS1.3 group: X25519MLKEM768
```

or:

```
Server Temp Key: X25519MLKEM768, ...
```

If parsing trace, accept `X25519MLKEM768` only when it appears as `NamedGroup` under `ServerHello` `key_share`. Do not count `ClientHello` `supported_groups` or `ClientHello` `key_share`. Offered groups are not proof of negotiation.

## Evidence contract

Every evidence object must include an `observation_type`:

- `negotiated`
- `offered`
- `observed`
- `inferred`
- `not_testable`

Rule:

- `X25519MLKEM768` readiness may be `transitional_hybrid` only with `negotiated` evidence.
- `offered` evidence is never enough.

## Failure categories to model

- `local_openssl_missing`
- `local_openssl_too_old`
- `local_openssl_lacks_group`
- `target_connect_failed`
- `tls_handshake_failed`
- `sni_required_or_wrong`
- `middlebox_or_mtu_failure`
- `parse_no_group`
- `parse_ambiguous`
- `unexpected_group`

## Target normalization

Accept:

- `example.com`
- `example.com:443`
- `https://example.com`
- `https://example.com:8443`
- `1.2.3.4:443`

Normalize to:

- `original_input`
- `host`
- `port`
- `sni`
- `scheme = tls`
- `locator = tls://host:port`

Default port: `443`.

For DNS hosts, default SNI is `host`.

For IP addresses, default SNI is `null` unless user passes `--sni`.

Support:

```
qureddy scan tls 1.2.3.4:443 --sni example.com
```

## Native JSON output shape

```json
{
  "schema_version": "qureddy.scan.v1",
  "scan": {},
  "target": {},
  "dependencies": [],
  "assets": [],
  "evidence": [],
  "findings": [],
  "summary": {}
}
```

Every scan must record OpenSSL dependency metadata:

- `name`
- `path`
- `version`
- `supports_tls13_groups`
- `supports_x25519mlkem768`

## Raw evidence policy

Normal JSON output should include parsed evidence and hashes, not full large raw traces.

Include:

- command args, redacted if needed
- return code
- stdout hash
- stderr hash
- parsed negotiated group
- parsed protocol
- parsed cipher
- failure category
- OpenSSL path/version/capabilities

Do not log secrets or full certificate bodies.

## Policy for MVP

Use hardcoded Python rule objects, not YAML.

Minimum policy outcomes:

1. `negotiated_group == X25519MLKEM768` → severity: `info`, readiness: `transitional_hybrid`, confidence: `high`
2. hybrid not testable locally → severity: `info`, readiness: `unknown`, confidence: `high`
3. hybrid probe failed → severity: `info`, readiness: `unknown`, confidence: `medium`
4. `negotiated_group == X25519` → severity: `low`, readiness: `quantum_vulnerable`, confidence: `high`

### Severity vocabulary

- `critical`
- `high`
- `medium`
- `low`
- `info`

### Readiness vocabulary

- `quantum_vulnerable`
- `classically_weak`
- `transitional_hybrid`
- `quantum_safe`
- `unknown`
- `not_applicable`

## Exit codes

- `0` = scan completed, no findings above threshold
- `1` = scan completed, findings above threshold
- `2` = target scan failed
- `3` = local dependency missing or unsupported
- `4` = usage/configuration error

For MVP, threshold defaults to `high`. Info/low findings should not fail CI by default.

## Recommended first implementation files

- `src/qureddy/core/models.py`
- `src/qureddy/core/targets.py`
- `src/qureddy/core/policy.py`
- `src/qureddy/core/errors.py`
- `src/qureddy/scanners/tls/openssl_probe.py`
- `src/qureddy/scanners/tls/parse.py`
- `src/qureddy/scanners/tls/scanner.py`
- `src/qureddy/output/json.py`
- `src/qureddy/output/console.py`
- `src/qureddy/cli.py`
- `scripts/check_subprocess_boundaries.py`
- `tests/fixtures/openssl/`
- `tests/test_targets.py`
- `tests/test_tls_parse.py`
- `tests/test_policy.py`

Do not create speculative plugin infrastructure beyond what MVP needs. If a `Scanner` protocol already exists in docs and is needed, keep it minimal and synchronous.

## Testing requirements

- Unit tests must not require network access.
- Use captured OpenSSL fixture outputs.
- Parser tests must cover:
  - `Negotiated TLS1.3 group: X25519MLKEM768`
  - `Server Temp Key: X25519MLKEM768`
  - `Server Temp Key: X25519`
  - ClientHello-only `X25519MLKEM768` must be rejected
  - ServerHello `key_share` `X25519MLKEM768` in trace must be accepted
  - Missing group after apparent success produces `parse_no_group`
- Target tests must cover:
  - `example.com`
  - `example.com:443`
  - `https://example.com`
  - `https://example.com:8443`
  - `1.2.3.4:443`
  - `1.2.3.4:443 --sni example.com`
- Retry tests must cover:
  - `--retry-on target_connect_failed --retries 3` against an unreachable host attempts exactly 4 times (1 initial + 3 retries) and reports total attempts in the result.
  - `--retry-on tls_handshake_failed --retries 3` against an unreachable host does NOT retry (mismatched category) and exits after 1 attempt.
  - Default behavior (no flags) is single-attempt.
  - `--retries 3` without `--retry-on` exits with usage error (exit code 4).
  - `--retry-on unknown_category` exits with usage error (exit code 4).
  - `--retries 11` exits with usage error.
  - `--retry-delay 100` exits with usage error.
  - Retry delay is honored: 3 retries with `--retry-delay 0.1` takes >= 0.3 seconds wall time (use a clock injection or a fake sleep).
  - Mid-stream category change stops retries: if attempt 1 is `target_connect_failed` (in `--retry-on`) and attempt 2 is `tls_handshake_failed` (not in `--retry-on`), stop and report the second.
  - Each attempt produces its own evidence record; the result captures all of them.

## Run before final response

- `ruff check .`
- `mypy src/qureddy --strict`
- `pytest`

If any command cannot run because project setup is incomplete, state that clearly and explain what blocked it.

## Final response format

1. What you implemented.
2. Files changed.
3. Commands run and results.
4. Anti-pattern audit result.
5. Assumptions made.
