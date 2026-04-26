---
name: mvp-implement
description: Implement or extend the MVP 0.1 TLS scanner for QuReddy. Use when the active task is writing scanner code, adding probe behavior, building the CLI, or any work scoped to MVP 0.1 (TLS scanner only, Python via pipx, no Docker, OpenSSL 3.5+ subprocess).
---

# Skill: mvp-implement

Operational authority for MVP 0.1 implementation work. Loaded when Claude is writing code for the TLS scanner.

This skill replaces the role of `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md`. That doc is preserved for historical reference but should not be the working spec.

## Before you write any code

1. Read `docs/CODING_RULES.md` fully. It is the source of truth for engineering standards. Pay particular attention to Sections 1-12 (Python authoring), Section 21 (CI phases), Section 26 (security bar).
2. Read `docs/AGENT_ANTIPATTERNS.md` fully. This is your pre-response audit checklist.
3. Read `tests/fixtures/openssl/TARGETS.md` — the canonical target list for live tests and fixture capture.
4. Check the canonical MVP 0.1 spec at `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` for any specifics this skill does not yet cover (architecture diagram, use cases, model definitions, retry semantics).

If any rule in this skill conflicts with `docs/CODING_RULES.md`, the rules doc wins and this skill needs updating.

## Scope (what MVP 0.1 is)

One CLI command:

```
qureddy scan tls TARGET
  [--sni NAME]
  [--openssl PATH]
  [--format rich|json]
  [--timeout SECONDS]
  [--retry-on CATEGORY[,CATEGORY...]]
  [--retries N]
  [--retry-delay SECONDS]
  [-v|-vv|-vvv]
  [--json-logs]
  [-q|--quiet]
```

Real OpenSSL 3.5+ subprocess. Real probe of `X25519MLKEM768` against the target. Detect whether it was actually negotiated. Run a classical X25519 control probe. Emit native QuReddy JSON or a Rich table. Structured logging from day 0.

## Hard scope rules

**Includes:**
- Target parsing and normalization
- OpenSSL 3.5+ capability detection (`openssl version`, `openssl list -tls1_3 -tls-groups`)
- TLS 1.3 X25519MLKEM768 hybrid probe
- TLS 1.3 X25519 classical control probe
- Retry feature (narrow allowlist: `target_connect_failed`, `tls_handshake_failed`, `middlebox_or_mtu_failure`, `parse_no_group`)
- Native QuReddy JSON output
- Rich terminal output
- Structured `structlog` logging from day 0
- Fixture-based unit tests
- Live tests against the 6 canonical targets in `tests/fixtures/openssl/TARGETS.md`
- `tests/test_openssl_probe.py` (capability detection with a fake openssl binary)
- `tests/test_retry.py`
- `docs/STANDARDS.md`

**Excludes (do not write code for these):**
- sslyze, nassl, pyOpenSSL, Python `ssl`-based hybrid probing
- oqs-provider integration
- GPL/AGPL runtime dependencies
- certificate chain parsing
- `cryptography` dependency
- CBOM emission, SQLite, YAML policies, HNDL scoring
- HTML/PDF/CSV/Markdown reports
- SSH/local/cert/code/config scanners
- batch scanning
- Docker
- telemetry
- stdin input
- trace fallback parser

## NO PLACEHOLDER SCAFFOLDING

Every file you create must be used by the running command, by pytest, or by tooling required to run those. Do not create empty modules, unused abstractions, future plugin systems, fake scanner registries, TODO-only files, fake OpenSSL results, placeholder tests, unused extension points, report commands, CBOM emitters, database layers, or Docker files.

If a file you are about to create cannot participate in the working MVP command path or tests, do not create it. Explain why in your response.

## Build order

Build in this order. Do not skip ahead.

1. `pyproject.toml`, `src/qureddy/__init__.py`, `src/qureddy/__main__.py`, `src/qureddy/cli.py`. `qureddy --help` must work.
2. `src/qureddy/core/models.py`, `src/qureddy/core/errors.py`. Run `tests/test_models.py`.
3. `src/qureddy/core/targets.py`, `tests/test_targets.py`.
4. `src/qureddy/scanners/tls/openssl_probe.py`. Must call real OpenSSL.
5. `src/qureddy/scanners/tls/parse.py`, `tests/fixtures/openssl/*`, `tests/test_tls_parse.py`.
6. `src/qureddy/core/policy.py`, `tests/test_policy.py`.
7. `src/qureddy/core/retry.py`, `tests/test_retry.py`.
8. `src/qureddy/scanners/tls/scanner.py`. Calls capability check, hybrid probe, classical probe, parser, retry, and policy.
9. `src/qureddy/output/json.py`, `src/qureddy/output/console.py`.
10. `src/qureddy/core/logging.py`, `tests/test_logging.py`.
11. `tests/live/test_live_targets.py`.
12. `docs/STANDARDS.md`, update `AGENTS.md` if needed.

## OpenSSL boundary (non-negotiable)

All OpenSSL subprocess calls live only in `src/qureddy/scanners/tls/openssl_probe.py`. No other module calls OpenSSL.

`subprocess.run` with: args as a list, `shell=False`, explicit `timeout` (default 30s), `capture_output=True`, `check=False`, explicit return code handling.

OpenSSL path resolution order: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`.

## Required runtime dependencies

- `typer`
- `rich`
- `pydantic`
- `structlog`
- `packaging` (for OpenSSL version parsing — required, not optional)

Required dev/test:
- `pytest`
- `pytest-rerunfailures` (configured globally in `pyproject.toml` for 3 retries, 1s delay)
- `ruff`
- `mypy`

Do not add `cryptography`, `cyclonedx-python-lib`, `aiosqlite`, `Jinja2`, Tailwind tooling, `WeasyPrint`, or any report dependencies in MVP 0.1.

## Model definitions are locked

The Pydantic model definitions for `ScanTarget`, `OpenSSLDependency`, `ProbeCommand`, `ProbeResult`, `Asset`, `Evidence`, `Finding`, `ScanMetadata`, `ScanSummary`, `ScanResult` are locked in `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` Section 15A. Use exactly those shapes. Frozen by default with `extra="forbid"`. `ScanMetadata` is fully frozen — build it once at end-of-scan with `started_at` and `completed_at` both known.

`nist_quantum_security_level` is `ge=0, le=5` (CycloneDX-aligned). `Finding.evidence_ids` requires `min_length=1`.

## Tests are non-negotiable

Per `docs/CODING_RULES.md` Section 9: every test runs every time. No `@pytest.mark.skip`, no `@pytest.mark.acceptance`, no `tests/integration/` carve-out. The full suite runs on every `pytest` invocation. `pytest-rerunfailures` absorbs transient internet hiccups.

Live tests live in `tests/live/` and run with the default `pytest` invocation, not behind any marker.

Use case coverage from `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` Section 0B is mandatory: every use case maps to at least one test. If a use case has no test, MVP 0.1 is incomplete.

## Quality gates before final response

Run these before responding:

```
ruff check .
ruff format .
mypy src/qureddy --strict
pytest
```

If `ruff format` changes files, say so explicitly. If a command cannot run because the project setup is incomplete, name the blocking step.

## Final response format

1. What you implemented
2. Files created or changed
3. Commands run and exact results
4. Live test results for every target in `tests/live/test_live_targets.py`
5. Anti-pattern audit result, including the `ANTIPATTERN ACCEPTED:` for CycloneDX-flavored model fields
6. What you intentionally did not implement because it is out of MVP 0.1 scope
7. Assumptions and open questions

Do not say "fixed" unless you actually changed code and verified it. Do not claim a check passed unless you ran it.

## Definition of done

MVP 0.1 is incomplete if any of these are true:

- `qureddy scan tls TARGET` does not execute a real OpenSSL subprocess
- JSON output lacks dependencies, evidence, or findings
- parser tests use only invented inline strings and no fixture files
- live tests are absent
- any of the 6 use cases in `docs/mvp/MVP-0.1-CLAUDE-PROMPT.md` Section 0B has no corresponding test
- OpenSSL missing/old/lacking-group paths crash instead of returning structured output
- logs appear on stdout
- scan results appear on stderr
- any created module is unused by command path or tests
- TODO placeholders exist for MVP behavior
- `sslyze`, `nassl`, `cryptography` appear in runtime dependencies
- SQLite, CBOM, YAML policy loading, or `Dockerfile` appear

## When you are unsure

State the assumption explicitly:

```
ASSUMPTION: I am assuming X because the spec is silent on it. If wrong, change to Y.
```

Do not invent file paths, function names, or library APIs. Hallucinated imports are the single biggest source of bugs in agent code.

## When asked for an insecure shortcut

Per `docs/CODING_RULES.md` Section 26.13, you refuse and propose the secure alternative. This applies even when the request comes with framing like "just for now" or "to make CI green." A captured fixture, list-form arguments, or hash-only logging is the answer.
