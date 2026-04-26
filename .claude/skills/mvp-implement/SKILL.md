---
name: mvp-implement
description: Implement or extend the MVP 0.1 TLS scanner for QuReddy. Use when the active task is writing scanner code, adding probe behavior, building the CLI, or any work scoped to MVP 0.1 (TLS scanner only, Python via pipx, no Docker, OpenSSL 3.5+ subprocess). This skill is the sole operational authority for MVP 0.1 implementation. It is self-contained — the older monolithic prompt is no longer in the public repo.
---

# Skill: mvp-implement

The sole operational authority for MVP 0.1 implementation. Self-contained — every use case, locked model, retry rule, JSON shape, and exit code you need is in this file. The earlier monolithic prompt was removed from the public tree to prevent drift; it lives in `scratch/` locally if anyone needs it for historical inspection.

## Before you write any code

1. Read `docs/CODING_RULES.md` fully. Source of truth for engineering standards. Pay attention to Sections 1-12 (Python authoring), Section 21 (CI phases), Section 26 (security bar).
2. Read `docs/AGENT_ANTIPATTERNS.md` fully. Pre-response audit checklist.
3. Read `tests/fixtures/openssl/TARGETS.md`. Canonical target list.
4. Read `docs/EXAMPLES.md`. Side-by-side good vs bad code patterns. The first file you write sets the precedent for everything else; do not set it from your training-data instincts.

If any rule in this skill conflicts with `docs/CODING_RULES.md`, the rules doc wins and this skill needs updating. Surface the conflict, do not silently violate.

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

## MVP 0.1 use cases

These are the concrete user scenarios MVP 0.1 must satisfy. Every use case must be covered by at least one test (unit or live). If a use case has no test, MVP 0.1 is incomplete.

**Use Case 1: Check Hybrid PQ Negotiation.** As a security engineer, I want to scan a public TLS endpoint and determine whether it actually negotiates X25519MLKEM768.
- Command: `qureddy scan tls pq.cloudflareresearch.com --format json`
- Success: JSON includes `readiness=transitional_hybrid` based on `negotiated` evidence (not `offered`).
- Test: `tests/live/test_live_targets.py::test_pq_cloudflareresearch_hybrid` AND `tests/test_tls_parse.py`

**Use Case 2: Confirm Classical Fallback.** As a reviewer, I want to compare hybrid and classical behavior.
- Command: `qureddy scan tls example.com --format json`
- Success: JSON valid, no false `transitional_hybrid` claim, classical X25519 reported as `quantum_vulnerable`.
- Test: `tests/live/test_live_targets.py::test_example_com_classical` AND `tests/test_policy.py`

**Use Case 3: Scan With SNI Against An IP.** As an operator, I want to scan a TLS virtual host by IP while supplying SNI.
- Command: `qureddy scan tls 1.1.1.1:443 --sni one.one.one.one --format json`
- Success: Normalized target has `host=1.1.1.1`, `sni=one.one.one.one`. Probe uses `-servername one.one.one.one`.
- Test: `tests/live/test_live_targets.py::test_one_one_one_one_with_sni` AND `tests/test_targets.py`

**Use Case 4: Detect Unsupported Local OpenSSL.** As a user, I want a clear result when local OpenSSL cannot test X25519MLKEM768.
- Command: `qureddy scan tls google.com --openssl /path/to/old/openssl --format json`
- Success: Exit code 3. Output has `readiness=unknown`, `failure_category=local_openssl_too_old` or `local_openssl_lacks_group`. Does not falsely claim the server is not PQ-ready.
- Test: `tests/test_openssl_probe.py` using a fake openssl binary (small shell script under `tests/fixtures/openssl/fake/`).

**Use Case 5: Handle TLS 1.3 Probe Failure Cleanly.** As a reviewer, I want a TLS 1.2-only server to fail as structured scanner output, not a Python traceback.
- Command: `qureddy scan tls tls-v1-2.badssl.com:1012 --format json`
- Success: Exit code 2. Output has `failure_category=tls_handshake_failed`. JSON valid. No traceback.
- Test: `tests/live/test_live_targets.py::test_tls12_only_handshake_failure`

**Use Case 6: Retry A Transient Network Failure.** As an operator, I want to retry only failure categories that might be transient.
- Command: `qureddy scan tls example.com --retry-on target_connect_failed --retries 3 --retry-delay 1 --format json`
- Success: Each attempt recorded as its own `Evidence`. `total_attempts` reflects actual attempts. Mid-stream change to a non-retryable category stops retries.
- Test: `tests/test_retry.py`

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

Required dev/test dependencies (enterprise-grade gates from day 0):
- `pytest`
- `pytest-cov`
- `pytest-rerunfailures` (configured globally in `pyproject.toml` for 3 retries, 1s delay)
- `ruff`
- `mypy`
- `bandit` (Python security footguns — subprocess mistakes, shell=True, unsafe temp files)
- `pip-audit` (known vulnerable Python dependencies)
- `deptry` (unused or missing dependencies)
- `reuse` (SPDX/license header compliance)
- `semgrep` (security smells; report-only for MVP 0.1)

External dev tools (not Python deps; install per-OS):
- `gitleaks` (secrets in working tree); fallback `trufflehog` if unavailable

Do not add `cryptography`, `cyclonedx-python-lib`, `aiosqlite`, `Jinja2`, Tailwind tooling, `WeasyPrint`, or any report dependencies in MVP 0.1.

## Locked Pydantic model definitions

Implement these in `src/qureddy/core/models.py`. You may add fields only if explicitly required by this skill. Do not remove fields. Do not change types.

Imports:

```python
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
```

Frozen config (use this on every model):

```python
FROZEN = ConfigDict(frozen=True, extra="forbid")
```

Enums:

```python
class ObservationType(str, Enum):
    NEGOTIATED = "negotiated"
    OFFERED = "offered"
    OBSERVED = "observed"
    INFERRED = "inferred"
    NOT_TESTABLE = "not_testable"

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Readiness(str, Enum):
    QUANTUM_VULNERABLE = "quantum_vulnerable"
    CLASSICALLY_WEAK = "classically_weak"
    TRANSITIONAL_HYBRID = "transitional_hybrid"
    QUANTUM_SAFE = "quantum_safe"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"

class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class FailureCategory(str, Enum):
    LOCAL_OPENSSL_MISSING = "local_openssl_missing"
    LOCAL_OPENSSL_TOO_OLD = "local_openssl_too_old"
    LOCAL_OPENSSL_LACKS_GROUP = "local_openssl_lacks_group"
    TARGET_CONNECT_FAILED = "target_connect_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    SNI_REQUIRED_OR_WRONG = "sni_required_or_wrong"
    MIDDLEBOX_OR_MTU_FAILURE = "middlebox_or_mtu_failure"
    PARSE_NO_GROUP = "parse_no_group"
    PARSE_AMBIGUOUS = "parse_ambiguous"
    UNEXPECTED_GROUP = "unexpected_group"

class OutputFormat(str, Enum):
    RICH = "rich"
    JSON = "json"
```

Models:

```python
class ScanTarget(BaseModel):
    model_config = FROZEN
    original_input: str
    host: str
    port: int
    sni: str | None
    scheme: str = "tls"
    locator: str

class OpenSSLDependency(BaseModel):
    model_config = FROZEN
    name: str = "openssl"
    path: str | None = None
    version: str | None = None
    supports_tls13_groups: bool = False
    supports_x25519mlkem768: bool = False
    failure_category: FailureCategory | None = None

class ProbeCommand(BaseModel):
    model_config = FROZEN
    executable: str
    args: tuple[str, ...]
    timeout_seconds: int
    redacted: bool = False

class ProbeResult(BaseModel):
    model_config = FROZEN
    command: ProbeCommand
    return_code: int
    stdout_sha256: str
    stderr_sha256: str
    stdout_excerpt: str = ""
    stderr_excerpt: str = ""
    duration_ms: int
    attempt_number: int = 1
    failure_category: FailureCategory | None = None

class Asset(BaseModel):
    model_config = FROZEN
    id: str
    asset_type: str
    locator: str
    display_name: str
    protocol: str = "tls"
    protocol_version: str | None = None
    algorithm: str | None = None
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    key_size: int | None = None
    negotiated_group: str | None = None
    bom_ref: str | None = None
    oid: str | None = None
    nist_quantum_security_level: int | None = Field(default=None, ge=0, le=5)

class Evidence(BaseModel):
    model_config = FROZEN
    id: str
    asset_id: str
    evidence_type: str
    observation_type: ObservationType
    source: str
    protocol: str = "tls"
    protocol_version: str | None = None
    cipher_suite: str | None = None
    negotiated_group: str | None = None
    probe_result: ProbeResult | None = None
    failure_category: FailureCategory | None = None
    confidence: Confidence = Confidence.HIGH
    notes: tuple[str, ...] = Field(default_factory=tuple)

class Finding(BaseModel):
    model_config = FROZEN
    id: str
    asset_id: str
    evidence_ids: tuple[str, ...] = Field(min_length=1)
    rule_id: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    readiness: Readiness
    confidence: Confidence
    algorithm: str | None = None
    primitive: str | None = None
    parameter_set_identifier: str | None = None
    key_size: int | None = None
    protocol: str = "tls"
    protocol_version: str | None = None
    negotiated_group: str | None = None
    bom_ref: str | None = None
    oid: str | None = None
    nist_quantum_security_level: int | None = Field(default=None, ge=0, le=5)

class ScanMetadata(BaseModel):
    model_config = FROZEN
    scan_id: str
    started_at: datetime
    completed_at: datetime
    scanner_name: str = "tls"
    scanner_version: str = "0.1.0"
    status: str
    total_attempts: int = 1

class ScanSummary(BaseModel):
    model_config = FROZEN
    target: str
    finding_count: int
    highest_severity: Severity | None = None
    readiness: Readiness
    failure_category: FailureCategory | None = None

class ScanResult(BaseModel):
    model_config = FROZEN
    schema_version: str = "qureddy.scan.v1"
    scan: ScanMetadata
    target: ScanTarget
    dependencies: tuple[OpenSSLDependency, ...]
    assets: tuple[Asset, ...]
    evidence: tuple[Evidence, ...]
    findings: tuple[Finding, ...]
    summary: ScanSummary
```

### Model notes

- `Evidence.notes: tuple[str, ...]` is the parser's debug context. No `dict[str, Any]` escape hatch.
- `nist_quantum_security_level` is `ge=0, le=5`, CycloneDX-aligned. `0` means "assessed and not in any PQ category"; `None` means "not assessed."
- `Finding.evidence_ids` requires `min_length=1`. Model rejects orphan findings at construction.
- `attempt_number` on `ProbeResult` and `total_attempts` on `ScanMetadata` support the retry feature.
- **`ScanMetadata` is fully frozen.** Build it once at end-of-scan with `started_at` and `completed_at` both known. The `TLSScanner.scan()` orchestrator captures `started_at` as a local `datetime`, runs the scan, then constructs `ScanMetadata` once at the end. Do not build a `ScanMetadata` early and mutate it. Do not mutate any nested model after `ScanResult` is built.
- The CycloneDX-flavored fields (`primitive`, `parameter_set_identifier`, `bom_ref`, `oid`, `nist_quantum_security_level`) are unused at MVP 0.1 but locked in now to avoid a JSON schema migration when CBOM emission lands at MVP 0.3. **`ANTIPATTERN ACCEPTED: speculative generality, because CycloneDX field names will land at MVP 0.3 and JSON schema stability matters for early adopters.`** Mark this in your final-response audit.

## Locked policy model

In `src/qureddy/core/policy.py`:

```python
from __future__ import annotations
from enum import Enum
from pydantic import BaseModel, ConfigDict
from qureddy.core.models import (
    Asset, Confidence, Evidence, FailureCategory, Finding,
    FROZEN, ObservationType, Readiness, Severity,
)

class RuleField(str, Enum):
    NEGOTIATED_GROUP = "negotiated_group"
    OBSERVATION_TYPE = "observation_type"
    FAILURE_CATEGORY = "failure_category"

class RuleCondition(BaseModel):
    model_config = FROZEN
    field: RuleField  # enum, not str — typos fail at construction
    equals: str | None = None
    failure_category: FailureCategory | None = None
    observation_type: ObservationType | None = None

class PolicyRule(BaseModel):
    model_config = FROZEN
    id: str
    finding_type: str
    title: str
    description: str
    severity: Severity
    readiness: Readiness
    confidence: Confidence
    conditions: tuple[RuleCondition, ...]

MVP_POLICY: tuple[PolicyRule, ...] = (
    # ... four rules, see "MVP policy rules" below
)

def classify_evidence(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Classify TLS evidence into MVP findings."""
```

`field: RuleField` (an enum), not `field: str`. Catches typos at model construction time, not at "why isn't my rule firing" time.

## MVP policy rules (exactly these four)

1. `tls.hybrid.negotiated_x25519mlkem768` → severity=info, readiness=transitional_hybrid, confidence=high. Fires when `negotiated_group == "X25519MLKEM768"` AND `observation_type == NEGOTIATED`.
2. `tls.hybrid.not_testable` → severity=info, readiness=unknown, confidence=high. Fires when `failure_category` ∈ {`local_openssl_missing`, `local_openssl_too_old`, `local_openssl_lacks_group`}.
3. `tls.hybrid.probe_failed` → severity=info, readiness=unknown, confidence=medium. Fires when `failure_category` ∈ {`target_connect_failed`, `tls_handshake_failed`, `sni_required_or_wrong`, `middlebox_or_mtu_failure`, `parse_no_group`, `parse_ambiguous`}.
4. `tls.classical.negotiated_x25519` → severity=low, readiness=quantum_vulnerable, confidence=high. Fires when `negotiated_group == "X25519"` AND `observation_type == NEGOTIATED`.

Findings must reference evidence IDs (`evidence_ids: tuple[str, ...]`, min_length=1).

## Retry semantics (locked)

CLI accepts retry flags. **Narrow allowlist by design** for MVP 0.1: only failures that can plausibly be transient are retryable.

Retryable categories (allowlist):
- `target_connect_failed`
- `tls_handshake_failed`
- `middlebox_or_mtu_failure`
- `parse_no_group`

Non-retryable categories (always reject in `--retry-on`):
- `local_openssl_missing`, `local_openssl_too_old`, `local_openssl_lacks_group` — local capability is deterministic
- `sni_required_or_wrong` — fix your SNI, don't retry
- `parse_ambiguous`, `unexpected_group` — deterministic on identical input

Flags:
- `--retry-on CATEGORY[,CATEGORY...]` — only retryable allowlist values accepted. Default empty.
- `--retries N` — integer, default 0, max 3.
- `--retry-delay SECONDS` — float, default 1.0, max 10.

Behavior:
1. First attempt always runs. Retries fire only if first attempt's `failure_category` matches `--retry-on`.
2. Sleep `--retry-delay` between attempts.
3. If a retry produces a *different* failure category than what triggered the retry, stop and report the new category.
4. If a retry succeeds, scan succeeds. Earlier failures recorded as `Evidence`.
5. Local capability failures never reach retry orchestration — detected at capability-check time, exit 3 immediately.
6. Validation:
   - `--retry-on` value not in retryable allowlist → exit 4 naming the rejected category and the allowed set
   - `--retry-on` value not in `FailureCategory` enum at all → exit 4 "unknown failure category"
   - `--retries` outside [0, 3] → exit 4
   - `--retry-delay` outside [0.0, 10.0] → exit 4
   - `--retries N > 0` without `--retry-on` → exit 4 "no retry categories specified"
7. Each attempt produces its own `Evidence` record. Result reports `total_attempts`.

Default behavior (no flags) is single-attempt.

## JSON output shape

Top-level keys must appear in this exact order:

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

Use `model.model_dump(mode="json")`. Do not hand-build dicts.

Raw evidence policy:
- include parsed evidence
- include command args, redacted if needed
- include return code
- include stdout/stderr SHA-256 hashes
- include parsed negotiated group, protocol, cipher
- include `failure_category` when applicable
- include `attempt_number` on each `ProbeResult`
- include `total_attempts` on `ScanMetadata`
- do not include full OpenSSL stdout/stderr by default
- do not include full traces
- do not include certificate PEM bodies

## Exit codes

- 0: scan completed successfully
- 1: reserved for future high-severity findings (do not emit at MVP 0.1)
- 2: target scan failed
- 3: local dependency missing or unsupported
- 4: usage/configuration error

## Tests are non-negotiable

Per `docs/CODING_RULES.md` Section 9: every test runs every time. No `@pytest.mark.skip`, no `@pytest.mark.acceptance`, no `tests/integration/` carve-out. The full suite runs on every `pytest` invocation. `pytest-rerunfailures` absorbs transient internet hiccups.

Live tests live in `tests/live/` and run with the default `pytest` invocation, not behind any marker.

Use case coverage above is mandatory: every UC1-UC6 maps to at least one test.

## Quality gates before final response (enterprise-grade, verify-only)

Run all of these. Do not skip. Do not claim PASS without running. If a tool is unavailable, report `NOT RUN` with the exact reason.

**Tier 1 (every code-touching task):**

```
ruff check .
ruff format --check .
mypy src/qureddy --strict
pytest --cov=qureddy --cov-fail-under=80
bandit -r src/qureddy
pip-audit
deptry .
reuse lint
```

**Secret scan (one of these):**

```
gitleaks detect --no-git --source .
```

If `gitleaks` is unavailable:

```
trufflehog filesystem --no-update .
```

**Semgrep (report-only for MVP 0.1):**

```
semgrep scan --config auto .
```

Semgrep findings are reported but do not block MVP 0.1 implementation until rules are tuned. Once false-positive baseline is known, Semgrep promotes to blocking in a later milestone.

### Rules for these gates

- `ruff format --check .` reports formatting issues without rewriting files. Per CODING_RULES §1.5, mechanical formatting changes are separate from behavior changes. **Do not silently rewrite the diff.** If you are explicitly doing a formatting-only task, run `ruff format .` (without `--check`) and warn the user it will modify files.
- Coverage threshold is 80%. Failure to hit it is a real signal — add tests, do not lower the threshold.
- `bandit` runs at MEDIUM threshold (configured in `pyproject.toml`). Findings at MEDIUM or higher block. LOW findings are reported but do not block.
- `pip-audit` blocks on HIGH or CRITICAL CVEs. MEDIUM and below are reported but do not block.
- `reuse lint` requires every source file to have an SPDX header (`# SPDX-License-Identifier: Apache-2.0`).
- `deptry` flags dependencies declared but unused, and imports without a corresponding declared dependency.

If any gate is unavailable (tool not installed, project setup incomplete), report exactly which one and why. Do not skip silently. Do not say "looks fine."

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
- any of the 6 use cases above has no corresponding test
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
