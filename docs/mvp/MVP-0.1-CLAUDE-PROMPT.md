# MVP 0.1 — Claude Implementation Prompt (HISTORICAL REFERENCE)

> **This document is no longer the implementation authority.**
> The active authority is `.claude/skills/mvp-implement/SKILL.md`. That skill is what Claude Code loads when working on MVP 0.1.
>
> This file is preserved as historical reference. It contains material the skill references but does not duplicate: the architecture diagram (§0A), use cases (§0B), locked Pydantic model definitions (§15A), locked policy model (§16A), JSON output shape (§18), and retry semantics (§12A). Read those sections when the skill points you here.
>
> If this file and the skill disagree, **the skill wins.** Behavior changes go in the skill, not here.

You are Claude Code implementing BreachSAFE QuReddy MVP 0.1 in this repository.

Repository root:
  `/Users/Shared/claude/breachsafe-qureddy`

Your task:
  Build the working MVP 0.1 vertical slice:
  `qureddy scan tls TARGET`

The sections below remain the canonical reference for the technical material the skill points at (architecture, use cases, locked models, JSON shape, retry semantics).

================================================================================
0. READ FIRST
================================================================================

Before writing code, read these files from disk:

1. `CLAUDE.md`
2. `AGENTS.md`
3. `docs/CODING_RULES.md`
4. `docs/AGENT_ANTIPATTERNS.md`
5. `docs/OSS_STANDARDS.md`
6. `docs/CLAUDE_DEVELOPER_PROMPT.md`
7. `docs/mvp/CURRENT.md`
8. `tests/fixtures/openssl/TARGETS.md`

After reading, treat this prompt as the locked MVP 0.1 implementation prompt.

You must audit your final diff against `docs/AGENT_ANTIPATTERNS.md` before final response. If you intentionally violate anything, write:

  `ANTIPATTERN ACCEPTED: <name>, because <reason>`

================================================================================
0A. ARCHITECTURE
================================================================================

```
                          BreachSAFE QuReddy MVP 0.1

                                  User
                                   |
                                   v
                     qureddy scan tls TARGET [options]
                                   |
                                   v
                            Typer CLI
                         src/qureddy/cli.py
                                   |
                +------------------+------------------+
                |                                     |
                v                                     v
        Target Normalizer                      Logging Setup
     core/targets.py                           core/logging.py
                |                                     |
                v                                     v
        ScanTarget model                    stderr structured logs
                |
                v
           TLS Scanner
    scanners/tls/scanner.py
                |
      +---------+----------+
      |                    |
      v                    v
OpenSSL Capability     TLS Probe Runner
openssl_probe.py       openssl_probe.py
      |                    |
      |                    +-----------------------------+
      |                                                  |
      v                                                  v
OpenSSLDependency                              Hybrid probe: X25519MLKEM768
path/version/groups                            Classical probe: X25519
      |                                                  |
      +----------------------+---------------------------+
                             |
                             v
                       ProbeResult
               stdout/stderr hashes, return code,
               duration, attempt number, failure category
                             |
                             v
                       TLS Parser
                 scanners/tls/parse.py
                             |
                             v
                         Evidence
          negotiated group, protocol, cipher, observation type
                             |
                             v
                     Policy Classifier
                       core/policy.py
                             |
                             v
                          Findings
            severity, readiness, confidence, evidence refs
                             |
                             v
                        ScanResult
                       core/models.py
                             |
              +--------------+--------------+
              |                             |
              v                             v
      Rich Output stdout             JSON Output stdout
      output/console.py              output/json.py
```

**Boundary rule:**

Only this module may execute OpenSSL:

  `src/qureddy/scanners/tls/openssl_probe.py`

All other modules consume typed models. They do not know OpenSSL exists.

**No storage path:**

MVP 0.1 has no SQLite, no CBOM, no reports, no scanner registry. Scan in, result out, exit.

================================================================================
0B. MVP USE CASES
================================================================================

These are the concrete user scenarios MVP 0.1 must satisfy. Every use case must be covered by either a unit test or a live test. If a use case has no corresponding test, the MVP is incomplete.

**Use Case 1: Check Hybrid PQ Negotiation**

As a security engineer, I want to scan one public TLS endpoint and determine whether it actually negotiates X25519MLKEM768.

Command:
  `qureddy scan tls pq.cloudflareresearch.com --format json`

Success: JSON includes `readiness=transitional_hybrid` based on `negotiated` evidence (not `offered`).

**Use Case 2: Confirm Classical Fallback**

As a reviewer, I want to see whether a server still negotiates classical X25519 so I can compare hybrid and classical behavior.

Command:
  `qureddy scan tls example.com --format json`

Success: JSON is valid. Findings do not falsely claim `transitional_hybrid`. Classical X25519 is reported as `quantum_vulnerable`.

**Use Case 3: Scan With SNI Against An IP**

As an operator, I want to scan a TLS virtual host by IP while supplying SNI.

Command:
  `qureddy scan tls 1.1.1.1:443 --sni one.one.one.one --format json`

Success: Normalized target has `host=1.1.1.1` and `sni=one.one.one.one`. Probe uses `-servername one.one.one.one`.

**Use Case 4: Detect Unsupported Local OpenSSL**

As a user, I want a clear result when my local OpenSSL cannot test X25519MLKEM768.

Command:
  `qureddy scan tls google.com --openssl /path/to/old/openssl --format json`

Success: Exit code 3. Output has `readiness=unknown`, `failure_category=local_openssl_too_old` or `local_openssl_lacks_group`. The scanner does not falsely claim the server is not PQ-ready.

**Use Case 5: Handle TLS 1.3 Probe Failure Cleanly**

As a reviewer, I want a TLS 1.2-only server to fail as structured scanner output, not a Python traceback.

Command:
  `qureddy scan tls tls-v1-2.badssl.com:1012 --format json`

Success: Exit code 2. Output has `failure_category=tls_handshake_failed`. JSON is valid. No traceback on stderr.

**Use Case 6: Retry A Transient Network Failure**

As an operator, I want to retry only failure categories that might be transient.

Command:
  `qureddy scan tls example.com --retry-on target_connect_failed --retries 3 --retry-delay 1 --format json`

Success: Each attempt is recorded as its own `Evidence`. `total_attempts` reflects actual attempts. Mid-stream change to a non-retryable category stops retries.

================================================================================
1. CRITICAL RULE: NO PLACEHOLDER SCAFFOLDING
================================================================================

Do not scaffold placeholders.

Every file you create must be used by one of these:
- the running command: `qureddy scan tls TARGET`
- pytest tests
- packaging/tooling required to run the command

Do not create:
- empty modules
- unused abstractions
- future plugin systems
- fake scanner registries
- TODO-only files
- fake OpenSSL results
- placeholder tests
- unused extension points
- report commands
- CBOM emitters
- database layers
- Docker files

If a file listed below cannot participate in the working MVP command path or tests, do not create it. Explain why in the final response.

MVP 0.1 is incomplete unless this command performs a real OpenSSL subprocess probe:

  `qureddy scan tls pq.cloudflareresearch.com --format json`

and returns valid JSON with: scan metadata, normalized target, OpenSSL dependency metadata, evidence, findings, summary.

================================================================================
2. CANONICAL NAMING
================================================================================

- Product: BreachSAFE QuReddy
- Friendly name: QuReddy
- CLI command: `qureddy`
- Python import package: `qureddy`
- PyPI package: `breachsafe-qureddy`
- OpenSSL env var: `QUREDDY_OPENSSL`

Do not write `qready`. Do not write `qreddy`. Exception: you may mention them only in a guard statement saying not to use them.

================================================================================
3. MVP 0.1 SCOPE
================================================================================

Implement exactly one user command:

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

MVP 0.1 includes:
- target parsing and normalization
- OpenSSL 3.5+ capability detection
- TLS 1.3 X25519MLKEM768 hybrid probe
- TLS 1.3 X25519 classical control probe
- negotiated group/protocol/cipher parsing
- retry feature: `--retry-on`, `--retries`, `--retry-delay`
- native QuReddy JSON output
- Rich terminal output
- structured logging from day 0
- fixture-based unit tests
- live tests against the targets in `tests/fixtures/openssl/TARGETS.md`
- `docs/STANDARDS.md`

MVP 0.1 excludes:
- sslyze, nassl, pyOpenSSL, Python `ssl`-based hybrid probing
- oqs-provider integration
- GPL/AGPL runtime dependencies
- certificate chain parsing
- `cryptography` dependency
- CBOM emission
- SQLite, YAML policies
- HNDL scoring
- HTML/PDF/CSV/Markdown reports
- SSH/local/cert/code/config scanners
- batch scanning
- Docker
- telemetry
- stdin input
- trace fallback parser
- subprocess boundary CI script

================================================================================
4. DEPENDENCIES
================================================================================

Required runtime dependencies:
- `typer`
- `rich`
- `pydantic`
- `structlog`
- `packaging` — required for OpenSSL version parsing. Do not hand-roll `Version` comparisons.

Required dev/test dependencies:
- `pytest`
- `pytest-rerunfailures` — every test gets up to 3 retries with 1s delay before failing. Configure in `pyproject.toml` `[tool.pytest.ini_options]` so it applies to every `pytest` invocation, not via individual `@pytest.mark.flaky` decorators.
- `ruff`
- `mypy`

Do not add `cryptography`, `cyclonedx-python-lib`, `aiosqlite`, `Jinja2`, Tailwind tooling, `WeasyPrint`, or any report dependencies in MVP 0.1.

Every new dependency must satisfy `docs/CODING_RULES.md`: actively maintained, Apache-compatible license, replaces meaningful code we would otherwise write, justified in final response.

================================================================================
5. REQUIRED FILES
================================================================================

Create or update only files needed for the working MVP.

Core files (create if missing, update only if needed):
- `pyproject.toml`
- `README.md`
- `LICENSE`
- `.gitignore` — ensure `.tmp/` is listed
- `AGENTS.md`
- `docs/STANDARDS.md`

Python package:
- `src/qureddy/__init__.py`
- `src/qureddy/__main__.py`
- `src/qureddy/cli.py`
- `src/qureddy/core/__init__.py`
- `src/qureddy/core/errors.py`
- `src/qureddy/core/logging.py`
- `src/qureddy/core/models.py`
- `src/qureddy/core/policy.py`
- `src/qureddy/core/targets.py`
- `src/qureddy/core/retry.py` (new — retry orchestration)
- `src/qureddy/scanners/__init__.py`
- `src/qureddy/scanners/tls/__init__.py`
- `src/qureddy/scanners/tls/openssl_probe.py`
- `src/qureddy/scanners/tls/parse.py`
- `src/qureddy/scanners/tls/scanner.py`
- `src/qureddy/output/__init__.py`
- `src/qureddy/output/console.py`
- `src/qureddy/output/json.py`

Tests:
- `tests/fixtures/openssl/brief_hybrid.txt`
- `tests/fixtures/openssl/brief_classical.txt`
- `tests/fixtures/openssl/clienthello_only_hybrid.txt`
- `tests/fixtures/openssl/parse_no_group.txt`
- `tests/test_models.py`
- `tests/test_targets.py`
- `tests/test_openssl_probe.py` — capability detection: missing OpenSSL, version too old, lacks `X25519MLKEM768`. Use a fake OpenSSL binary (a tiny shell script in a fixture directory that emits canned `version` and `list -tls1_3 -tls-groups` output) so this stays hermetic.
- `tests/test_tls_parse.py`
- `tests/test_policy.py`
- `tests/test_retry.py`
- `tests/test_logging.py`
- `tests/live/__init__.py`
- `tests/live/test_live_targets.py`

Do not create:
- `src/qureddy/store/`, `src/qureddy/policies/`
- `src/qureddy/output/cbom.py`, `src/qureddy/output/html.py`
- `src/qureddy/scanners/{ssh,certs,code,local}/`
- `Dockerfile`

Every Python source file must include:

  `# SPDX-License-Identifier: Apache-2.0`

Use `from __future__ import annotations` in every Python file.

================================================================================
6. PACKAGING
================================================================================

`pyproject.toml` must declare:
- project name: `breachsafe-qureddy`
- Python: `>=3.12`
- package/import: `qureddy`
- console script: `qureddy = "qureddy.cli:app"`
- pytest config that enables `pytest-rerunfailures` globally with 3 reruns and 1s delay

Use `src/` layout.

Development commands must work:

```
uv venv
uv pip install -e ".[dev]"
qureddy --help
qureddy scan tls --help
```

================================================================================
7. BUILD ORDER
================================================================================

Build in this order. Do not skip ahead.

1. Packaging and CLI shell — `pyproject.toml`, `__init__.py`, `__main__.py`, `cli.py`. `qureddy --help` must work.
2. Core models and errors — `core/models.py`, `core/errors.py`. Run `tests/test_models.py`.
3. Target parsing — `core/targets.py`, `tests/test_targets.py`.
4. OpenSSL capability and subprocess probe — `scanners/tls/openssl_probe.py`. Must call real OpenSSL.
5. OpenSSL output parser — `scanners/tls/parse.py`, `tests/fixtures/openssl/*`, `tests/test_tls_parse.py`.
6. Policy classification — `core/policy.py`, `tests/test_policy.py`.
7. Retry orchestration — `core/retry.py`, `tests/test_retry.py`.
8. TLS scanner orchestration — `scanners/tls/scanner.py`. Calls capability check, hybrid probe, classical probe, parser, retry, and policy.
9. Output — `output/json.py`, `output/console.py`.
10. Logging — `core/logging.py`, `tests/test_logging.py`.
11. Live tests — `tests/live/test_live_targets.py`.
12. Docs — `docs/STANDARDS.md`, update `AGENTS.md` if needed.

================================================================================
8. TARGET PARSING
================================================================================

`src/qureddy/core/targets.py` must expose:

  `parse_target(input_str: str, sni_override: str | None = None) -> ScanTarget`

Accepted target inputs: `example.com`, `example.com:443`, `https://example.com`, `https://example.com:8443`, `1.2.3.4:443`.

Normalize to `ScanTarget` with: `original_input`, `host`, `port`, `sni`, `scheme`, `locator`.

Rules:
- default port 443
- default scheme `tls`
- hostname target: SNI = host
- IP target: SNI = `None` unless `--sni` is provided
- locator format: `tls://host:port`
- invalid target raises `TargetParseError`
- missing TARGET exits 4

================================================================================
9. EXIT CODES
================================================================================

- 0 = scan completed successfully
- 1 = reserved for future higher-severity findings
- 2 = target scan failed
- 3 = local dependency missing or unsupported
- 4 = usage/configuration error

MVP 0.1 emits 0, 2, 3, 4. Exit 1 is reserved.

================================================================================
10. OPENSSL BOUNDARY
================================================================================

All OpenSSL subprocess calls must live only in `src/qureddy/scanners/tls/openssl_probe.py`. No other module may call OpenSSL.

Use `subprocess.run` with: args as a list, `shell=False`, explicit `timeout` (default 30s), `capture_output=True`, `check=False`, explicit return code handling.

Do not use `os.system`. Do not use `shell=True`. Do not use `subprocess.Popen` unless `subprocess.run` cannot work and you justify why.

OpenSSL path resolution order: `--openssl PATH` → `QUREDDY_OPENSSL` env var → `openssl` on `PATH`.

================================================================================
11. OPENSSL CAPABILITY CHECK
================================================================================

Run:

```
openssl version
openssl list -tls1_3 -tls-groups
```

Required: OpenSSL >= 3.5.0, `X25519MLKEM768` appears in the TLS 1.3 group list.

Parse the group list as case-insensitive, whitespace-tokenized. Do not depend on column alignment or header lines. The OpenSSL output format may shift between point releases.

If OpenSSL is missing, too old, or lacks `X25519MLKEM768`:
- do not crash
- do not claim the server is not PQ-ready
- emit a structured local dependency result: severity=info, readiness=unknown, confidence=high, failure_category one of `local_openssl_missing` | `local_openssl_too_old` | `local_openssl_lacks_group`
- exit 3

Dependency metadata must appear in JSON: name, path, version, supports_tls13_groups, supports_x25519mlkem768.

================================================================================
12. PROBE COMMANDS
================================================================================

Hybrid probe:

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

If SNI is `None`, omit `-servername` and its value entirely. Default timeout 30s.

If `-brief` is unreliable in local validation, drop `-brief` and parse default `s_client` output. Document the decision in a code comment and in final response.

Do not implement trace fallback in MVP 0.1.

If a probe returns success but no negotiated group can be parsed: emit `parse_no_group`, readiness=unknown, severity=info, confidence=medium.

================================================================================
12A. RETRY SEMANTICS
================================================================================

The CLI accepts retry flags that apply to the scanner's interactions with the target. Retries are narrow by design for MVP 0.1: only failures that can plausibly be transient are retryable.

Retryable categories (allowlist):
- `target_connect_failed`
- `tls_handshake_failed`
- `middlebox_or_mtu_failure`
- `parse_no_group`

Non-retryable categories (always reject in `--retry-on`):
- `local_openssl_missing`
- `local_openssl_too_old`
- `local_openssl_lacks_group` — local capability is deterministic; retry orchestration must not see it
- `sni_required_or_wrong` — fix your SNI, don't retry
- `parse_ambiguous` — deterministic on identical input
- `unexpected_group` — deterministic on identical input

Flags:
- `--retry-on CATEGORY[,CATEGORY...]` — comma-separated failure categories. Only categories from the retryable allowlist above are accepted. Default: empty.
- `--retries N` — integer, default 0, max 3.
- `--retry-delay SECONDS` — float, default 1.0, max 10.

Behavior:

1. The first attempt always runs. Retries fire only if the first attempt's failure category matches `--retry-on`.
2. Between attempts, sleep `--retry-delay` seconds.
3. If a retry produces a *different* failure category than the one that triggered the retry, stop and report the new category.
4. If a retry produces a non-failure outcome, the scan succeeds and reports that outcome. Earlier failures are recorded as evidence.
5. Local capability failures are never reached by retry orchestration. They are detected at capability-check time before any probe runs and exit 3 immediately.
6. Validation:
   - `--retry-on` value not in the retryable allowlist → exit 4 with message naming the rejected category and the allowed set
   - `--retry-on` value not in `FailureCategory` enum at all → exit 4 with message "unknown failure category"
   - `--retries` outside [0, 3] → exit 4
   - `--retry-delay` outside [0.0, 10.0] → exit 4
   - `--retries N > 0` without `--retry-on` → exit 4 with message "no retry categories specified"
7. Each attempt produces its own `Evidence` record. The result reports total attempt count.

Default behavior (no flags) is single-attempt.

================================================================================
13. POSITIVE HYBRID EVIDENCE
================================================================================

Accept hybrid negotiation only from these parsed outputs:

  `Negotiated TLS1.3 group: X25519MLKEM768`

or:

  `Server Temp Key: X25519MLKEM768, ...`

Never accept: `X25519MLKEM768` in ClientHello, supported_groups offered by client, key_share offered by client, local OpenSSL supported group list, documentation, or assumptions.

Offered group is not negotiated group.

`readiness=transitional_hybrid` requires: `negotiated_group=X25519MLKEM768` AND `observation_type=negotiated`.

================================================================================
14. FAILURE CATEGORIES
================================================================================

Model these categories: `local_openssl_missing`, `local_openssl_too_old`, `local_openssl_lacks_group`, `target_connect_failed`, `tls_handshake_failed`, `sni_required_or_wrong`, `middlebox_or_mtu_failure`, `parse_no_group`, `parse_ambiguous`, `unexpected_group`.

`src/qureddy/core/errors.py` must define:
- `QureddyError`
- `LocalOpenSSLMissing`
- `LocalOpenSSLTooOld`
- `LocalOpenSSLLacksGroup`
- `TargetConnectFailed`
- `TLSHandshakeFailed`
- `ParseNoGroup`
- `ParseAmbiguous`
- `TargetParseError`

Use specific exceptions or typed failure results. Do not swallow exceptions.

================================================================================
15. CORE VOCABULARY
================================================================================

`observation_type`: `negotiated`, `offered`, `observed`, `inferred`, `not_testable`.
`severity`: `critical`, `high`, `medium`, `low`, `info`.
`readiness`: `quantum_vulnerable`, `classically_weak`, `transitional_hybrid`, `quantum_safe`, `unknown`, `not_applicable`.
`confidence`: `high`, `medium`, `low`.

Use Enums or constrained Pydantic models. No loose strings.

================================================================================
15A. REQUIRED MODEL DEFINITIONS
================================================================================

Implement these in `src/qureddy/core/models.py`. You may add fields only if required by this MVP prompt. Do not remove fields.

Imports:

```python
from __future__ import annotations
from datetime import datetime
from enum import Enum
from typing import Any
from pydantic import BaseModel, ConfigDict, Field
```

Frozen config (use this on every model except `ScanMetadata`):

```python
FROZEN = ConfigDict(frozen=True, extra="forbid")
```

`ScanMetadata` uses `ConfigDict(frozen=False, extra="forbid")` because `completed_at` and `status` are set at end-of-scan.

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

Notes:
- `Evidence.notes: tuple[str, ...]` is the parser's debug context. No `dict[str, Any]` escape hatch.
- `nist_quantum_security_level` is `ge=0, le=5`, CycloneDX-aligned. `0` means "assessed and not in any PQ category"; `None` means "not assessed."
- `Finding.evidence_ids` requires `min_length=1`. The model rejects orphan findings at construction time, not at test time.
- `attempt_number` on `ProbeResult` and `total_attempts` on `ScanMetadata` support the retry feature.
- **`ScanMetadata` is fully frozen.** `started_at` and `completed_at` are both required, no two-phase mutable construction. The `TLSScanner.scan()` orchestrator captures `started_at` as a local `datetime`, runs the scan, then constructs `ScanMetadata` once at the end with `completed_at` known. Do not build a `ScanMetadata` early and mutate it. Do not mutate any nested model after `ScanResult` is built.
- The CycloneDX-flavored fields (`primitive`, `parameter_set_identifier`, `bom_ref`, `oid`, `nist_quantum_security_level`) are unused at MVP 0.1 but locked in now to avoid a JSON schema migration when CBOM emission lands at MVP 0.3. **`ANTIPATTERN ACCEPTED: speculative generality, because CycloneDX field names will land at MVP 0.3 and JSON schema stability matters for early adopters.`** Mark this in your final-response audit.

================================================================================
16. POLICY
================================================================================

Use hardcoded Python policy objects only. Do not implement YAML loading.

MVP rules (exactly these four IDs):

1. `tls.hybrid.negotiated_x25519mlkem768` → severity=info, readiness=transitional_hybrid, confidence=high
2. `tls.hybrid.not_testable` → severity=info, readiness=unknown, confidence=high
3. `tls.hybrid.probe_failed` → severity=info, readiness=unknown, confidence=medium
4. `tls.classical.negotiated_x25519` → severity=low, readiness=quantum_vulnerable, confidence=high

Policy evaluation must produce findings. Findings must reference evidence IDs.

================================================================================
16A. REQUIRED POLICY MODEL
================================================================================

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
    field: RuleField
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
    # ... four rules with the IDs above
)

def classify_evidence(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Classify TLS evidence into MVP findings."""
```

Note: `field: RuleField` (an enum), not `field: str`. Catches typos at model construction time, not at "why is my rule not firing" time.

================================================================================
17. MODELS AND CBOM ALIGNMENT
================================================================================

MVP 0.1 does not emit CBOM. Internal models are forward-compatible with CycloneDX 1.6 CBOM:
- `algorithm`: internal name string
- `primitive`: future `algorithmProperties.primitive`
- `parameter_set_identifier`: future `algorithmProperties.parameterSetIdentifier`
- `key_size`: optional, where semantically correct
- `protocol`: future `protocolProperties.type`, e.g. `tls`
- `protocol_version`: future `protocolProperties.version`, e.g. `1.3`
- `negotiated_group`: evidence field, not a `bom-ref`
- `bom_ref`: optional future CBOM reference
- `oid`: optional string
- `nist_quantum_security_level`: optional int 1-5
- `confidence`: high/medium/low, later mapped to numeric CycloneDX evidence confidence

Do not claim direct mappings (`algorithm` → `algorithmProperties.primitive`, etc.). A later CBOM adapter creates the asset components.

================================================================================
18. JSON OUTPUT
================================================================================

Top-level JSON keys must appear in this exact order for stable diffs:

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

Raw evidence policy:
- include parsed evidence
- include command args, redacted if needed
- include return code
- include stdout/stderr SHA-256 hashes
- include parsed negotiated group, protocol, cipher
- include failure category when applicable
- include attempt_number on each ProbeResult
- include total_attempts on ScanMetadata
- do not include full OpenSSL stdout/stderr by default
- do not include full traces
- do not include certificate PEM bodies

================================================================================
19. RICH OUTPUT
================================================================================

Default format is rich. Header line:

  `QuReddy 0.1.0 by BreachSAFE OSS`

No emoji. Example shape:

```
QuReddy 0.1.0 by BreachSAFE OSS
Target: tls://example.com:443
OpenSSL: /path/to/openssl OpenSSL 3.5.x

TLS 1.3 Key Exchange
Hybrid probe:     X25519MLKEM768    transitional_hybrid | info
Classical probe:  X25519            quantum_vulnerable   | low

Summary
Findings: 2
Readiness: transitional_hybrid
```

Layout can vary, but must fit a normal terminal and must not use marketing copy.

================================================================================
20. STRUCTURED LOGGING
================================================================================

Add `structlog` to runtime dependencies.

`src/qureddy/core/logging.py` must expose:

```python
def configure_logging(verbosity: int = 0, json_logs: bool = False) -> None: ...
def get_logger(name: str) -> structlog.stdlib.BoundLogger: ...
```

Verbosity: 0=WARNING, 1=INFO, 2=DEBUG, 3=DEBUG with extra subprocess and parsing context.

CLI flags: `-v`, `-vv`, `-vvv`, `--json-logs`, `-q/--quiet`.

Discipline:
- logs go to stderr
- scan results go to stdout
- never mix logs and scan output

Log: scanner phase start/end at INFO with duration_ms; subprocess start/end at INFO with redacted args, timeout, return code, duration_ms; parser decisions at DEBUG with bounded input excerpts; policy evaluation at DEBUG with rule_id, matched, reasoning; recoverable errors at WARNING; scan failures at ERROR.

Never log: secrets, private keys, full PEMs, full OpenSSL traces, full certificate bodies.

Tests: `json_logs=True` emits valid JSON; verbosity gates output correctly; scan_id and target context propagate through nested calls.

================================================================================
21. DOCS/STANDARDS.md
================================================================================

Create `docs/STANDARDS.md`. Document alignment to:
- CycloneDX 1.6: future CBOM emission format
- NIST IR 8547: PQC transition and CBOM concept reference
- NIST FIPS 203: ML-KEM
- NIST FIPS 204: ML-DSA, future scanners
- NIST FIPS 205: SLH-DSA, future scanners
- draft-ietf-tls-hybrid-design: TLS hybrid PQ key exchange
- RFC 8446: TLS 1.3
- OpenSSL 3.5: MVP probing implementation dependency, not a standard

Document non-alignment: CVSS, OWASP risk rating, NIST SP 800-30, SPDX 3.0, MITRE ATLAS. Say plainly why each does not apply to MVP 0.1 PQC TLS readiness scanning.

================================================================================
22. TESTS
================================================================================

Use `pytest`. Per `docs/CODING_RULES.md`: every test runs every time. No skip markers, no `-m` gates, no `tests/integration/` carve-out. The full suite runs on every `pytest` invocation.

`pytest-rerunfailures` retries each test up to 3 times with 1s delay before declaring failure. This applies to all tests including live ones; it absorbs transient internet hiccups without hiding real failures.

Required fixtures:

- `tests/fixtures/openssl/brief_hybrid.txt` — realistic OpenSSL output containing `Negotiated TLS1.3 group: X25519MLKEM768` or `Server Temp Key: X25519MLKEM768, ...`
- `tests/fixtures/openssl/brief_classical.txt` — `Server Temp Key: X25519, ...`
- `tests/fixtures/openssl/clienthello_only_hybrid.txt` — `X25519MLKEM768` only as offered ClientHello material; parser must reject as proof of negotiation
- `tests/fixtures/openssl/parse_no_group.txt` — successful-looking output with no parseable group

Required tests:

`tests/test_models.py`:
- `ScanResult` serializes with top-level keys in exact order: `schema_version`, `scan`, `target`, `dependencies`, `assets`, `evidence`, `findings`, `summary`
- `nist_quantum_security_level` rejects values below 0 and above 5
- Enums serialize as lowercase strings
- `Evidence` requires `observation_type`
- `Finding` requires at least one `evidence_id`
- All models except `ScanMetadata` are frozen (mutation raises)

`tests/test_targets.py`:
- `example.com`, `example.com:443`, `https://example.com`, `https://example.com:8443`, `1.2.3.4:443`
- `1.2.3.4:443` with `sni_override="example.com"`
- invalid input raises `TargetParseError`

`tests/test_tls_parse.py`:
- detects `X25519MLKEM768` from `Negotiated TLS1.3 group`
- detects `X25519MLKEM768` from `Server Temp Key`
- detects `X25519` from `Server Temp Key`
- rejects ClientHello-only `X25519MLKEM768`
- `parse_no_group` represented correctly
- unexpected group represented correctly

`tests/test_policy.py`:
- `X25519MLKEM768` negotiated → `transitional_hybrid`/info/high
- `X25519` negotiated → `quantum_vulnerable`/low/high
- local not testable → unknown/info/high
- failed hybrid probe → unknown/info/medium

`tests/test_retry.py`:
- `--retry-on target_connect_failed --retries 3` against unreachable host attempts exactly 4 times (1+3) and reports `total_attempts=4`
- `--retry-on tls_handshake_failed --retries 3` against unreachable host does NOT retry on `target_connect_failed` (mismatched category), exits after 1 attempt
- default behavior (no flags) is single-attempt
- `--retries 3` without `--retry-on` exits 4
- `--retry-on unknown_category` exits 4
- `--retries 11` exits 4
- `--retry-delay 100` exits 4
- mid-stream category change stops retries
- each attempt produces its own Evidence record
- retry-delay timing honored: 3 retries with `--retry-delay 0.1` takes >= 0.3s wall time (use a clock injection or fake sleep — do not use `time.sleep` in tests directly)

`tests/test_logging.py`:
- JSON logs parse as JSON
- verbosity levels gate logs
- context vars propagate `scan_id` and `target`

No placeholder tests. No `assert True` tests. No tests that only import modules.

**Use case coverage (per section 0B):**

Every use case in section 0B must be covered by at least one test. Mapping:

- Use Case 1 (Hybrid PQ negotiation) → `tests/live/test_live_targets.py::test_pq_cloudflareresearch_hybrid` AND `tests/test_tls_parse.py` (parser side)
- Use Case 2 (Classical fallback) → `tests/live/test_live_targets.py::test_example_com_classical` AND `tests/test_policy.py`
- Use Case 3 (SNI against IP) → `tests/live/test_live_targets.py::test_one_one_one_one_with_sni` AND `tests/test_targets.py`
- Use Case 4 (Unsupported local OpenSSL) → `tests/test_openssl_probe.py` using a fake OpenSSL binary (small shell script under `tests/fixtures/openssl/fake/`) that emits canned `openssl version` and `openssl list -tls1_3 -tls-groups` output. Capability detection is a probe-module concern, not a parser concern.
- Use Case 5 (TLS 1.3 probe failure) → `tests/live/test_live_targets.py::test_tls12_only_handshake_failure`
- Use Case 6 (Retry transient failure) → `tests/test_retry.py` (unit) — live retry verification is not required because the unit test already verifies attempt counting and Evidence records

If any use case has no corresponding test, the MVP is incomplete (per definition of done in section 25).

================================================================================
23. LIVE TESTS
================================================================================

Live tests run as part of the default `pytest` suite, not behind any marker. They live in `tests/live/`. Every `pytest` invocation runs them. `pytest-rerunfailures` absorbs transient network blips.

Targets are taken from `tests/fixtures/openssl/TARGETS.md`. For MVP 0.1, implement live tests for:

PQ / hybrid candidates:
- `pq.cloudflareresearch.com`
- `www.cloudflare.com`
- `www.google.com`

Classical baseline:
- `example.com`

SNI handling:
- `1.1.1.1:443` with `--sni one.one.one.one`

TLS failure baseline (forced TLS 1.2-only):
- `tls-v1-2.badssl.com:1012`

Acceptance contract:

1. `pq.cloudflareresearch.com` → exits 0 within 30s, valid JSON, includes `readiness=transitional_hybrid`
2. `www.cloudflare.com` → exits 0 within 30s, valid JSON, *should usually* include `transitional_hybrid` (do not hardcode as required positive — endpoint posture changes)
3. `www.google.com` → exits 0 within 30s, valid JSON (hybrid result may vary by region/edge)
4. `example.com` → exits 0 within 30s, valid JSON, should not include `transitional_hybrid`
5. `1.1.1.1:443 --sni one.one.one.one` → exits 0 within 30s, valid JSON; normalized target host is `1.1.1.1`, normalized SNI is `one.one.one.one`
6. `tls-v1-2.badssl.com:1012` → exits 2 within 30s, valid JSON error structure, `failure_category=tls_handshake_failed`, no traceback

Do not test against BreachSAFE-owned domains. Use public test infrastructure and controlled protocol edge cases.

If a target fails its expected outcome, do not fake the result. Report whether this looks like endpoint posture change, OpenSSL capability issue, or scanner bug. Include captured output summary in final response.

During implementation, save before/after smoke outputs under:

```
.tmp/smoke/before/
.tmp/smoke/after/
```

Do not commit `.tmp/`. Add `.tmp/` to `.gitignore` if not present.

Final response must summarize live test results for every target above.

================================================================================
24. QUALITY GATES
================================================================================

Run before final response (verify-only, do not modify files):

- `pytest`
- `ruff check .`
- `ruff format --check .`
- `mypy src/qureddy --strict`

`ruff format --check .` reports issues without rewriting files. Per CODING_RULES §1.5, mechanical formatting is a separate commit from behavior. If formatting is wrong, surface it; do not silently rewrite the diff. Only run `ruff format .` (no `--check`) when explicitly doing a formatting-only task, and warn the user it will modify files.

If network or OpenSSL 3.5+ is unavailable, explain exactly what command could not run and why.

MVP 0.1 is not complete unless: `pytest` passes (including live tests), `ruff check` passes, `ruff format` is clean, `mypy --strict` passes, OR a blocking external dependency is clearly documented.

================================================================================
24A. CODING RULES AUDIT
================================================================================

Before final response, walk every Python file you created or changed and audit it against `docs/CODING_RULES.md`. Check explicitly:

**File and function size:**
- No function longer than 30 lines without a justifying comment. Hard ceiling 50 lines.
- No file longer than 300 lines without a justifying comment. Hard ceiling 400 lines.
- Each module has one clear responsibility.

**Naming:**
- No `utils.py`, `helpers.py`, `common.py`, or any miscellaneous-bucket module.
- Names describe what the thing is, not how it is implemented (`parse_certificate_chain`, not `cert_parser_func`).
- No abbreviations except universal ones (TLS, SSH, RSA, KEX, HMAC). `certificate` not `cert` in type names.

**Type hints:**
- Every public function has type hints on every parameter and return value.
- `from __future__ import annotations` at the top of every file.
- `mypy --strict` clean.
- No implicit `Any`. If you need `Any`, write it explicitly with a comment explaining why.

**Error handling:**
- No bare `except`. No `except Exception` without re-raise (top-level CLI is the only exception).
- No swallowed exceptions. Every `except` clause re-raises, logs with structured context, or transforms into a domain error.
- No `print()` for errors. Use the project logger.

**Imports:**
- No conditional imports inside functions without a documented reason.
- Standard library, then third-party, then first-party, with blank lines between groups.
- No `from x import *`. Ever.
- No relative imports across modules. Absolute imports only.

**Comments and docstrings:**
- Every public class and function has a Google-style docstring with Args, Returns, Raises where applicable.
- No commented-out code.
- Comments explain *why*, not *what*.
- No `# TODO` without a tracking issue or `# TODO(reason): description` format.
- No `# noqa` without a specific rule code and a comment explaining why.

**Subprocess discipline:**
- All OpenSSL subprocess calls live only in `scanners/tls/openssl_probe.py`. No exceptions.
- `subprocess.run` with args as a list, `shell=False`, explicit `timeout`, `capture_output=True`, `check=False`.
- No `os.system`. No `shell=True`.

**Security hygiene:**
- No `eval()`, `exec()`, `pickle.loads()` on untrusted input.
- No `verify=False` or `ssl.CERT_NONE`. A bad certificate is a finding, not a workaround.
- No logging of secrets, private keys, full PEMs, full traces, full certificate bodies.
- All user-supplied paths resolved via `pathlib.Path.resolve()` and validated.

**Voice in code:**
- No marketing language in docstrings or comments. No "leverage," no "intersection of," no "robust enterprise-grade."
- No em dashes anywhere.
- No emoji.
- No ASCII art banners.

For every violation, either fix it before responding or mark it explicitly:

  `ANTIPATTERN ACCEPTED: <rule>, because <reason>`

The two known accepted antipatterns for this MVP are already documented in section 15A (CycloneDX-flavored fields on Asset/Finding). Anything else needs explicit justification.

================================================================================
25. DEFINITION OF DONE
================================================================================

Incomplete if any of these are true:
- `qureddy scan tls TARGET` does not execute a real OpenSSL subprocess
- JSON output lacks dependencies, evidence, or findings
- parser tests use only invented inline strings and no fixture files
- live tests are absent
- any of the 6 use cases in section 0B has no corresponding test
- OpenSSL missing/old/lacking-group paths crash instead of returning structured output
- logs appear on stdout
- scan results appear on stderr
- any created module is unused by command path or tests
- TODO placeholders exist for MVP behavior
- `sslyze`, `nassl`, `cryptography` appear in runtime dependencies
- SQLite, CBOM, YAML policy loading, or `Dockerfile` appear

================================================================================
26. FINAL RESPONSE FORMAT
================================================================================

1. What you implemented.
2. Files created or changed.
3. Commands run and exact results.
4. Live test results for every target in `tests/live/test_live_targets.py`.
5. Anti-pattern audit result, including the `ANTIPATTERN ACCEPTED:` for CycloneDX-flavored model fields.
6. What you intentionally did not implement because it is out of MVP 0.1 scope.
7. Assumptions and open questions.

Do not end with generic "let me know" language. Do not add marketing copy. Do not over-explain.
