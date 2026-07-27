# Code Examples — Good vs Bad

Side-by-side examples for the highest-frequency QuReddy code patterns. Read this **before writing the first file in a new module**. The first 5 files in any module set the precedent for everything that follows; this doc anchors that precedent.

This is companion material to `docs/contributors/coding-rules.md`. The rules document tells you *what* the standard is; this document shows you *what it looks like*.

---

## 1. Pydantic models

The active implementation skill in `.agents/skills/` defines the canonical model shape. This is the pattern for any new model.

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""Domain models for QuReddy core."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

FROZEN = ConfigDict(frozen=True, extra="forbid")


class ScanStatus(str, Enum):
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanRecord(BaseModel):
    """A single completed scan, immutable after construction."""

    model_config = FROZEN

    id: str
    target_locator: str
    status: ScanStatus
    started_at: datetime
    completed_at: datetime
    finding_count: int = Field(ge=0)
```

### Bad

```python
# Missing SPDX header
# Missing __future__ annotations
# Missing module docstring
import datetime  # wrong module
from pydantic import BaseModel  # missing ConfigDict, Field

class scan_record(BaseModel):  # wrong case (Rule 3.4)
    id: str
    target: str  # ambiguous name (Rule 3.6 / 4.4)
    status: str  # stringly-typed where Enum belongs (Rule 4.5)
    started: datetime.datetime  # naive datetime (Rule 4.8)
    finding_count: int  # no constraint
    # No model_config — accepts arbitrary extra fields, mutable by default
    # No docstring (Rule 10.1)
```

### Why

- `from __future__ import annotations` enables forward references; required everywhere (Rule 4.3).
- SPDX header required by `reuse lint` and OpenSSF criterion.
- `model_config = FROZEN` → models are immutable and reject unknown fields. Catches typos at construction (Rule 4.7).
- `Enum` for fixed vocabularies, never `str` (Rule 4.5).
- Datetimes are timezone-aware UTC; the model declares `datetime` and the construction-site uses `datetime.now(timezone.utc)` (Rule 4.8).
- `Field(ge=0)` validates at the boundary — invalid input fails at model construction, not at use site (Rule 5.6 trust-boundary validation).

---

## 2. pytest tests

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""Tests for ScanTarget normalization."""
from __future__ import annotations

import pytest

from qureddy.core.errors import TargetParseError
from qureddy.core.targets import parse_target


class TestParseTargetHostname:
    """Hostname inputs should produce SNI = host."""

    def test_bare_hostname_uses_default_port(self) -> None:
        result = parse_target("example.com")
        assert result.host == "example.com"
        assert result.port == 443
        assert result.sni == "example.com"

    def test_hostname_with_port_keeps_port(self) -> None:
        result = parse_target("example.com:8443")
        assert result.host == "example.com"
        assert result.port == 8443
        assert result.sni == "example.com"


class TestParseTargetIP:
    """IP inputs should produce SNI = None unless overridden."""

    def test_ip_alone_has_no_sni(self) -> None:
        result = parse_target("1.2.3.4:443")
        assert result.host == "1.2.3.4"
        assert result.sni is None

    def test_ip_with_sni_override_uses_override(self) -> None:
        result = parse_target("1.2.3.4:443", sni_override="example.com")
        assert result.sni == "example.com"


class TestParseTargetInvalid:
    """Invalid inputs raise TargetParseError."""

    @pytest.mark.parametrize(
        "bad_input",
        [
            "",
            "   ",
            "not a url",
            ":443",
            "example.com:99999",
        ],
    )
    def test_invalid_inputs_raise(self, bad_input: str) -> None:
        with pytest.raises(TargetParseError):
            parse_target(bad_input)
```

### Bad

```python
# Missing SPDX, missing __future__
import pytest
from qureddy.core.targets import parse_target

def test_targets():  # name says nothing (Rule 9.8)
    """test target parsing"""
    result = parse_target("example.com")
    assert result  # asserts nothing meaningful (Rule 9.10 spirit)

def test_more():
    # mixed concerns: valid + invalid in one test (Rule 9.7)
    assert parse_target("example.com").port == 443
    try:
        parse_target("")
    except:  # bare except (Rule 6.3)
        pass

@pytest.mark.parametrize("inp,expected", [
    ("example.com", 443),       # valid case
    ("", "raises"),             # invalid case mixed in (Rule 9.9)
    ("1.2.3.4:443", 443),       # different concern (SNI not tested)
])
def test_parametrize_misuse(inp, expected):
    if expected == "raises":
        with pytest.raises(Exception):  # broad catch (Rule 6.3)
            parse_target(inp)
    else:
        assert parse_target(inp).port == expected
```

### Why

- Test names describe what they verify (Rule 9.8). `test_bare_hostname_uses_default_port` tells you what's being tested without reading the body.
- One concept per test (Rule 9.7). The "invalid inputs" parametrize is fine because every case verifies the same concept (raises `TargetParseError`).
- `pytest.raises(SpecificException)`, not bare `except` (Rule 6.3).
- Class organization groups tests by behavior. Optional but helps when the test file grows past 100 lines.

---

## 3. Subprocess calls (OpenSSL probe)

OpenSSL subprocess calls live **only** in `src/qureddy/scanners/tls/openssl_probe.py` (Rule 7.1).

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""OpenSSL 3.6.3+ subprocess probe for TLS scans."""
from __future__ import annotations

import hashlib
import subprocess
from datetime import datetime, timezone

from qureddy.core.errors import LocalOpenSSLMissing, TLSHandshakeFailed
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    FailureCategory, ProbeCommand, ProbeResult,
)

log = get_logger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30


def run_hybrid_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> ProbeResult:
    """Run X25519MLKEM768 probe against host:port. Returns ProbeResult."""
    args = _build_probe_args(openssl_path, host, port, sni, group="X25519MLKEM768")
    return _run_subprocess(args, timeout_seconds)


def _build_probe_args(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    group: str,
) -> list[str]:
    args = [
        openssl_path, "s_client",
        "-connect", f"{host}:{port}",
        "-tls1_3",
        "-groups", group,
        "-brief",
    ]
    if sni is not None:
        args.extend(["-servername", sni])
    return args


def _run_subprocess(args: list[str], timeout_seconds: int) -> ProbeResult:
    started = datetime.now(timezone.utc)
    log.info(
        "subprocess.start",
        executable=args[0],
        arg_count=len(args),
        timeout_seconds=timeout_seconds,
    )

    try:
        completed = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        raise TLSHandshakeFailed(
            f"OpenSSL timed out after {timeout_seconds}s"
        ) from None
    except FileNotFoundError as e:
        raise LocalOpenSSLMissing(str(e)) from e

    duration_ms = int(
        (datetime.now(timezone.utc) - started).total_seconds() * 1000
    )
    log.info(
        "subprocess.complete",
        return_code=completed.returncode,
        duration_ms=duration_ms,
    )

    return ProbeResult(
        command=ProbeCommand(
            executable=args[0],
            args=tuple(args[1:]),
            timeout_seconds=timeout_seconds,
        ),
        return_code=completed.returncode,
        stdout_sha256=hashlib.sha256(completed.stdout.encode()).hexdigest(),
        stderr_sha256=hashlib.sha256(completed.stderr.encode()).hexdigest(),
        stdout_excerpt=completed.stdout[:500],
        stderr_excerpt=completed.stderr[:500],
        duration_ms=duration_ms,
    )
```

### Bad

```python
import os, subprocess  # no __future__, no SPDX

def probe(host, port, sni):  # no type hints, no docstring
    cmd = f"openssl s_client -connect {host}:{port} -servername {sni} -tls1_3 -groups X25519MLKEM768 -brief"
    print(f"Running: {cmd}")  # print in library code (Rule 8.7); also leaks command via stdout
    result = os.system(cmd)  # os.system (Rule 7.2); shell injection (Rule 7.3); no timeout (Rule 7.4); no capture (Rule 7.5)
    if result != 0:
        raise Exception("failed")  # bare Exception (Rule 6.1); no context (Rule 6.4)
    return result
```

### Why

- Args as a list, never shell string. `shell=False` always. (Rules 7.3, 7.4, 7.5, 7.6).
- Explicit `timeout=`. Hung subprocess = hung scanner (Rule 7.4).
- `check=False` then inspect returncode manually. `check=True` raises `CalledProcessError` and loses context (Rule 7.6).
- Catch specific exceptions (`subprocess.TimeoutExpired`, `FileNotFoundError`), not bare `except` (Rule 6.3).
- `raise X from e` to preserve the cause chain, or `from None` when the original is irrelevant (Rule 6.4).
- Hash subprocess output, log the hash; do not log the full output (Rule 7.7).
- Structured logging with k/v pairs, not f-string (Rule 8.3).

---

## 4. Structured logging

### Good

```python
log = get_logger(__name__)

log.info(
    "probe.start",
    target=target.locator,
    group="X25519MLKEM768",
    timeout_seconds=30,
)

log.warning(
    "probe.retry",
    target=target.locator,
    attempt_number=attempt + 1,
    failure_category=failure.value,
    delay_seconds=retry_delay,
)
```

### Bad

```python
log = get_logger(__name__)

log.info(f"starting probe on {target.locator} with X25519MLKEM768")  # f-string (Rule 8.3)
log.info("probe.start", target.locator)  # positional, not k/v
print(f"DEBUG: about to retry {target.locator}")  # print in library code (Rule 8.7)
log.error("retrying anyway")  # ERROR level for a normal retry (Rule 8.4)
log.info(f"got back {full_subprocess_stdout}")  # logging full subprocess output (Rule 8.5, 7.7)
```

### Why

- K/V pairs are searchable (`grep target=example.com:443 logs.json`). F-strings are not.
- Event names are dotted (`probe.start`, `probe.complete`, `probe.retry`, `parse.success`, `parse.failure`). Consistent vocabulary across modules.
- Levels match meaning: WARNING for recoverable, ERROR for scan-fatal, INFO for milestones (Rule 8.4).
- Never log secrets, full PEMs, full subprocess output (Rules 8.5, 7.7).

---

## 5. Custom exceptions

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""Domain-specific exception hierarchy."""
from __future__ import annotations


class QureddyError(Exception):
    """Base class for all QuReddy errors."""


class LocalOpenSSLMissing(QureddyError):
    """OpenSSL binary not found at any expected path."""


class LocalOpenSSLTooOld(QureddyError):
    """OpenSSL found but version is below 3.6.3.

    Raised by the capability check. Maps to FailureCategory.LOCAL_OPENSSL_TOO_OLD.
    """


class TargetParseError(QureddyError):
    """User input could not be parsed into a valid ScanTarget."""


class TLSHandshakeFailed(QureddyError):
    """TLS handshake failed.

    Distinct from TargetConnectFailed: the TCP connection succeeded but
    the TLS handshake did not complete. Maps to FailureCategory.TLS_HANDSHAKE_FAILED.
    """
```

### Bad

```python
class QureddyException(Exception): pass  # "Exception" suffix is redundant (Python convention)

class OpenSSLError(QureddyException):
    """error"""  # docstring says nothing (Rule 10.1)

# All errors collapsed to one type:
def find_openssl() -> str:
    if not path:
        raise OpenSSLError("openssl missing")
    if version < "3.6.3":
        raise OpenSSLError("openssl old")  # caller can't tell these apart (Rule 6.1)
```

### Why

- Specific exception types let callers handle different failure modes differently (Rule 6.1).
- Every public class has a docstring (Rule 10.1). Docstrings document *intent*, not the type hint (Rule 10.6).
- Map exceptions to `FailureCategory` enum values explicitly so the policy module can classify findings.

---

## 6. Docstrings

### Good

```python
def parse_target(input_str: str, sni_override: str | None = None) -> ScanTarget:
    """Parse a user-supplied target string into a normalized ScanTarget.

    Args:
        input_str: User input. Accepts hostname, host:port, https URL, or IP.
        sni_override: Optional SNI override. Required for IP targets that
            need to address a specific virtual host.

    Returns:
        Normalized ScanTarget with locator format `tls://host:port`.

    Raises:
        TargetParseError: If input cannot be parsed into a valid target.
    """
```

### Bad

```python
def parse_target(input_str, sni_override=None):
    """
    Args:
        input_str (str): the input string (a string)
        sni_override (str | None): optional SNI override, defaults to None

    Returns:
        ScanTarget: the result
    """
    # missing Raises
    # repeats type hints in prose (Rule 10.6)
    # describes what types are, not what they mean
```

### Why

- Docstring documents *intent*, not types. The signature already documents types (Rule 10.6).
- Args/Returns/Raises sections required where applicable (Rule 10.1).
- Google style throughout. Pick one style and stick with it.

---

## 7. CLI command body (Typer)

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""Typer CLI entry point for the qureddy command."""
from __future__ import annotations

import sys

import typer

from qureddy.core.errors import (
    LocalOpenSSLLacksGroup, LocalOpenSSLMissing, LocalOpenSSLTooOld,
    QureddyError, TargetParseError,
)
from qureddy.core.logging import configure_logging
from qureddy.core.targets import parse_target
from qureddy.output.console import render_rich
from qureddy.output.json import render_json
from qureddy.scanners.tls.scanner import TLSScanner

app = typer.Typer(help="QuReddy — post-quantum TLS readiness scanner.")
scan = typer.Typer(help="Run scans.")
app.add_typer(scan, name="scan")


@scan.command("tls")
def scan_tls(
    target: str = typer.Argument(..., help="Target to scan (host[:port])"),
    sni: str | None = typer.Option(None, help="SNI override (required for IP targets)"),
    openssl: str | None = typer.Option(None, "--openssl", help="Path to openssl binary"),
    output_format: str = typer.Option("rich", "--format", help="rich | json"),
    timeout: int = typer.Option(30, help="Per-probe timeout in seconds"),
    verbose: int = typer.Option(0, "-v", count=True, help="Verbosity (-v/-vv/-vvv)"),
    json_logs: bool = typer.Option(False, "--json-logs"),
    quiet: bool = typer.Option(False, "-q", "--quiet"),
) -> None:
    """Scan a TLS endpoint for post-quantum readiness."""
    configure_logging(verbosity=verbose, json_logs=json_logs, quiet=quiet)

    try:
        scan_target = parse_target(target, sni_override=sni)
    except TargetParseError as e:
        typer.echo(f"qureddy: invalid target: {e}", err=True)
        raise typer.Exit(code=4)

    try:
        result = TLSScanner(openssl_path=openssl).scan(scan_target, timeout_seconds=timeout)
    except (LocalOpenSSLMissing, LocalOpenSSLTooOld, LocalOpenSSLLacksGroup) as e:
        typer.echo(f"qureddy: local openssl problem: {e}", err=True)
        raise typer.Exit(code=3)
    except QureddyError as e:
        typer.echo(f"qureddy: scan failed: {e}", err=True)
        raise typer.Exit(code=2)

    if output_format == "json":
        render_json(result, sys.stdout)
    else:
        render_rich(result, sys.stdout)
```

### Bad

```python
import typer
from qureddy.scanners.tls.scanner import TLSScanner

app = typer.Typer()

@app.command()
def scan(target: str, sni: str = None, fmt: str = "rich"):  # cryptic name "fmt" (Rule 3.2)
    print(f"scanning {target}")  # print on stdout mixed with output (Rule 8.2)
    try:
        result = TLSScanner().scan(target)  # passing raw string, not ScanTarget
    except Exception as e:  # broad catch eats KeyboardInterrupt (Rule 6.2)
        print(f"error: {e}")
        return  # silently exits 0 on error (Rule 11.3)
    print(result)  # print stdout (correct in CLI but no formatting)
```

### Why

- Exit codes are deliberate: 0/2/3/4 distinguished (Rule 11.3).
- Errors go to `stderr` via `typer.echo(..., err=True)`; output goes to `stdout` via the renderers (Rule 11.1).
- Catch specific exceptions, not bare `Exception`. The CLI top-level is the one place where `QureddyError` (the base class) is acceptable to catch (Rule 6.5).
- The CLI module is the trust boundary that reads environment/argv and passes typed values down. Library code does not call `os.getenv` (Rule 5.6).

---

## 8. JSON output

Use `model.model_dump(mode="json")`. Do not hand-build dicts.

### Good

```python
# SPDX-License-Identifier: Apache-2.0
"""JSON output adapter."""
from __future__ import annotations

import json
import sys
from typing import IO

from qureddy.core.models import ScanResult


def render_json(result: ScanResult, stream: IO[str] = sys.stdout) -> None:
    """Render a ScanResult as JSON to the given stream.

    Uses Pydantic's model_dump(mode="json") for stable serialization.
    Top-level keys appear in the order defined by the ScanResult model.
    """
    payload = result.model_dump(mode="json")
    json.dump(payload, stream, indent=2, sort_keys=False)
    stream.write("\n")
```

### Bad

```python
def render_json(result):  # no types
    out = {}
    out["schema_version"] = "qureddy.scan.v1"  # hand-built; key order drifts
    out["scan"] = {"id": result.scan.scan_id, "started": str(result.scan.started_at)}  # naive str()
    out["target"] = {}
    for k in dir(result.target):  # introspection-driven serialization
        if not k.startswith("_"):
            out["target"][k] = getattr(result.target, k)
    out["evidence"] = [e.__dict__ for e in result.evidence]  # bypasses Pydantic
    print(json.dumps(out))  # print to stdout, no stream argument
```

### Why

- `model.model_dump(mode="json")` produces a stable, serializable dict that respects all the Pydantic field rules. Hand-built dicts drift (Rule 11.5).
- `sort_keys=False` preserves the model-declared field order, which is the public JSON schema contract (Rule 11.4).
- Output is written to a stream argument so tests can capture it (default `sys.stdout`).

---

## How to use this document

When you start writing a new file in MVP 0.1:

1. Find the section above that matches what you're writing (Pydantic model? subprocess call? CLI command?).
2. Read the **Why** explanation. The patterns aren't arbitrary — each one prevents a specific failure mode named in `docs/contributors/coding-rules.md`.
3. Write your code in the **Good** style. If your code starts to look like the **Bad** example, you have drifted; revisit the example.

When this document and `docs/contributors/coding-rules.md` disagree, the rules document wins. This document is illustration; the rules are authority.
