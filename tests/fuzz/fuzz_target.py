# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for ``parse_target`` (issue #86, #37).

Feeds arbitrary text to :func:`qureddy.core.targets.parse_target` and asserts
it either returns a normalized ``ScanTarget`` or raises only its declared
``TargetParseError`` -- never an unhandled crash. Any other exception (for
example a Pydantic ``ScanTarget`` validation error escaping the parser) is a
genuine finding and is left to propagate to libFuzzer.

Run with the ``fuzz`` optional dependency group; see ``tests/fuzz/README.md``.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext

try:
    import atheris
except ImportError:  # pragma: no cover - atheris is an optional fuzz-only dependency
    atheris = None

# Instrument the module under test for coverage-guided fuzzing when atheris is
# present; fall back to a no-op context so the file stays importable in a normal
# dev environment where atheris is not installed.
_instrument = atheris.instrument_imports() if atheris is not None else nullcontext()
with _instrument:
    from qureddy.core.errors import TargetParseError
    from qureddy.core.targets import parse_target


def TestOneInput(data: bytes) -> None:  # noqa: N802 - atheris entrypoint naming
    """Drive ``parse_target`` with one fuzzed input string."""
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    try:
        target = parse_target(raw)
    except TargetParseError:
        return
    assert target.host, "parse_target returned a target with an empty host"
    assert target.locator.startswith("tls://"), "unexpected TLS locator scheme"


def main() -> None:
    """Register the harness with libFuzzer and start fuzzing."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
