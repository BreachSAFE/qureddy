# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for ``parse_ssh_target`` (issue #86, #37).

Feeds arbitrary text to :func:`qureddy.core.targets.parse_ssh_target` and
asserts it either returns a normalized ``ssh://`` ``ScanTarget`` or raises only
its declared ``TargetParseError`` -- never an unhandled crash. Any other
exception is left to propagate to libFuzzer as a finding.

Run with the ``fuzz`` optional dependency group; see ``tests/fuzz/README.md``.
"""

from __future__ import annotations

import sys
from contextlib import nullcontext

try:
    import atheris
except ImportError:  # pragma: no cover - atheris is an optional fuzz-only dependency
    atheris = None

_instrument = atheris.instrument_imports() if atheris is not None else nullcontext()
with _instrument:
    from qureddy.core.errors import TargetParseError
    from qureddy.core.targets import parse_ssh_target


def TestOneInput(data: bytes) -> None:  # noqa: N802 - atheris entrypoint naming
    """Drive ``parse_ssh_target`` with one fuzzed input string."""
    fdp = atheris.FuzzedDataProvider(data)
    raw = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    try:
        target = parse_ssh_target(raw)
    except TargetParseError:
        return
    assert target.host, "parse_ssh_target returned a target with an empty host"
    assert target.locator.startswith("ssh://"), "unexpected SSH locator scheme"


def main() -> None:
    """Register the harness with libFuzzer and start fuzzing."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
