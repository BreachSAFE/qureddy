# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for the OpenSSL ``s_client -brief`` parser (issue #86).

Feeds arbitrary text (the class of untrusted subprocess stdout the scanner
parses) to :func:`qureddy.scanners.tls.parse.parse_brief_output`. That parser
is total by contract -- it never raises, returning a ``ParsedNegotiation`` for
any input -- so the harness asserts that invariant holds for every input.

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
    from qureddy.scanners.tls.parse import ParsedNegotiation, parse_brief_output


def TestOneInput(data: bytes) -> None:  # noqa: N802 - atheris entrypoint naming
    """Drive ``parse_brief_output`` with a fuzzed expected-group and stdout."""
    fdp = atheris.FuzzedDataProvider(data)
    expected_group = fdp.ConsumeUnicodeNoSurrogates(32)
    stdout = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    result = parse_brief_output(stdout, expected_group=expected_group)
    assert isinstance(result, ParsedNegotiation), "parser returned a non-ParsedNegotiation"


def main() -> None:
    """Register the harness with libFuzzer and start fuzzing."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
