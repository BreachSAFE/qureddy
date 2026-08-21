# SPDX-FileCopyrightText: 2026 Paul Volosen <paulvolosen@gmail.com>
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for the certificate-signature classifier (issue #86).

Feeds arbitrary text (the class of untrusted ``openssl x509 -text`` stdout the
scanner parses) to
:func:`qureddy.scanners.tls.cert_sig.parse_certificate_signature`. That parser
is total by contract -- it never raises, returning a ``CertSignature`` for any
input -- so the harness asserts that invariant and the internal consistency of
the post-quantum classification for every input.

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
    from qureddy.scanners.tls.cert_sig import (
        CertSignature,
        parse_certificate_signature,
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 - atheris entrypoint naming
    """Drive ``parse_certificate_signature`` with fuzzed x509 text."""
    fdp = atheris.FuzzedDataProvider(data)
    x509_text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    result = parse_certificate_signature(x509_text)
    assert isinstance(result, CertSignature), "parser returned a non-CertSignature"
    # A post-quantum classification must be fully populated; a classical or
    # undetermined one must not claim a canonical name / OID / level.
    if result.is_post_quantum:
        assert result.canonical_name is not None, "PQC result missing canonical name"
        assert result.oid is not None, "PQC result missing OID"
        assert result.nist_level in {1, 2, 3, 5}, "PQC result has an invalid NIST level"
    else:
        assert result.canonical_name is None, "non-PQC result leaked a canonical name"


def main() -> None:
    """Register the harness with libFuzzer and start fuzzing."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
