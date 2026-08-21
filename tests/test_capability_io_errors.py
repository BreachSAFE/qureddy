# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Capability-probe I/O and result-boundary error paths (issue #109).

Covers openssl_probe/_capability_io.py:37, 46-52, 78-79, 89-90 -- the
missing-binary and timeout branches of `run_openssl`, and the InvalidVersion
guards in `extract_version` / `extract_library_version`; plus
openssl_probe/_results.py:96, 99 -- `decode_partial` for the None and
already-decoded-str cases.

Hermetic: `subprocess.run` is injected; no OpenSSL binary and no network.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.scanners.tls.openssl_probe._capability_io import (
    extract_library_version,
    extract_version,
    run_openssl,
)
from qureddy.scanners.tls.openssl_probe._results import decode_partial

_RUN = "qureddy.scanners.tls.openssl_probe._capability_io.subprocess.run"


class TestRunOpensslErrors:
    """_capability_io.py:37, 46-52 -- typed exit-3 remaps for local failures."""

    def test_missing_binary_raises_local_openssl_missing(self) -> None:
        with (
            patch(_RUN, side_effect=FileNotFoundError("no such file")),
            pytest.raises(LocalOpenSSLMissing),
        ):
            run_openssl(["/nonexistent/openssl", "version"], timeout_seconds=5)

    def test_timeout_raises_local_openssl_broken_with_dependency(self) -> None:
        """A binary that exists but hangs during the capability check is a
        LocalOpenSSLBroken (exit-3 surface), carrying the dependency record."""
        with (
            patch(_RUN, side_effect=subprocess.TimeoutExpired(cmd=["openssl"], timeout=5)),
            pytest.raises(LocalOpenSSLBroken) as excinfo,
        ):
            run_openssl(["/usr/bin/openssl", "version"], timeout_seconds=5)
        assert "unresponsive" in str(excinfo.value)


class TestVersionExtractionInvalidVersion:
    """_capability_io.py:78-79, 89-90 -- a banner that matches the version
    regex but is not a parseable version resolves to None, never raises."""

    def test_extract_version_invalid_returns_none(self) -> None:
        # Matches the OpenSSL release-fragment regex but `Version()` rejects it.
        assert extract_version("OpenSSL 1.2.3-foo built on ...") is None

    def test_extract_library_version_invalid_returns_none(self) -> None:
        assert extract_library_version("(Library: OpenSSL 1.2.3-foo)") is None


class TestDecodePartial:
    """_results.py:94-99 -- partial-byte decoding for the timeout ProbeResult."""

    def test_none_decodes_to_empty_string(self) -> None:
        assert decode_partial(None) == ""

    def test_already_decoded_str_passes_through(self) -> None:
        assert decode_partial("already text") == "already text"

    def test_bytes_are_utf8_decoded_with_replacement(self) -> None:
        # invalid byte -> U+FFFD replacement, never a UnicodeDecodeError
        assert decode_partial(b"ok\xff") == "ok�"
