# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Degraded-subprocess paths in the legacy TLS cipher sweep (issue #109, #246).

Covers legacy_probe.py:175-180, 212, 214, 251, 297-298 -- the timeout /
missing-binary handling in `_run_openssl`, the "we don't know" (timed-out)
versus "confirmed empty" distinction in `_candidate_ciphers`, the nonzero /
empty candidate list, and the mid-sweep handshake timeout that must mark the
whole protocol result `probe_incomplete` rather than a clean negative.

Hermetic: `subprocess.run` is injected; no OpenSSL binary and no network.
"""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from qureddy.core.errors import LocalOpenSSLBroken, LocalOpenSSLMissing
from qureddy.scanners.tls.legacy_probe import probe_legacy_protocol

# #296: subprocess execution now lives only in the executor; legacy_probe
# routes through it, so that is the seam to inject.
_RUN = "qureddy.scanners.tls.openssl_probe.executor.subprocess.run"


def _completed(returncode: int, stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(
        args=["openssl"], returncode=returncode, stdout=stdout, stderr=""
    )


def _probe() -> object:
    return probe_legacy_protocol(
        "/fixture/openssl", "192.0.2.1", 443, None, "-tls1", "TLSv1", timeout_seconds=5
    )


def test_candidate_timeout_marks_probe_incomplete_not_offered() -> None:
    """A subprocess timeout while listing candidate ciphers is a "we don't
    know" outcome (legacy_probe.py:175-177, 211-212) -- the result must be
    probe_incomplete, distinct from a confirmed "server offers nothing"."""
    with patch(_RUN, side_effect=subprocess.TimeoutExpired(cmd=["openssl"], timeout=5)):
        result = _probe()
    assert result.probe_incomplete is True
    assert result.offered is False
    assert result.accepted_ciphers == ()


def test_missing_openssl_raises_local_openssl_missing() -> None:
    """FileNotFoundError from the candidate sweep is remapped to the typed
    local-dependency error (legacy_probe.py:178-180), not a raw traceback."""
    with (
        patch(_RUN, side_effect=FileNotFoundError("no such file")),
        pytest.raises(LocalOpenSSLMissing),
    ):
        _probe()


def test_unlaunchable_openssl_raises_local_openssl_broken() -> None:
    """#296/#374: an OSError launching openssl (non-executable / WinError 193)
    was previously UNCAUGHT in legacy_probe and crashed the sweep. It must now
    surface as the typed exit-3 local-dependency error."""
    with (
        patch(_RUN, side_effect=OSError(193, "not a valid application")),
        pytest.raises(LocalOpenSSLBroken),
    ):
        _probe()


def test_nonzero_candidate_exit_is_confirmed_empty_not_incomplete() -> None:
    """A clean nonzero exit (or empty stdout) from `openssl ciphers` is a
    confirmed "no candidates" answer, not a timeout (legacy_probe.py:213-214):
    offered False AND probe_incomplete False."""
    with patch(_RUN, return_value=_completed(1)):
        result = _probe()
    assert result.offered is False
    assert result.probe_incomplete is False


def test_handshake_timeout_mid_sweep_marks_incomplete() -> None:
    """Candidates enumerate fine, then the first handshake times out: the sweep
    must stop and mark the protocol incomplete (legacy_probe.py:251, 297-298),
    never report a clean "not offered"."""
    responses = [
        _completed(0, stdout="AES128-SHA:AES256-SHA"),  # _candidate_ciphers
        subprocess.TimeoutExpired(cmd=["openssl"], timeout=5),  # first handshake
    ]
    with patch(_RUN, side_effect=responses):
        result = _probe()
    assert result.probe_incomplete is True
    assert result.offered is False
    assert result.accepted_ciphers == ()
