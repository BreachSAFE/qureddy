# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression: an SSH peer-close (clean EOF) is a connectivity failure (#244).

A closed connection surfaced as ``SSHProbeError`` with no ``OSError`` cause, so
``build_ssh_failure_result`` classified it ``PARSE_AMBIGUOUS`` instead of
``TARGET_CONNECT_FAILED``. The probe now chains a ``ConnectionError`` at the two
EOF sites; ``build_ssh_failure_result`` already maps an ``OSError`` cause to
``TARGET_CONNECT_FAILED``, so the cause is the load-bearing signal.
"""

from __future__ import annotations

import pytest

from qureddy.scanners.ssh.probe import SSHProbeError, _read_banner, _recvn


class _ClosedSocket:
    """A socket whose peer has closed: every recv returns b'' (clean EOF)."""

    def recv(self, _n: int) -> bytes:
        return b""


def test_recvn_peer_close_chains_oserror() -> None:
    with pytest.raises(SSHProbeError) as excinfo:
        _recvn(_ClosedSocket(), 4)  # type: ignore[arg-type]
    # An OSError cause is what routes this to TARGET_CONNECT_FAILED (#244).
    assert isinstance(excinfo.value.__cause__, OSError)


def test_read_banner_peer_close_chains_oserror() -> None:
    with pytest.raises(SSHProbeError) as excinfo:
        _read_banner(_ClosedSocket())  # type: ignore[arg-type]
    assert isinstance(excinfo.value.__cause__, OSError)
