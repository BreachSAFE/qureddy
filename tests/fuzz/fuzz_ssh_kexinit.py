# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harness for the SSH KEXINIT wire parser (issue #86).

The SSH probe reads an untrusted server's cleartext ``SSH_MSG_KEXINIT`` off a
raw socket. This harness exercises the pure byte-parsing core of that path --
packet framing (:func:`_read_packet_payload`, length/padding bounds) and
name-list decoding (:func:`_parse_kexinit`) -- by replaying fuzzed bytes
through an in-memory socket. No network I/O is performed.

The parser must either return two name lists or raise only its declared
``SSHProbeError``; any other exception is left to propagate as a finding.

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
    from qureddy.core.errors import SSHProbeError
    from qureddy.scanners.ssh.probe import (
        _parse_kexinit as parse_kexinit,
    )
    from qureddy.scanners.ssh.probe import (
        _read_packet_payload as read_packet_payload,
    )


class _ReplaySocket:
    """A minimal read-only socket that serves a fixed byte buffer to ``recv``."""

    def __init__(self, payload: bytes) -> None:
        self._buffer = memoryview(payload)
        self._offset = 0

    def recv(self, size: int) -> bytes:
        """Return up to ``size`` buffered bytes, or ``b""`` once exhausted."""
        chunk = self._buffer[self._offset : self._offset + size]
        self._offset += len(chunk)
        return bytes(chunk)


def TestOneInput(data: bytes) -> None:  # noqa: N802 - atheris entrypoint naming
    """Replay fuzzed bytes through the SSH packet/name-list parser."""
    sock = _ReplaySocket(data)
    try:
        payload = read_packet_payload(sock)
        kex, host_keys = parse_kexinit(payload)
    except SSHProbeError:
        return
    assert isinstance(kex, list), "kex algorithms must be a list"
    assert isinstance(host_keys, list), "host-key algorithms must be a list"


def main() -> None:
    """Register the harness with libFuzzer and start fuzzing."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
