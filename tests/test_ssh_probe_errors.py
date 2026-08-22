# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hostile/degraded SSH read paths (issue #109).

Covers ssh/probe.py:81-82, 96-97, 101-102, 116-117, 123-124 -- the
connection-closed, oversized-banner, invalid-padding, and truncated-namelist
error branches. Every byte from an SSH endpoint is untrusted, so these are the
branches that decide whether a malformed peer degrades to a typed SSHProbeError
or crashes the scan.

Hermetic: a one-shot loopback (127.0.0.1) server replays fixed bytes; no
network. The server sends its canned bytes, then lingers briefly before closing
so the client's own banner write is buffered and its reads come from the local
TCP buffer deterministically.
"""

from __future__ import annotations

import socket
import struct
import threading
from contextlib import suppress

import pytest

from qureddy.core.errors import SSHProbeError
from qureddy.scanners.ssh.probe import (
    _read_packet_payload,
    _validate_packet_framing,
    read_kexinit_offer,
)

_BANNER = b"SSH-2.0-test\r\n"


class _ReplaySocket:
    """A minimal read-only socket that serves a fixed byte buffer to ``recv``.

    Mirrors the in-memory socket used by the SSH fuzz harness
    (``tests/fuzz/fuzz_ssh_kexinit.py``) so the pure packet-framing path can be
    exercised without any network I/O.
    """

    def __init__(self, payload: bytes) -> None:
        self._buffer = memoryview(payload)
        self._offset = 0

    def recv(self, size: int) -> bytes:
        chunk = self._buffer[self._offset : self._offset + size]
        self._offset += len(chunk)
        return bytes(chunk)


def _serve_bytes(data: bytes, *, close_delay: float = 0.3) -> int:
    """Replay `data` on a fresh loopback port, then close after `close_delay`.

    The delay lets the client finish reading its buffered bytes (and write its
    own banner into the kernel buffer) before the server EOFs, so a
    "connection closed" branch fires deterministically rather than racing.
    """
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run() -> None:
        conn, _ = srv.accept()
        try:
            with suppress(OSError):
                conn.sendall(data)
            # Drain whatever the client writes (its own banner) before closing,
            # so the close is a clean FIN (-> EOF on the client's read) rather
            # than an RST from unread data (-> "connection reset" on its write).
            conn.settimeout(close_delay)
            with suppress(OSError):
                while conn.recv(4096):
                    pass
        finally:
            conn.close()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _frame(payload: bytes) -> bytes:
    """Wrap a KEXINIT payload in valid RFC 4253 §6 binary-packet framing.

    Picks a padding length of 4..255 bytes such that ``(packet_length + 4)`` is a
    multiple of the 8-byte block size, so the frame reaches the name-list parser
    rather than tripping the packet-framing guard.
    """
    pad_len = -(len(payload) + 5) % 8
    if pad_len < 4:
        pad_len += 8
    body = bytes([pad_len]) + payload + b"\x00" * pad_len
    return struct.pack(">I", len(body)) + body


def test_closed_before_banner_raises_typed_error() -> None:
    """Server sends nothing and closes: the byte-at-a-time banner read must
    raise SSHProbeError, not hang or crash (probe.py:96-97)."""
    port = _serve_bytes(b"")
    with pytest.raises(SSHProbeError, match="closed before banner"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_oversized_banner_rejected() -> None:
    """A banner with no newline that runs past the 8192-byte bound is rejected
    fast, not read unboundedly (probe.py:100-102)."""
    port = _serve_bytes(b"A" * (8192 + 1))
    with pytest.raises(SSHProbeError, match="banner exceeded bound"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_connection_closed_mid_packet_raises() -> None:
    """A valid banner then a packet-length header with no body: the bounded
    read must raise on EOF mid-packet (probe.py:80-82)."""
    port = _serve_bytes(_BANNER + struct.pack(">I", 50))
    with pytest.raises(SSHProbeError, match="closed mid-packet"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_invalid_padding_length_rejected() -> None:
    """A packet whose declared padding is >= the packet length is malformed and
    must be rejected before slicing the payload (probe.py:115-117)."""
    # pkt_len == 4, pad_len == 200 -> pad_len >= pkt_len.
    bad_packet = struct.pack(">I", 4) + bytes([200, 0, 0, 0])
    port = _serve_bytes(_BANNER + bad_packet)
    with pytest.raises(SSHProbeError, match="invalid SSH padding length"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_truncated_namelist_length_field_rejected() -> None:
    """A KEXINIT payload that ends right after the 16-byte cookie -- too short
    for even the first name-list length field -- is rejected (probe.py:122-124),
    distinct from the already-tested name-list-body truncation."""
    payload = bytes([20]) + b"\x00" * 16  # SSH_MSG_KEXINIT + cookie, nothing more
    port = _serve_bytes(_BANNER + _frame(payload))
    with pytest.raises(SSHProbeError, match="truncated KEXINIT"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def _raw_packet(pkt_len: int, body: bytes) -> bytes:
    """A packet with an explicit length header and raw body (may be malformed)."""
    return struct.pack(">I", pkt_len) + body


def test_zero_padding_length_rejected() -> None:
    """RFC 4253 §6 requires at least 4 bytes of padding; pad_len=0 on an
    otherwise well-aligned packet is malformed and must be rejected."""
    # pkt_len=4 -> (4+4)%8==0 (aligned); body[0]=0 -> pad_len below the 4-byte floor.
    sock = _ReplaySocket(_raw_packet(4, bytes([0, 1, 2, 3])))
    with pytest.raises(SSHProbeError, match="invalid SSH padding length"):
        _read_packet_payload(sock)


def test_oversized_padding_length_rejected() -> None:
    """Padding above the 255-byte ceiling is malformed. A single length byte can
    never exceed 255 on the wire, so the framing validator is exercised directly
    to prove the upper bound is enforced (RFC 4253 §6)."""
    # pkt_len=260 -> (260+4)%8==0 (aligned) so the padding-range check is reached.
    with pytest.raises(SSHProbeError, match="invalid SSH padding length"):
        _validate_packet_framing(pkt_len=260, pad_len=256)


def test_misaligned_packet_length_rejected() -> None:
    """(packet_length + 4) must be a multiple of the 8-byte block size; a
    misaligned packet is malformed even if its padding byte looks sane."""
    # pkt_len=5 -> (5+4)%8==1 (misaligned); pad_len byte (4) is otherwise valid.
    sock = _ReplaySocket(_raw_packet(5, bytes([4, 0, 0, 0, 0])))
    with pytest.raises(SSHProbeError, match="misaligned SSH packet length"):
        _read_packet_payload(sock)


def test_negative_payload_length_rejected() -> None:
    """payload = packet_length - pad_len - 1 must be >= 0; padding that consumes
    more than the packet body yields a negative payload and must be rejected."""
    # pkt_len=12 (aligned), pad_len=200 in the 4..255 range -> payload 12-200-1 < 0.
    sock = _ReplaySocket(_raw_packet(12, bytes([200]) + b"\x00" * 11))
    with pytest.raises(SSHProbeError, match="invalid SSH padding length"):
        _read_packet_payload(sock)


def test_wellformed_packet_parses() -> None:
    """A well-formed, aligned packet with valid padding still returns exactly its
    payload bytes -- the fix must not change the contract for good input."""
    payload = b"payload-content"  # 15 bytes
    sock = _ReplaySocket(_frame(payload))
    assert _read_packet_payload(sock) == payload
