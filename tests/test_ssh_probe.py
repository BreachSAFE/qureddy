# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the SSH KEXINIT probe — hostile-server hardening + parsing.

Every byte from an SSH endpoint is untrusted (esp. a vendor SFTP host qureddy
does not control), so these tests focus on malformed/adversarial input, not
just the happy path.
"""

from __future__ import annotations

import contextlib
import socket
import struct
import threading
import time

import pytest

from qureddy.core.errors import SSHProbeError
from qureddy.scanners.ssh.probe import read_kexinit_offer


def _serve(behavior, *, banner: bytes = b"SSH-2.0-test\r\n", coalesce: bytes = b"") -> int:
    """Start a one-shot fake SSH server on a random port; return the port."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def run() -> None:
        conn, _ = srv.accept()
        try:
            conn.sendall(banner + coalesce)  # real servers send banner immediately
            with contextlib.suppress(OSError):
                conn.recv(64)
            behavior(conn)
        except OSError:
            pass
        finally:
            time.sleep(0.2)
            conn.close()
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


def _frame(payload: bytes) -> bytes:
    """Wrap a raw payload in valid RFC 4253 §6 framing (4..255-byte aligned padding).

    Keeps a deliberately malformed *payload* (non-KEXINIT, truncated name-list)
    inside a well-formed *packet*, so the test exercises the payload-level check
    rather than the packet-framing guard.
    """
    pad_len = -(len(payload) + 5) % 8
    if pad_len < 4:
        pad_len += 8
    body = bytes([pad_len]) + payload + b"\x00" * pad_len
    return struct.pack(">I", len(body)) + body


def _kexinit(kex: bytes, host_keys: bytes) -> bytes:
    payload = bytes([20]) + b"\x00" * 16
    for nl in (kex, host_keys, b"", b"", b"", b"", b"", b"", b"", b""):
        payload += struct.pack(">I", len(nl)) + nl
    payload += b"\x00" + struct.pack(">I", 0)  # first_kex_follows + reserved
    pad = 8 - ((len(payload) + 5) % 8) or 8
    body = bytes([pad]) + payload + b"\x00" * pad
    return struct.pack(">I", len(body)) + body


def test_oversized_packet_length_rejected_fast() -> None:
    port = _serve(lambda c: c.sendall(struct.pack(">I", 0xFFFFFFFF)))
    start = time.time()
    with pytest.raises(SSHProbeError, match="implausible"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)
    assert time.time() - start < 2  # bounded, not a hang


def test_non_kexinit_payload_rejected() -> None:
    # Well-framed packet whose payload's first byte is not SSH_MSG_KEXINIT (20).
    port = _serve(lambda c: c.sendall(_frame(b"NOTKEX!!")))
    with pytest.raises(SSHProbeError, match="KEXINIT"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_truncated_namelist_rejected() -> None:
    # KEXINIT msg + cookie then a name-list length that overruns the payload.
    payload = bytes([20]) + b"\x00" * 16 + struct.pack(">I", 9999)
    port = _serve(lambda c: c.sendall(_frame(payload)))
    with pytest.raises(SSHProbeError, match="truncated"):
        read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)


def test_banner_and_packet_coalesced_parses_correctly() -> None:
    # banner + KEXINIT in ONE send — the byte-by-byte banner read must not
    # consume the packet's bytes.
    pkt = _kexinit(b"mlkem768x25519-sha256", b"ssh-ed25519")
    port = _serve(lambda c: None, coalesce=pkt)
    offer = read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)
    assert "mlkem768x25519-sha256" in offer.kex_algorithms
    assert "ssh-ed25519" in offer.host_key_algorithms


def test_closed_port_raises_typed_error() -> None:
    with pytest.raises(SSHProbeError):
        read_kexinit_offer("127.0.0.1", 59999, timeout_seconds=2)


def test_pseudo_kex_markers_filtered() -> None:
    pkt = _kexinit(b"mlkem768x25519-sha256,ext-info-s,kex-strict-s-v00@openssh.com", b"ssh-ed25519")
    port = _serve(lambda c: None, coalesce=pkt)
    offer = read_kexinit_offer("127.0.0.1", port, timeout_seconds=5)
    assert "ext-info-s" not in offer.kex_algorithms
    assert "kex-strict-s-v00@openssh.com" not in offer.kex_algorithms
    assert "mlkem768x25519-sha256" in offer.kex_algorithms
    assert offer.strict_kex is True
