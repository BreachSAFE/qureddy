# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded native TLS selector parser safety checks (#700)."""

from __future__ import annotations

from qureddy.scanners.tls.native_selector import _server_hello_suite


def test_server_hello_parser_rejects_short_and_wrong_messages() -> None:
    assert _server_hello_suite(b"") is None
    assert _server_hello_suite(b"\x01\x00\x00\x00") is None
    assert _server_hello_suite(b"\x02\x00\x00\x25" + b"\x00" * 37) is None


def test_server_hello_parser_rejects_truncated_session_id() -> None:
    body = b"\x03\x03" + b"R" * 32 + b"\x20" + b"S" * 3
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    assert _server_hello_suite(message) is None
