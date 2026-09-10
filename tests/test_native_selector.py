# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded native TLS selector parser safety checks (#700)."""

from __future__ import annotations

import socket
import time

import pytest

from qureddy.scanners.tls.native_selector import (
    NativeSuite,
    _client_hello,
    _read_record,
    _read_selected_suite,
    _server_hello_suite,
    probe_excluded_suites,
    select_excluded_suite,
)


def test_server_hello_parser_rejects_short_and_wrong_messages() -> None:
    assert _server_hello_suite(b"") is None
    assert _server_hello_suite(b"\x01\x00\x00\x00") is None
    assert _server_hello_suite(b"\x02\x00\x00\x25" + b"\x00" * 37) is None


def test_server_hello_parser_rejects_truncated_session_id() -> None:
    body = b"\x03\x03" + b"R" * 32 + b"\x20" + b"S" * 3
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    assert _server_hello_suite(message) is None


def _server_hello_record(suite_id: int) -> bytes:
    body = b"\x03\x03" + b"R" * 32 + b"\x00" + suite_id.to_bytes(2, "big") + b"\x00"
    message = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(message).to_bytes(2, "big") + message


def test_native_reader_accepts_exact_server_hello() -> None:
    left, right = socket.socketpair()
    try:
        right.sendall(_server_hello_record(0x0005))
        assert _read_selected_suite(left, 0x0005, time.monotonic() + 1) == (True, True)
    finally:
        left.close()
        right.close()


def test_native_reader_classifies_alert_and_unexpected_records() -> None:
    for record, expected in (
        (b"\x15\x03\x03\x00\x02\x02\x28", (False, True)),
        (b"\x14\x03\x03\x00\x00", (False, False)),
    ):
        left, right = socket.socketpair()
        try:
            right.sendall(record)
            assert _read_selected_suite(left, 0x0005, time.monotonic() + 1) == expected
        finally:
            left.close()
            right.close()


def test_native_reader_rejects_truncated_and_oversized_records() -> None:
    for record in (b"\x16\x03", b"\x16\x03\x03\x40\x01"):
        left, right = socket.socketpair()
        try:
            right.sendall(record)
            right.close()
            assert _read_record(left) is None
        finally:
            left.close()

    left, right = socket.socketpair()
    try:
        right.sendall(b"\x16\x03\x03\x00\x02\x02")
        right.close()
        assert _read_record(left) is None
    finally:
        left.close()


def test_native_reader_handles_incomplete_handshake_bounds() -> None:
    left, right = socket.socketpair()
    try:
        right.sendall(b"\x16\x03\x03\x00\x01\x01")
        right.close()
        assert _read_selected_suite(left, 0x0005, time.monotonic() + 1) == (False, False)
    finally:
        left.close()

    left, right = socket.socketpair()
    try:
        payload = b"\x02\x00\x00\x25"
        right.sendall(b"\x16\x03\x03\x00\x04" + payload)
        assert _read_selected_suite(left, 0x0005, time.monotonic() - 1) == (False, False)
    finally:
        left.close()

    left, right = socket.socketpair()
    try:
        record = b"\x16\x03\x03\x00\x01\x01"
        right.sendall(record * 8)
        assert _read_selected_suite(left, 0x0005, time.monotonic() + 1) == (False, False)
    finally:
        left.close()
        right.close()


def test_native_selector_reads_through_socket_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    left, right = socket.socketpair()
    right.sendall(_server_hello_record(0x0005))
    monkeypatch.setattr(
        "qureddy.scanners.tls.native_selector.socket.create_connection",
        lambda *_args, **_kwargs: left,
    )
    try:
        assert select_excluded_suite(
            "example.com",
            443,
            "example.com",
            "TLSv1.2",
            NativeSuite("RC4-SHA", 0x0005),
            timeout_seconds=1,
        ) == (True, True)
    finally:
        right.close()


def test_native_probe_rolls_up_acceptance_and_incompleteness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcomes = iter(((True, True), (False, True), (False, False), (False, True)))
    monkeypatch.setattr(
        "qureddy.scanners.tls.native_selector.select_excluded_suite",
        lambda *_args, **_kwargs: next(outcomes),
    )
    assert probe_excluded_suites(
        "example.com", 443, "example.com", "TLSv1.2", timeout_seconds=1
    ) == (("RC4-MD5",), True)


def test_native_selector_reports_socket_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> socket.socket:
        raise OSError("controlled failure")

    monkeypatch.setattr("qureddy.scanners.tls.native_selector.socket.create_connection", fail)
    assert select_excluded_suite(
        "example.com",
        443,
        "example.com",
        "TLSv1.2",
        NativeSuite("RC4-SHA", 0x0005),
        timeout_seconds=1,
    ) == (False, False)


def test_client_hello_offers_one_reviewed_suite() -> None:
    hello = _client_hello("example.com", "example.com", 0x0303, 0x0005)
    assert b"\x00\x05" in hello
