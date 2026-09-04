# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for the shared STARTTLS connection argument contract."""

from __future__ import annotations

from qureddy.scanners.tls.connection import (
    StartTLSMode,
    build_s_client_args,
    starttls_args,
)


def test_direct_tls_has_no_starttls_argument() -> None:
    """Direct TLS remains byte-compatible when no application mode is selected."""

    args = build_s_client_args("openssl", "example.test", 443, "example.test")

    assert args == [
        "openssl",
        "s_client",
        "-connect",
        "example.test:443",
        "-servername",
        "example.test",
    ]
    assert starttls_args(None) == ()


def test_starttls_mode_is_bounded_and_shared() -> None:
    """A selected enum contributes exactly one OpenSSL mode pair."""

    args = build_s_client_args(
        "openssl",
        "localhost",
        3306,
        "localhost",
        extra=("-tls1_3", "-groups", "X25519MLKEM768", "-brief"),
        starttls=StartTLSMode.MYSQL,
    )

    assert args[-5:] == ["-brief", "-starttls", "mysql", "-servername", "localhost"]
