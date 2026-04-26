# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for ScanTarget normalization."""

from __future__ import annotations

import pytest

from qureddy.core.errors import TargetParseError
from qureddy.core.targets import parse_target


class TestParseTargetHostname:
    """Hostname inputs default SNI = host, port 443."""

    def test_bare_hostname_uses_default_port(self) -> None:
        result = parse_target("example.com")
        assert result.host == "example.com"
        assert result.port == 443
        assert result.sni == "example.com"
        assert result.locator == "tls://example.com:443"

    def test_hostname_with_port_keeps_port(self) -> None:
        result = parse_target("example.com:8443")
        assert result.host == "example.com"
        assert result.port == 8443
        assert result.locator == "tls://example.com:8443"

    def test_https_url_normalizes_to_tls_locator(self) -> None:
        result = parse_target("https://example.com")
        assert result.host == "example.com"
        assert result.port == 443
        assert result.scheme == "tls"
        assert result.locator == "tls://example.com:443"

    def test_https_url_with_port(self) -> None:
        result = parse_target("https://example.com:8443")
        assert result.port == 8443

    def test_original_input_is_preserved(self) -> None:
        result = parse_target("https://example.com:8443")
        assert result.original_input == "https://example.com:8443"


class TestParseTargetIP:
    """IP inputs have SNI=None unless overridden."""

    def test_ipv4_with_port_has_no_sni(self) -> None:
        result = parse_target("1.2.3.4:443")
        assert result.host == "1.2.3.4"
        assert result.port == 443
        assert result.sni is None

    def test_ipv4_with_sni_override_uses_override(self) -> None:
        result = parse_target("1.1.1.1:443", sni_override="one.one.one.one")
        assert result.host == "1.1.1.1"
        assert result.sni == "one.one.one.one"

    def test_ipv4_without_port_uses_443(self) -> None:
        result = parse_target("1.2.3.4")
        assert result.port == 443
        assert result.sni is None

    def test_ipv6_bracketed_with_port(self) -> None:
        result = parse_target("[2001:db8::1]:443")
        assert result.host == "2001:db8::1"
        assert result.port == 443
        assert result.sni is None

    def test_ipv6_bracketed_without_port_uses_default(self) -> None:
        result = parse_target("[2001:db8::1]")
        assert result.port == 443


class TestParseTargetInvalid:
    """Invalid inputs raise TargetParseError."""

    @pytest.mark.parametrize(
        "bad_input",
        [
            "",
            "   ",
            "not a url",
            ":443",
            "example.com:99999",
            "example.com:-1",
            "example.com:notaport",
            "ftp://example.com",
            "https://",
            "[2001:db8::1]:notaport",
            "host..example.com",
        ],
    )
    def test_invalid_inputs_raise(self, bad_input: str) -> None:
        with pytest.raises(TargetParseError):
            parse_target(bad_input)
