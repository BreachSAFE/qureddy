# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for ScanTarget normalization."""

from __future__ import annotations

import pytest

from qureddy.core.errors import TargetParseError
from qureddy.core.targets import parse_ssh_target, parse_target


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


class TestParseTargetTrailingDotFqdn:
    """Issue #130: a single trailing dot is a valid absolute FQDN (RFC 1034).

    Accept it as a target, but strip it from the stored host, locator, and the
    derived SNI so the on-wire SNI stays RFC 6066 compliant.
    """

    @pytest.mark.parametrize(
        ("target", "host"),
        [
            ("www.google.com.", "www.google.com"),
            ("example.com.", "example.com"),
        ],
    )
    def test_trailing_dot_fqdn_parses_without_dot(self, target: str, host: str) -> None:
        result = parse_target(target)
        assert result.host == host
        assert result.sni == host
        assert result.sni is not None
        assert not result.sni.endswith(".")
        assert result.locator == f"tls://{host}:443"

    def test_trailing_dot_fqdn_preserves_original_input(self) -> None:
        result = parse_target("www.google.com.")
        assert result.original_input == "www.google.com."

    def test_trailing_dot_fqdn_with_port(self) -> None:
        result = parse_target("example.com.:8443")
        assert result.host == "example.com"
        assert result.sni == "example.com"
        assert result.locator == "tls://example.com:8443"

    def test_double_trailing_dot_still_rejected(self) -> None:
        with pytest.raises(TargetParseError):
            parse_target("example.com..")


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

    def test_hostname_with_sni_override_uses_override(self) -> None:
        result = parse_target("example.com", sni_override="other.example")
        assert result.host == "example.com"
        assert result.sni == "other.example"

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
            # #128: non-canonical port forms int() would silently "correct"
            "example.com:٤٤٣",  # Arabic-Indic digits
            "example.com:4_43",  # underscore
            "example.com:+443",  # leading sign
            "example.com: 443",  # surrounding whitespace
            "http://[bad",  # #139: unclosed IPv6 bracket -> urlparse ValueError, must be exit 4 not 70
        ],
    )
    def test_invalid_inputs_raise(self, bad_input: str) -> None:
        with pytest.raises(TargetParseError):
            parse_target(bad_input)

    @pytest.mark.parametrize("bad_sni", ["", " ", "   ", "\t", "\n"])
    def test_empty_or_whitespace_sni_override_raises(self, bad_sni: str) -> None:
        with pytest.raises(TargetParseError, match="empty or whitespace"):
            parse_target("example.com", sni_override=bad_sni)

    @pytest.mark.parametrize(
        "bad_sni",
        [
            "0\n",  # #145: trailing newline ($ would otherwise let it through)
            "evil\ninjected",  # embedded newline
            "-oProxyCommand=x",  # leading dash
            "a\x1b[31mb",  # ANSI escape
            "host name",  # space
        ],
    )
    def test_sni_override_with_invalid_hostname_chars_raises(self, bad_sni: str) -> None:
        with pytest.raises(TargetParseError, match="not a valid hostname"):
            parse_target("example.com", sni_override=bad_sni)


class TestParseSshTarget:
    """SSH target grammar accepts only endpoint-intent-preserving forms."""

    @pytest.mark.parametrize(
        ("target", "host", "port"),
        [
            ("example.com", "example.com", 22),
            ("example.com:2222", "example.com", 2222),
            ("ssh://example.com", "example.com", 22),
            ("sftp://example.com:2222", "example.com", 2222),
            ("[2001:db8::1]:2222", "2001:db8::1", 2222),
            ("ssh://[2001:db8::1]", "2001:db8::1", 22),
        ],
    )
    def test_accepted_forms(self, target: str, host: str, port: int) -> None:
        result = parse_ssh_target(target)
        assert result.host == host
        assert result.port == port
        assert result.scheme == "ssh"

    @pytest.mark.parametrize(
        ("target", "host"),
        [
            ("www.google.com.", "www.google.com"),
            ("example.com.:2222", "example.com"),
            ("ssh://example.com.", "example.com"),
        ],
    )
    def test_trailing_dot_fqdn_parses_without_dot(self, target: str, host: str) -> None:
        result = parse_ssh_target(target)
        assert result.host == host
        assert result.locator.startswith(f"ssh://{host}:")
        assert not result.host.endswith(".")

    def test_ssh_double_trailing_dot_still_rejected(self) -> None:
        with pytest.raises(TargetParseError):
            parse_ssh_target("example.com..")

    @pytest.mark.parametrize(
        "target",
        [
            "https://example.com",
            "tls://example.com",
            "ftp://example.com",
            "nonsense://example.com",
            "ssh://user@example.com",
            "ssh://example.com/path",
            "ssh://example.com?query=yes",
            "ssh://example.com#fragment",
            "example.com/path",
            "ssh://[bad",  # #139: unclosed IPv6 bracket -> urlparse ValueError, must be exit 4 not 70
        ],
    )
    def test_rejected_forms(self, target: str) -> None:
        with pytest.raises(TargetParseError):
            parse_ssh_target(target)
