# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the OpenSSL output parser. Real captures + boundary cases."""

from __future__ import annotations

from pathlib import Path

from qureddy.core.models import FailureCategory
from qureddy.scanners.tls.parse import parse_brief_output

FIXTURES = Path(__file__).parent / "fixtures" / "openssl"
HYBRID = "X25519MLKEM768"
CLASSICAL = "X25519"


def _load(name: str) -> str:
    raw = (FIXTURES / name).read_text(encoding="utf-8")
    return "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))


class TestRealHybridCapture:
    """Pinned-baseline replay derived from a live pq.cloudflareresearch.com capture."""

    def test_negotiated_line_is_recognized(self) -> None:
        result = parse_brief_output(
            _load("brief_hybrid_pq_cloudflare.txt"),
            expected_group=HYBRID,
        )
        assert result.negotiated_group == HYBRID
        assert result.failure_category is None

    def test_protocol_and_cipher_extracted(self) -> None:
        result = parse_brief_output(
            _load("brief_hybrid_pq_cloudflare.txt"),
            expected_group=HYBRID,
        )
        assert result.protocol_version == "TLSv1.3"
        assert result.cipher_suite == "TLS_AES_256_GCM_SHA384"


class TestRealClassicalCapture:
    """Pinned-baseline replay derived from a live example.com capture."""

    def test_classical_x25519_recognized_via_peer_temp_key(self) -> None:
        result = parse_brief_output(
            _load("brief_classical_example_com.txt"),
            expected_group=CLASSICAL,
        )
        assert result.negotiated_group == CLASSICAL
        assert result.failure_category is None
        assert result.protocol_version == "TLSv1.3"


class TestUnexpectedGroupGate:
    """Probe asked for hybrid; server returned classical."""

    def test_classical_response_to_hybrid_request_flags_unexpected(self) -> None:
        result = parse_brief_output(
            _load("brief_classical_pq_cloudflare.txt"),
            expected_group=HYBRID,
        )
        assert result.failure_category is FailureCategory.UNEXPECTED_GROUP
        assert result.negotiated_group == CLASSICAL
        assert any(HYBRID in note for note in result.notes)


class TestClientHelloRejection:
    """ClientHello-only mention must not satisfy the negotiation gate."""

    def test_clienthello_only_hybrid_returns_parse_no_group(self) -> None:
        result = parse_brief_output(
            _load("clienthello_only_hybrid.txt"),
            expected_group=HYBRID,
        )
        assert result.negotiated_group is None
        assert result.failure_category is FailureCategory.PARSE_NO_GROUP
        assert any("ClientHello" in note for note in result.notes)


class TestParseNoGroup:
    """Successful handshake with no group line → PARSE_NO_GROUP."""

    def test_handshake_without_group_line(self) -> None:
        result = parse_brief_output(
            _load("parse_no_group.txt"),
            expected_group=HYBRID,
        )
        assert result.negotiated_group is None
        assert result.failure_category is FailureCategory.PARSE_NO_GROUP


class TestParseAmbiguous:
    """Conflicting Negotiated vs Peer Temp Key → PARSE_AMBIGUOUS."""

    def test_conflicting_evidence_returns_ambiguous(self) -> None:
        result = parse_brief_output(
            _load("ambiguous_conflict.txt"),
            expected_group=HYBRID,
        )
        assert result.negotiated_group is None
        assert result.failure_category is FailureCategory.PARSE_AMBIGUOUS


class TestServerTempKeyFallback:
    """Older OpenSSL `Server Temp Key:` form is still accepted."""

    def test_server_temp_key_form_recognized(self) -> None:
        stdout = (
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_128_GCM_SHA256\n"
            "Server Temp Key: X25519, 253 bits\n"
        )
        result = parse_brief_output(stdout, expected_group=CLASSICAL)
        assert result.negotiated_group == CLASSICAL
        assert result.failure_category is None


class TestBoundaryEmptyAndWhitespace:
    """Empty / whitespace input must not crash; PARSE_NO_GROUP is the verdict."""

    def test_empty_stdout(self) -> None:
        result = parse_brief_output("", expected_group=HYBRID)
        assert result.failure_category is FailureCategory.PARSE_NO_GROUP

    def test_whitespace_only_stdout(self) -> None:
        result = parse_brief_output("   \n\t\n", expected_group=HYBRID)
        assert result.failure_category is FailureCategory.PARSE_NO_GROUP


class TestBoundaryRegexAnchoring:
    """Comment-style lines must not satisfy the group regex."""

    def test_group_inside_comment_line_is_ignored(self) -> None:
        stdout = (
            "# TODO: confirm X25519MLKEM768 in a future probe\n"
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_128_GCM_SHA256\n"
            "Peer Temp Key: X25519, 253 bits\n"
        )
        result = parse_brief_output(stdout, expected_group=CLASSICAL)
        assert result.negotiated_group == CLASSICAL
        assert result.failure_category is None


class TestBoundaryReplacementChars:
    """U+FFFD characters must not crash or accidentally satisfy a regex."""

    def test_replacement_chars_yield_parse_no_group(self) -> None:
        stdout = "Protocol version: TLSv1.3\nPeer Temp Key: ��, 0 bits\n"
        result = parse_brief_output(stdout, expected_group=HYBRID)
        assert result.failure_category is FailureCategory.PARSE_NO_GROUP
