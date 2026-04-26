# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parse OpenSSL `s_client -brief` output into structured negotiation data.

Captured from real OpenSSL 3.5.6 (homebrew `openssl@3.5`):

  - Hybrid PQ negotiation announces via ``Negotiated TLS1.3 group: <name>``.
    `Peer Temp Key:` does not appear in `-brief` mode for hybrid groups.
  - Classical X25519 negotiation announces via ``Peer Temp Key: X25519, <n> bits``.
    `Negotiated TLS1.3 group:` does not appear in `-brief` for classical.

The historical spec referred to the second line as ``Server Temp Key:``;
real OpenSSL 3.5.6 emits ``Peer Temp Key:``. The parser accepts both for
forward and backward compatibility but always anchors at line start so a
ClientHello-derived dump cannot satisfy the pattern.

Input contract: stdout is decoded UTF-8 text. Comment-prefix stripping
and ANSI-escape removal are caller responsibilities; the parser does
not normalize input.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from qureddy.core.models import FailureCategory

NEGOTIATED_LINE = re.compile(
    r"^\s*Negotiated\s+TLS1\.3\s+group:\s*(?P<group>[A-Za-z0-9_]+)\s*$",
    re.MULTILINE,
)
PEER_OR_SERVER_TEMP_KEY = re.compile(
    r"^\s*(?:Peer|Server)\s+Temp\s+Key:\s*(?P<group>[A-Za-z0-9_]+)",
    re.MULTILINE,
)
CLIENTHELLO_LINE = re.compile(r"^\s*ClientHello\b.*$", re.MULTILINE)
PROTOCOL_VERSION = re.compile(
    r"^\s*Protocol\s+version:\s*(?P<protocol>TLSv\d+(?:\.\d+)?)\s*$",
    re.MULTILINE,
)
CIPHERSUITE = re.compile(
    r"^\s*Ciphersuite:\s*(?P<cipher>[A-Z0-9_]+)\s*$",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class ParsedNegotiation:
    """Structured outcome of parsing one probe's stdout.

    Plain frozen dataclass, not a Pydantic model: this is internal,
    parser-to-scanner state. The scanner converts these into the
    locked Pydantic Evidence/Asset shapes downstream.
    """

    negotiated_group: str | None = None
    protocol_version: str | None = None
    cipher_suite: str | None = None
    failure_category: FailureCategory | None = None
    notes: tuple[str, ...] = ()


def parse_brief_output(stdout: str, *, expected_group: str) -> ParsedNegotiation:
    """Parse `openssl s_client -brief` stdout into a ParsedNegotiation.

    Args:
        stdout: Raw stdout from a real or fixture-replayed s_client run.
        expected_group: The TLS 1.3 group the probe was configured to
            negotiate. Used as a gate: when ServerHello-derived evidence
            names a different group, the parser emits UNEXPECTED_GROUP
            rather than silently reporting whatever the server returned.

    Returns:
        ParsedNegotiation with negotiated_group set only when
        ServerHello-derived evidence supports it AND the group matches
        expected_group. Otherwise failure_category names the failure
        path with notes attributing the verdict.
    """
    protocol = _first_match(PROTOCOL_VERSION, stdout, "protocol")
    cipher = _first_match(CIPHERSUITE, stdout, "cipher")
    negotiated = _first_match(NEGOTIATED_LINE, stdout, "group")
    temp_key = _first_match(PEER_OR_SERVER_TEMP_KEY, stdout, "group")

    if negotiated is not None and temp_key is not None and negotiated != temp_key:
        return _ambiguous(protocol, cipher, negotiated, temp_key)

    server_evidence = negotiated or temp_key
    if server_evidence is None:
        return _no_group(stdout, protocol, cipher, expected_group)

    if server_evidence != expected_group:
        return _unexpected(protocol, cipher, server_evidence, expected_group)

    return ParsedNegotiation(
        negotiated_group=server_evidence,
        protocol_version=protocol,
        cipher_suite=cipher,
    )


def _ambiguous(
    protocol: str | None,
    cipher: str | None,
    negotiated: str,
    temp_key: str,
) -> ParsedNegotiation:
    return ParsedNegotiation(
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.PARSE_AMBIGUOUS,
        notes=(f"conflicting evidence: negotiated={negotiated} vs temp_key={temp_key}",),
    )


def _no_group(
    stdout: str,
    protocol: str | None,
    cipher: str | None,
    expected_group: str,
) -> ParsedNegotiation:
    notes: list[str] = []
    if _has_clienthello_context(stdout, expected_group):
        notes.append(f"{expected_group} appeared only in ClientHello-derived context")
    notes.append("no ServerHello-derived group line present")
    return ParsedNegotiation(
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.PARSE_NO_GROUP,
        notes=tuple(notes),
    )


def _unexpected(
    protocol: str | None,
    cipher: str | None,
    server_evidence: str,
    expected_group: str,
) -> ParsedNegotiation:
    return ParsedNegotiation(
        negotiated_group=server_evidence,
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.UNEXPECTED_GROUP,
        notes=(f"server selected {server_evidence}, probe requested {expected_group}",),
    )


def _first_match(pattern: re.Pattern[str], text: str, group_name: str) -> str | None:
    match = pattern.search(text)
    return match.group(group_name) if match else None


def _has_clienthello_context(stdout: str, group: str) -> bool:
    return any(group in m.group(0) for m in CLIENTHELLO_LINE.finditer(stdout))
