# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parser regressions for stock ``ike-scan --multiline`` output."""

from __future__ import annotations

from qureddy.scanners.ike.parser import parse_ike_scan_output
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus


def test_key_exchange_size_never_infers_a_group() -> None:
    """Cover the MODP/ECP payload-size collision from issue #679."""
    response = parse_ike_scan_output(
        IKEMode.IKEV2,
        text="vpn\tIKEv2 SA_INIT Handshake returned\n\tKeyExchange(96 bytes)",
    )

    assert response.dh_groups == ()


def test_identity_requires_every_aggressive_mode_marker() -> None:
    """Reject incomplete pre-authentication identity evidence from issue #680."""
    incomplete = "Handshake returned\nKeyExchange(128 bytes)\nID(Type=ID_USER_FQDN)"

    assert not parse_ike_scan_output(IKEMode.IKEV1_AGGRESSIVE, text=incomplete).identity_exposed


def test_explicit_notify_is_distinct_from_silence() -> None:
    """Preserve the named rejection required by issue #686."""
    notify = (
        "vpn\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n"
        "Ending ike-scan: 0 returned handshake; 1 returned notify"
    )
    silent = "Ending ike-scan: 0 returned handshake; 0 returned notify"

    rejected = parse_ike_scan_output(IKEMode.IKEV2, text=notify)
    no_response = parse_ike_scan_output(IKEMode.IKEV2, text=silent)

    assert rejected.status is IKEParseStatus.REJECTED
    assert rejected.responder_notify == "NO-PROPOSAL-CHOSEN"
    assert no_response.status is IKEParseStatus.NO_RESPONSE


def test_ikev2_underscore_notify_is_an_explicit_rejection() -> None:
    """Preserve ike-scan's IKEv2 registry spelling from issue #715."""
    output = (
        "vpn\tNotify message 14 (NO_PROPOSAL_CHOSEN)\n"
        "Ending ike-scan: 0 returned handshake; 1 returned notify"
    )

    response = parse_ike_scan_output(IKEMode.IKEV2, text=output)

    assert response.status is IKEParseStatus.REJECTED
    assert response.responder_notify == "NO_PROPOSAL_CHOSEN"
