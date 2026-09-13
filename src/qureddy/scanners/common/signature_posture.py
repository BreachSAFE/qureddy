# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Posture for protocols that sign and negotiate nothing.

`posture.py` reads every axis from key exchange. A chain account performs no
handshake, so those signals never fire and each axis falls to UNKNOWN while the
signing algorithm sits in evidence. These two functions answer the cases that
reading has no input for, and return None where the key-exchange reading holds.
"""

from __future__ import annotations

from qureddy.core.models import AxisStatus, HndlExposure, PqcSupport
from qureddy.core.vocabulary import SIGNATURE_ONLY_PROTOCOLS


def signature_only_pqc_axis(
    *, protocol: str, signature_classical: bool
) -> tuple[PqcSupport, AxisStatus] | None:
    """Answer the PQC axis from the signing algorithm, or return None."""
    if protocol in SIGNATURE_ONLY_PROTOCOLS and signature_classical:
        return PqcSupport.CLASSICAL_ONLY_OBSERVED, AxisStatus.CLASSICAL
    return None


def signature_only_ciso_text(
    *, protocol: str, account_without_key: bool = False
) -> tuple[str, str] | None:
    """Answer the headline and action for a protocol that only signs, or None.

    The key-exchange wording would name a step that never runs, and its action
    ("enable a supported hybrid group") names a control no operator of a chain
    account holds.

    An account holding no key of its own gets its own pair. Falling through to
    the unknown text would read "posture could not be confirmed", which names a
    measurement that failed; nothing failed here, and the answer is that the
    keys are somewhere this scan did not look.
    """
    if protocol not in SIGNATURE_ONLY_PROTOCOLS:
        return None
    if account_without_key:
        return (
            "This address holds no key of its own, so it carries no key exposure.",
            "Assess the owner and upgrade keys, which are held off this address.",
        )
    return (
        "The account signs with a classical algorithm that meets no NIST category.",
        "Track the published key, since exposure begins at publication.",
    )


def protocol_hndl_exposure(
    *, protocol: str, not_testable: bool, signature_classical: bool
) -> HndlExposure | None:
    """Settle the exposure cases a key-exchange reading cannot answer."""
    if protocol == "ike" or not_testable:
        return HndlExposure.UNKNOWN
    if protocol in SIGNATURE_ONLY_PROTOCOLS:
        # The harvestable value is the public key itself: recorded today, solved
        # by Shor later. A classical signing algorithm is that exposure, and an
        # address with no key of its own has none to harvest.
        return HndlExposure.AT_RISK if signature_classical else HndlExposure.UNKNOWN
    return None
