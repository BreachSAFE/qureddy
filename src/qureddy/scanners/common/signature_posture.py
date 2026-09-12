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


def protocol_hndl_exposure(
    *, protocol: str, not_testable: bool, signature_classical: bool
) -> HndlExposure | None:
    """Settle the exposure cases a key-exchange reading cannot answer."""
    if protocol == "ike" or not_testable:
        return HndlExposure.UNKNOWN
    if protocol in SIGNATURE_ONLY_PROTOCOLS:
        # The harvestable value is the public key itself: recorded today, solved
        # by Shor later. A classical signing algorithm is that exposure.
        return HndlExposure.AT_RISK if signature_classical else HndlExposure.UNKNOWN
    return None
