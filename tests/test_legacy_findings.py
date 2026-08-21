# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Legacy-protocol evidence classification (#137)."""

from __future__ import annotations

from qureddy.core.models import Asset, ObservationType
from qureddy.scanners.tls._legacy_findings import evidence_from_legacy_result
from qureddy.scanners.tls.legacy_probe import LegacyProtocolResult

_ASSET = Asset(id="asset-1", asset_type="tls.endpoint", locator="tls://x:443", display_name="x:443")


def _evidence(*, offered: bool, accepted: tuple[str, ...], incomplete: bool = False) -> object:
    result = LegacyProtocolResult(
        protocol_flag="-tls1",
        protocol_version="TLSv1",
        offered=offered,
        accepted_ciphers=accepted,
        probe_incomplete=incomplete,
    )
    return evidence_from_legacy_result(_ASSET, result)


def test_offered_legacy_protocol_is_offered() -> None:
    evidence = _evidence(offered=True, accepted=("AES128-SHA",))
    assert evidence.observation_type is ObservationType.OFFERED


def test_confirmed_not_offered_is_not_offered() -> None:
    # #137: a completed sweep with no accepted ciphers is a confirmed negative and must
    # NOT be OFFERED, or the CBOM falsely claims the endpoint provides this legacy protocol.
    evidence = _evidence(offered=False, accepted=())
    assert evidence.observation_type is ObservationType.NOT_OFFERED


def test_incomplete_sweep_is_not_testable() -> None:
    evidence = _evidence(offered=False, accepted=(), incomplete=True)
    assert evidence.observation_type is ObservationType.NOT_TESTABLE
