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


# --- finding_from_legacy_result branches (#364 coverage) ---

from qureddy.core.models import Evidence, HygieneStatus, Severity  # noqa: E402
from qureddy.scanners.common.posture import build_interpretation  # noqa: E402
from qureddy.scanners.tls._legacy_findings import finding_from_legacy_result  # noqa: E402

_EVIDENCE = Evidence(
    id="ev-1",
    asset_id=_ASSET.id,
    evidence_type="tls.legacy.cipher",
    observation_type=ObservationType.OFFERED,
    source="qureddy.scanners.tls.legacy_probe",
    protocol_version="TLSv1.2",
)


def _finding(*, protocol: str, accepted: tuple[str, ...], offered: bool = True) -> object:
    result = LegacyProtocolResult(
        protocol_flag="-x",
        protocol_version=protocol,
        offered=offered,
        accepted_ciphers=accepted,
        probe_incomplete=False,
    )
    return finding_from_legacy_result(_ASSET, _EVIDENCE, result)


def test_classical_nondeprecated_nonweak_protocol_is_low_finding() -> None:
    # #240: TLS 1.2 (not deprecated) with a strong cipher is the classical-only
    # case -> LOW finding via _classical_protocol_finding, not HIGH/MEDIUM.
    finding = _finding(protocol="TLSv1.2", accepted=("ECDHE-RSA-AES256-GCM-SHA384",))
    assert finding is not None
    assert finding.severity is Severity.LOW


def test_not_offered_protocol_has_no_finding() -> None:
    assert _finding(protocol="TLSv1.2", accepted=(), offered=False) is None


def test_incomplete_offered_sweep_notes_incomplete() -> None:
    # Hits the probe_incomplete note branch in _legacy_protocol_notes.
    evidence = _evidence(offered=True, accepted=("AES128-SHA",), incomplete=True)
    assert any("sweep incomplete" in note for note in evidence.notes)


def test_deprecated_protocol_is_finding() -> None:
    # TLSv1 is deprecated -> _deprecated_or_weak_finding branch.
    finding = _finding(protocol="TLSv1", accepted=("AES128-SHA",))
    assert finding is not None
    assert finding.severity is not Severity.LOW


def test_tls12_weak_cipher_drives_weak_hygiene_and_ciso_summary() -> None:
    finding = _finding(protocol="TLSv1.2", accepted=("DES-CBC3-SHA",))
    assert finding is not None

    interpretation = build_interpretation([finding], [], None)

    assert finding.rule_id == "tls.transport.weak"
    assert finding.finding_type == "tls.transport.weak"
    assert interpretation.hygiene_status is HygieneStatus.WEAK
    assert interpretation.reason_codes == ("weak_classical_algorithm_observed",)
    assert interpretation.headline == "Classically weak algorithm exposure was observed."


def test_deprecated_protocol_with_weak_cipher_preserves_both_facts() -> None:
    finding = _finding(protocol="TLSv1", accepted=("RC4-SHA",))
    assert finding is not None

    interpretation = build_interpretation([finding], [], None)

    assert finding.rule_id == "tls.legacy.protocol_offered"
    assert finding.finding_type == "tls.transport.weak"
    assert interpretation.hygiene_status is HygieneStatus.WEAK
    assert interpretation.reason_codes == (
        "deprecated_protocol_observed",
        "weak_classical_algorithm_observed",
    )
