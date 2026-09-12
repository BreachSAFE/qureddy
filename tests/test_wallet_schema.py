# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Gate G7: the optional `subject` field leaves existing scan JSON byte identical.

`ScanTarget` gained `subject` so a wallet scan (`btc`, `eth`) can name the account
examined while `locator` keeps naming the endpoint contacted. Byte identical here
means that for a `tls`, `ssh` or `ike` target the serialized document carries the
same keys with the same values it carried before the field existed: `subject`
appears in no `model_dump()` key set, in no `model_dump_json()` text, and in no
rendered `ScanResult`. The pre-change bytes come from `tests/golden/json.golden`,
generated before this field and untouched by it.

The wallet invariants are proved here as well: a subject belongs to a scheme in
`SUBJECT_SCHEMES`, it carries a non-blank value, and `locator` still has to match
`scheme://host:port` for the new schemes.
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from qureddy.core.models import (
    SUBJECT_SCHEMES,
    SUPPORTED_SCHEMES,
    ScanResult,
    ScanTarget,
    StartTLSMode,
)
from qureddy.output.json import render_json
from tests.test_models import _make_scan_result, _make_target
from tests.test_output import _build_result

GOLDEN_JSON = Path(__file__).parent / "golden" / "json.golden"

# The ScanTarget key set as it stood before `subject` existed. `starttls_mode`
# is listed separately because it is excluded when unset.
PRE_CHANGE_TARGET_KEYS = frozenset(
    {"original_input", "host", "port", "sni", "scheme", "locator"},
)

ENDPOINT_SCHEMES = ("tls", "ssh", "ike")
WALLET_SCHEMES = ("btc", "eth")

BTC_SUBJECT = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
ETH_SUBJECT = "0x00000000219ab540356cbb839cbe05303d7705fa"


def _endpoint_target(scheme: str, *, subject: str | None = None) -> ScanTarget:
    """A minimal target for any scheme, with the locator the validator demands."""
    host = "example.com"
    port = 443
    return ScanTarget(
        original_input=host,
        host=host,
        port=port,
        sni=None,
        scheme=scheme,
        subject=subject,
        locator=f"{scheme}://{host}:{port}",
    )


def _canonical(payload: object) -> str:
    """Serialize with the normalization tests/golden/json.golden was written with."""
    return json.dumps(payload, indent=2, sort_keys=True)


def _rendered_json(result: ScanResult) -> dict[str, object]:
    stream = io.StringIO()
    render_json(result, stream)
    return json.loads(stream.getvalue())


class TestSubjectIsAbsentFromEndpointSchemes:
    """A tls, ssh or ike target serializes exactly as it did before the field."""

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_subject_is_not_a_dump_key(self, scheme: str) -> None:
        assert "subject" not in _endpoint_target(scheme).model_dump()

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_subject_appears_nowhere_in_the_json_text(self, scheme: str) -> None:
        assert "subject" not in _endpoint_target(scheme).model_dump_json()

    def test_reused_tls_target_fixture_omits_subject(self) -> None:
        target = _make_target()
        assert "subject" not in target.model_dump()
        assert "subject" not in target.model_dump_json()

    def test_reused_scan_result_fixture_omits_subject(self) -> None:
        stream = io.StringIO()
        render_json(_build_result(), stream)
        assert "subject" not in stream.getvalue()

    def test_a_btc_target_without_a_subject_also_omits_the_key(self) -> None:
        target = _endpoint_target("btc")
        assert target.subject is None
        assert "subject" not in target.model_dump()
        assert "subject" not in target.model_dump_json()


class TestTargetKeySetIsUnchanged:
    """The serialized target object holds the pre-change key set and nothing else."""

    def test_reused_fixture_target_keys_match_the_pre_change_contract(self) -> None:
        payload = _rendered_json(_build_result())
        assert isinstance(payload["target"], dict)
        assert set(payload["target"]) == PRE_CHANGE_TARGET_KEYS

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_every_endpoint_scheme_keeps_the_pre_change_key_set(self, scheme: str) -> None:
        assert set(_endpoint_target(scheme).model_dump()) == PRE_CHANGE_TARGET_KEYS

    def test_starttls_mode_is_present_only_when_set(self) -> None:
        with_starttls = ScanTarget(
            original_input="mail.example.com:25",
            host="mail.example.com",
            port=25,
            sni="mail.example.com",
            starttls_mode=StartTLSMode.SMTP,
            locator="tls://mail.example.com:25",
        )
        assert set(with_starttls.model_dump()) == PRE_CHANGE_TARGET_KEYS | {"starttls_mode"}
        assert set(_make_target().model_dump()) == PRE_CHANGE_TARGET_KEYS

    def test_wallet_target_adds_subject_and_nothing_else(self) -> None:
        target = _endpoint_target("btc", subject=BTC_SUBJECT)
        assert set(target.model_dump()) == PRE_CHANGE_TARGET_KEYS | {"subject"}


class TestGoldenBytesAreUnchanged:
    """The rendered target matches bytes recorded before the field existed."""

    def test_target_object_is_byte_identical_to_the_golden(self) -> None:
        golden = json.loads(GOLDEN_JSON.read_text(encoding="utf-8"))
        rendered = _rendered_json(_build_result())
        assert _canonical(rendered["target"]) == _canonical(golden["target"])

    def test_schema_version_is_unchanged(self) -> None:
        golden = json.loads(GOLDEN_JSON.read_text(encoding="utf-8"))
        rendered = _rendered_json(_build_result())
        assert rendered["schema_version"] == "qureddy.scan.v1"
        assert rendered["schema_version"] == golden["schema_version"]
        assert _make_scan_result().schema_version == "qureddy.scan.v1"


class TestRoundTrip:
    """model_validate(model_dump()) reproduces an equal model for every scheme."""

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_endpoint_scheme_round_trips(self, scheme: str) -> None:
        target = _endpoint_target(scheme)
        assert ScanTarget.model_validate(target.model_dump()) == target

    @pytest.mark.parametrize(
        ("scheme", "subject"),
        [("btc", BTC_SUBJECT), ("eth", ETH_SUBJECT)],
    )
    def test_wallet_scheme_round_trips_with_its_subject(self, scheme: str, subject: str) -> None:
        target = _endpoint_target(scheme, subject=subject)
        reloaded = ScanTarget.model_validate(target.model_dump())
        assert reloaded == target
        assert reloaded.subject == subject

    def test_reused_scan_result_fixture_round_trips(self) -> None:
        result = _build_result()
        assert ScanResult.model_validate(result.model_dump(mode="json")) == result


class TestSubjectSchemeInvariant:
    """A subject on a non-subject scheme is rejected at construction."""

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_subject_is_rejected_for_an_endpoint_scheme(self, scheme: str) -> None:
        with pytest.raises(ValidationError, match="subject is only valid for"):
            _endpoint_target(scheme, subject=BTC_SUBJECT)

    @pytest.mark.parametrize(
        ("scheme", "subject"),
        [("btc", BTC_SUBJECT), ("eth", ETH_SUBJECT)],
    )
    def test_subject_is_accepted_for_a_wallet_scheme(self, scheme: str, subject: str) -> None:
        assert _endpoint_target(scheme, subject=subject).subject == subject

    @pytest.mark.parametrize("subject", ["", "   ", "\t"])
    def test_a_blank_subject_is_rejected(self, subject: str) -> None:
        with pytest.raises(ValidationError, match="subject cannot be empty or whitespace-only"):
            _endpoint_target("btc", subject=subject)


class TestLocatorInvariantHoldsForWalletSchemes:
    """locator keeps naming the endpoint, for the new schemes as for the old."""

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES + WALLET_SCHEMES)
    def test_locator_equals_scheme_host_port(self, scheme: str) -> None:
        assert _endpoint_target(scheme).locator == f"{scheme}://example.com:443"

    @pytest.mark.parametrize("scheme", WALLET_SCHEMES)
    def test_a_mismatched_locator_is_rejected(self, scheme: str) -> None:
        with pytest.raises(ValidationError, match="does not match host/port/scheme"):
            ScanTarget(
                original_input="mempool.space",
                host="mempool.space",
                port=443,
                sni=None,
                scheme=scheme,
                subject=BTC_SUBJECT,
                locator=f"{scheme}://elsewhere.example:443",
            )


class TestSchemeSets:
    """The existing schemes survive the addition of the wallet ones."""

    @pytest.mark.parametrize("scheme", ENDPOINT_SCHEMES)
    def test_supported_schemes_still_contains_the_endpoint_schemes(self, scheme: str) -> None:
        assert scheme in SUPPORTED_SCHEMES

    def test_subject_schemes_are_the_wallet_schemes_only(self) -> None:
        assert sorted(SUBJECT_SCHEMES) == sorted(WALLET_SCHEMES)
        assert SUBJECT_SCHEMES <= SUPPORTED_SCHEMES
        assert SUBJECT_SCHEMES.isdisjoint(ENDPOINT_SCHEMES)

    def test_an_unknown_scheme_is_still_rejected(self) -> None:
        with pytest.raises(ValidationError, match="scheme must be one of"):
            _endpoint_target("doge")
