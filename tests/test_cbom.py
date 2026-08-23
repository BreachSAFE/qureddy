# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CycloneDX 1.7 CBOM output adapter (structural contract).

Semantic-guard, occurrence-provenance, and reproducibility tests live in the
companion module tests/test_cbom_semantics.py (split for issue #298). Shared
scan-result builders live in tests/_cbom_fixtures.py.
"""

from __future__ import annotations

import io
import json

import pytest

from qureddy._branding import PROJECT_VERSION
from qureddy.core.certificate import CertificateObservation
from qureddy.core.errors import CbomError
from qureddy.core.models import (
    Evidence,
    FailureCategory,
    ObservationType,
    OpenSSLDependency,
)
from qureddy.output.cbom import _assert_library_serialization_shape, render_cbom
from qureddy.scanners.tls.scanner import build_capability_failure_result
from tests._cbom_fixtures import _build_result, _forced_non_english_lc_time, _render


class TestCycloneDx17Contract:
    """Pin the deterministic and attribution-honest CycloneDX 1.7 shape."""

    def test_declares_cyclonedx_17(self) -> None:
        payload = _render(_build_result())

        assert payload["specVersion"] == "1.7"
        assert payload["$schema"] == "http://cyclonedx.org/schema/bom-1.7.schema.json"

    def test_library_intermediate_shape_guard_accepts_patch_surface(self) -> None:
        _assert_library_serialization_shape(
            {
                "dependencies": [{"ref": "endpoint"}],
                "components": [
                    {
                        "bom-ref": "crypto/certificate/leaf",
                        "cryptoProperties": {"certificateProperties": {}},
                    }
                ],
                "metadata": {"component": {"bom-ref": "endpoint"}},
            },
            has_certificate=True,
        )

    @pytest.mark.parametrize(
        ("payload", "message"),
        [
            (
                {"dependencies": {}, "components": [], "metadata": {"component": {}}},
                "dependencies/components",
            ),
            ({"dependencies": [], "components": [], "metadata": {}}, "metadata.component"),
            (
                {"dependencies": [{"ref": 1}], "components": [], "metadata": {"component": {}}},
                "dependency.ref",
            ),
            (
                {"dependencies": [], "components": [{"bom-ref": 1}], "metadata": {"component": {}}},
                "component.bom-ref",
            ),
        ],
    )
    def test_library_intermediate_shape_guard_fails_closed(
        self, payload: dict[str, object], message: str
    ) -> None:
        with pytest.raises(CbomError, match=message):
            _assert_library_serialization_shape(payload, has_certificate=False)

    def test_library_intermediate_shape_guard_rejects_bad_certificate_properties(self) -> None:
        payload = {
            "dependencies": [],
            "components": [{"bom-ref": "crypto/certificate/leaf", "cryptoProperties": {}}],
            "metadata": {"component": {}},
        }
        with pytest.raises(CbomError, match="certificateProperties"):
            _assert_library_serialization_shape(payload, has_certificate=True)

    def test_library_intermediate_shape_guard_rejects_missing_certificate(self) -> None:
        payload = {
            "dependencies": [],
            "components": [],
            "metadata": {"component": {}},
        }
        with pytest.raises(CbomError, match="certificate component"):
            _assert_library_serialization_shape(payload, has_certificate=True)

    def test_endpoint_is_metadata_only_with_stable_ref(self) -> None:
        first = _render(_build_result())
        second = _render(_build_result())

        assert first["metadata"]["component"]["bom-ref"] == "endpoint"
        assert second["metadata"]["component"]["bom-ref"] == "endpoint"
        assert "version" not in first["metadata"]["component"]
        component_refs = {c["bom-ref"] for c in first["components"]}
        assert "endpoint" not in component_refs
        # serialNumber, the emission timestamp, the per-run scan timing, and the
        # per-run annotation timestamps are run-identity fields, not deterministic
        # content (#152, #287).
        _run_identity = {"qureddy:scan.started_at", "qureddy:scan.completed_at"}
        for payload in (first, second):
            payload.pop("serialNumber")
            payload["metadata"].pop("timestamp")
            payload["metadata"]["properties"] = [
                prop
                for prop in payload["metadata"]["properties"]
                if prop["name"] not in _run_identity
            ]
            for annotation in payload.get("annotations", []):
                annotation.pop("timestamp", None)
        assert first == second

    def test_local_tools_are_provenance_not_endpoint_dependencies(self) -> None:
        payload = _render(_build_result())
        tools = payload["metadata"]["tools"]["components"]
        tools_by_ref = {tool["bom-ref"]: tool for tool in tools}
        deps_by_ref = {d["ref"]: d for d in payload["dependencies"]}

        # derive from the same source the emitter uses (importlib.metadata via _branding),
        # so a version bump never rots this assertion (#112).
        assert tools_by_ref["tool/qureddy"]["version"] == PROJECT_VERSION
        assert tools_by_ref["tool/openssl"]["version"] == "3.5.7"
        assert "crypto-library/openssl" not in json.dumps(payload)
        assert "dependsOn" not in deps_by_ref["endpoint"]

    def test_endpoint_provides_observed_crypto_assets(self) -> None:
        payload = _render(_build_result())
        deps_by_ref = {d["ref"]: d for d in payload["dependencies"]}

        assert "crypto/protocol/tls-tlsv1.3" in deps_by_ref["endpoint"]["provides"]
        assert "crypto/algorithm/x25519mlkem768" in deps_by_ref["endpoint"]["provides"]

    def test_missing_local_openssl_does_not_fabricate_crypto_assets(self) -> None:
        result = _build_result()
        failed = build_capability_failure_result(
            result.target,
            OpenSSLDependency(
                failure_category=FailureCategory.LOCAL_OPENSSL_MISSING,
            ),
        )
        payload = _render(failed)

        assert payload.get("components", []) == []
        assert [tool["bom-ref"] for tool in payload["metadata"]["tools"]["components"]] == [
            "tool/qureddy"
        ]
        assert payload["dependencies"] == [{"ref": "endpoint"}]

    def test_real_cipher_suite_name_used_not_synthetic_placeholder(self) -> None:
        payload = _render(_build_result())
        protocol = next(c for c in payload["components"] if c["name"] == "TLSv1.3")
        cipher_suite_name = protocol["cryptoProperties"]["protocolProperties"]["cipherSuites"][0][
            "name"
        ]
        assert cipher_suite_name == "TLS_AES_256_GCM_SHA384"

    def test_certificate_serial_uses_native_17_field(self) -> None:
        certificate = CertificateObservation(
            subject="CN=example.com",
            issuer="CN=Example CA",
            not_before="Jul 17 07:18:11 2026 GMT",
            not_after="Jul 17 07:18:11 2027 GMT",
            serial="0123456789ABCDEF",
            signature_algorithm="ecdsa-with-SHA256",
            public_key_summary="Public Key Algorithm: id-ecPublicKey",
            is_self_signed=False,
            is_post_quantum_signature=False,
        )
        certificate_evidence = Evidence(
            id="ev-cert",
            asset_id="asset-1",
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.OBSERVED,
            source="qureddy.scanners.tls.cert_sig",
            certificate=certificate,
        )
        assert "certificate" not in certificate_evidence.model_dump(mode="json")
        result = _build_result().model_copy(
            update={"evidence": (*_build_result().evidence, certificate_evidence)}
        )
        payload = _render(result)
        component = next(
            item for item in payload["components"] if item["bom-ref"] == "crypto/certificate/leaf"
        )
        certificate_properties = component["cryptoProperties"]["certificateProperties"]

        assert certificate_properties["serialNumber"] == "0123456789ABCDEF"
        assert all(
            prop["name"] != "qureddy:certificate.serial" for prop in component.get("properties", [])
        )

    @pytest.mark.parametrize(
        ("value", "expected"), [(True, "true"), (False, "false"), (None, "unknown")]
    )
    def test_certificate_self_signed_property_preserves_all_states(
        self, value: bool | None, expected: str
    ) -> None:
        payload = _render(self._cert_result(is_self_signed=value))
        certificate = next(
            item for item in payload["components"] if item["bom-ref"] == "crypto/certificate/leaf"
        )
        properties = {prop["name"]: prop["value"] for prop in certificate["properties"]}
        assert properties["qureddy:certificate.is_self_signed"] == expected

    def _cert_result(self, **overrides: object) -> object:
        fields: dict[str, object] = {
            "subject": "CN=example.com",
            "issuer": "CN=Example CA",
            "not_before": "Jul 17 07:18:11 2026 GMT",
            "not_after": "Jul 17 07:18:11 2027 GMT",
            "serial": "0123456789ABCDEF",
            "signature_algorithm": "ecdsa-with-SHA256",
            "public_key_summary": "Public-Key: (2048 bit)",
            "is_self_signed": False,
            "is_post_quantum_signature": False,
        }
        fields.update(overrides)
        certificate = CertificateObservation(**fields)  # type: ignore[arg-type]
        certificate_evidence = Evidence(
            id="ev-cert",
            asset_id="asset-1",
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.OBSERVED,
            source="qureddy.scanners.tls.cert_sig",
            certificate=certificate,
        )
        return _build_result().model_copy(
            update={"evidence": (*_build_result().evidence, certificate_evidence)}
        )

    def _subject_key_component(self, payload: dict) -> dict:
        certificate = next(
            item for item in payload["components"] if item["bom-ref"] == "crypto/certificate/leaf"
        )
        ref = certificate["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"]
        return next(item for item in payload["components"] if item["bom-ref"] == ref)

    def test_fully_pq_cert_same_alg_dedupes_to_one_deterministic_ref(self) -> None:
        # #343: a fully-PQ cert whose signature and subject key are the same parameter set
        # (ML-DSA-87 sig + ML-DSA-87 key) must resolve both refs to ONE shared asset — not two
        # Components with the same bom-ref that cyclonedx renames to a random ref (which
        # orphaned a component and broke --deterministic).
        result = self._cert_result(
            signature_algorithm="ML-DSA-87",
            public_key_algorithm="ML-DSA-87",
            public_key_bits=None,
            is_post_quantum_signature=True,
        )
        first, second = io.StringIO(), io.StringIO()
        render_cbom(result, first, reproducible=True)
        render_cbom(result, second, reproducible=True)
        assert first.getvalue() == second.getvalue()  # deterministic
        payload = json.loads(first.getvalue())
        ml_dsa = [c for c in payload["components"] if c["bom-ref"] == "crypto/algorithm/ml-dsa-87"]
        assert len(ml_dsa) == 1
        assert not any(c["bom-ref"].startswith("BomRef.") for c in payload["components"])
        cp = next(c for c in payload["components"] if c["bom-ref"] == "crypto/certificate/leaf")[
            "cryptoProperties"
        ]["certificateProperties"]
        assert (
            cp["signatureAlgorithmRef"] == cp["subjectPublicKeyRef"] == "crypto/algorithm/ml-dsa-87"
        )

    def test_rsa_subject_public_key_emits_depth_and_ref(self) -> None:
        # #313: the certificate's own RSA-2048 subject key becomes a linked crypto-asset with
        # its classical strength (NIST SP 800-57: 112-bit) and a quantum_vulnerable verdict.
        payload = _render(
            self._cert_result(public_key_algorithm="rsaEncryption", public_key_bits=2048)
        )
        component = self._subject_key_component(payload)
        assert component["name"] == "RSA-2048"
        properties = component["cryptoProperties"]["algorithmProperties"]
        assert properties["classicalSecurityLevel"] == 112
        assert properties["nistQuantumSecurityLevel"] == 0
        verdict = {p["name"]: p["value"] for p in component["properties"]}
        assert verdict["qureddy:readiness"] == "quantum_vulnerable"

    def test_undersized_rsa_subject_key_is_classically_weak(self) -> None:
        payload = _render(
            self._cert_result(public_key_algorithm="rsaEncryption", public_key_bits=1024)
        )
        verdict = {
            p["name"]: p["value"] for p in self._subject_key_component(payload)["properties"]
        }
        assert verdict["qureddy:readiness"] == "classically_weak"
        assert verdict["qureddy:severity"] == "high"

    def test_ec_subject_public_key_depth(self) -> None:
        payload = _render(
            self._cert_result(public_key_algorithm="id-ecPublicKey", public_key_bits=256)
        )
        component = self._subject_key_component(payload)
        assert component["name"] == "EC-256"
        assert component["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 128

    def test_slh_dsa_cert_signature_emits_post_quantum_level(self) -> None:
        # #201: an SLH-DSA (FIPS 205) cert must emit a non-zero
        # nistQuantumSecurityLevel in the CBOM, not fall through to level 0 as a
        # classical signature. Before the fix this asserted 0 (false negative).
        certificate = CertificateObservation(
            subject="CN=BreachSAFE Demo Root",
            issuer="CN=BreachSAFE Demo Root",
            not_before="Jul 17 07:18:11 2026 GMT",
            not_after="Jul 17 07:18:11 2027 GMT",
            serial="0123456789ABCDEF",
            signature_algorithm="SLH-DSA-SHA2-128s",
            public_key_summary="Public Key Algorithm: SLH-DSA-SHA2-128s",
            is_self_signed=True,
            is_post_quantum_signature=True,
        )
        certificate_evidence = Evidence(
            id="ev-cert",
            asset_id="asset-1",
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.OBSERVED,
            source="qureddy.scanners.tls.cert_sig",
            certificate=certificate,
        )
        result = _build_result().model_copy(
            update={"evidence": (*_build_result().evidence, certificate_evidence)}
        )
        payload = _render(result)
        algorithm = next(
            item
            for item in payload["components"]
            if item["bom-ref"] == "crypto/algorithm/slh-dsa-sha2-128s"
        )
        properties = algorithm["cryptoProperties"]["algorithmProperties"]
        assert properties["primitive"] == "signature"
        assert properties["parameterSetIdentifier"] == "SLH-DSA-SHA2-128S"
        assert properties["nistQuantumSecurityLevel"] == 1

    def test_certificate_dates_survive_non_english_host_locale(self) -> None:
        # #116: cert validity dates were parsed with a locale-dependent strptime and
        # silently dropped on a non-English host. Render under a forced non-English
        # LC_TIME and assert they still appear.
        certificate = CertificateObservation(
            subject="CN=example.com",
            issuer="CN=Example CA",
            not_before="Jul 17 07:18:11 2026 GMT",
            not_after="Jul 17 07:18:11 2027 GMT",
            serial="0123456789ABCDEF",
            signature_algorithm="ecdsa-with-SHA256",
            public_key_summary="Public Key Algorithm: id-ecPublicKey",
            is_self_signed=False,
            is_post_quantum_signature=False,
        )
        certificate_evidence = Evidence(
            id="ev-cert",
            asset_id="asset-1",
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.OBSERVED,
            source="qureddy.scanners.tls.cert_sig",
            certificate=certificate,
        )
        result = _build_result().model_copy(
            update={"evidence": (*_build_result().evidence, certificate_evidence)}
        )
        with _forced_non_english_lc_time():
            payload = _render(result)
        certificate_properties = next(
            item for item in payload["components"] if item["bom-ref"] == "crypto/certificate/leaf"
        )["cryptoProperties"]["certificateProperties"]
        assert certificate_properties["notValidBefore"] == "2026-07-17T07:18:11+00:00"
        assert certificate_properties["notValidAfter"] == "2027-07-17T07:18:11+00:00"

    def test_reproducible_mode_is_byte_identical_and_drops_run_identity(self) -> None:
        # #162: --deterministic omits the per-run identity so the same scan is
        # content-addressable (byte-identical on repeat).
        first = io.StringIO()
        second = io.StringIO()
        render_cbom(_build_result(), first, reproducible=True)
        render_cbom(_build_result(), second, reproducible=True)
        assert first.getvalue() == second.getvalue()
        payload = json.loads(first.getvalue())
        assert "serialNumber" not in payload
        assert "timestamp" not in payload["metadata"]
        property_names = {prop["name"] for prop in payload["metadata"]["properties"]}
        assert "qureddy:scan.id" not in property_names
        assert "qureddy:scan.started_at" not in property_names
        # deterministic content stays present
        assert "qureddy:scan.readiness" in property_names
        assert "qureddy:target.host" in property_names

    def test_summary_rollup_in_metadata(self) -> None:
        # #309: the JSON summary rollup (finding_count + highest_severity) must be in the CBOM
        # too, so a consumer keying on the CBOM alone never needs the native JSON.
        payload = _render(_build_result())
        props = {p["name"]: p["value"] for p in payload["metadata"]["properties"]}
        assert props["qureddy:scan.finding_count"] == "1"
        assert props["qureddy:scan.highest_severity"] == "info"

    def test_inventory_comes_from_positive_evidence_not_findings(self) -> None:
        result = _build_result()
        finding_only = result.model_copy(update={"evidence": ()})
        evidence_only = result.model_copy(update={"findings": ()})

        assert _render(finding_only).get("components", []) == []
        refs = {component["bom-ref"] for component in _render(evidence_only)["components"]}
        assert refs == {
            "crypto/algorithm/x25519mlkem768",
            "crypto/algorithm/tls_aes_256_gcm_sha384",  # #150: negotiated cipher suite as an asset
            "crypto/protocol/tls-tlsv1.3",
        }

    def test_unknown_and_not_testable_evidence_do_not_create_assets(self) -> None:
        result = _build_result()
        excluded = tuple(
            result.evidence[0].model_copy(update={"observation_type": observation})
            for observation in (ObservationType.INFERRED, ObservationType.NOT_TESTABLE)
        )

        payload = _render(result.model_copy(update={"evidence": excluded, "findings": ()}))

        assert payload.get("components", []) == []
