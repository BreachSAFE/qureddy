# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the CycloneDX 1.7 CBOM output adapter."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import locale
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from qureddy._branding import PROJECT_VERSION
from qureddy.core.certificate import CertificateObservation
from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    OpenSSLDependency,
    ProbeCommand,
    ProbeResult,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    ScanTarget,
    Severity,
)
from qureddy.output.cbom import render_cbom
from qureddy.output.cbom_semantics import validate_cbom_semantics
from qureddy.scanners.tls.scanner import build_capability_failure_result


def _build_result() -> ScanResult:
    target = ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )
    asset = Asset(
        id="asset-1",
        asset_type="tls.endpoint",
        locator=target.locator,
        display_name="example.com:443",
    )
    finding = Finding(
        id="finding-1",
        asset_id=asset.id,
        evidence_ids=("ev-1",),
        rule_id="tls.hybrid.negotiated_x25519mlkem768",
        finding_type="tls.kex.hybrid",
        title="TLS 1.3 negotiated X25519MLKEM768",
        description="test",
        severity=Severity.INFO,
        readiness=Readiness.TRANSITIONAL_HYBRID,
        confidence="high",  # type: ignore[arg-type]
        protocol_version="TLSv1.3",
        negotiated_group="X25519MLKEM768",
    )
    evidence = Evidence(
        id="ev-1",
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
    )
    dependency = OpenSSLDependency(
        path="/opt/homebrew/opt/openssl@3.5/bin/openssl",
        version="3.5.7",
        supports_tls13_groups=True,
        supports_x25519mlkem768=True,
    )
    return ScanResult(
        scan=ScanMetadata(
            scan_id="scan-test",
            started_at=datetime.now(UTC),
            completed_at=datetime.now(UTC),
            status="completed",
        ),
        target=target,
        dependencies=(dependency,),
        assets=(asset,),
        evidence=(evidence,),
        findings=(finding,),
        summary=ScanSummary(
            target=target.locator,
            finding_count=1,
            highest_severity=Severity.INFO,
            readiness=Readiness.TRANSITIONAL_HYBRID,
        ),
    )


def _render(result: ScanResult) -> dict:
    buf = io.StringIO()
    render_cbom(result, buf)
    return json.loads(buf.getvalue())


# The openssl subcommand a real probe records; only the interpreter/prefix path
# differs from one host to the next. It carries the target and forced group,
# which are semantic and must survive canonicalization verbatim (#207).
_PROBE_ARGS: tuple[str, ...] = (
    "s_client",
    "-connect",
    "example.com:443",
    "-groups",
    "X25519MLKEM768",
    "-servername",
    "example.com",
)


def _build_result_with_probe(executable: str) -> ScanResult:
    """A scan whose sole evidence carries a ProbeResult run from ``executable``.

    Two hosts observing identical crypto differ only in where their openssl binary
    lives (e.g. /opt/homebrew/opt/openssl@3.5/bin/openssl vs /usr/bin/openssl). This
    lets a test vary that host-specific path while holding the observed crypto and
    the probe's semantic arguments fixed (#207).
    """
    result = _build_result()
    probe_evidence = Evidence(
        id="ev-1",
        asset_id=result.assets[0].id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519MLKEM768",
        probe_result=ProbeResult(
            command=ProbeCommand(
                executable=executable,
                args=_PROBE_ARGS,
                timeout_seconds=30,
            ),
            return_code=0,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            duration_ms=42,
            attempt_number=1,
        ),
    )
    return result.model_copy(update={"evidence": (probe_evidence,)})


def _render_reproducible_bytes(result: ScanResult) -> str:
    buf = io.StringIO()
    render_cbom(result, buf, reproducible=True)
    return buf.getvalue()


def _emit_reproducible_cbom_bytes() -> str:
    """Render a fixed, probe-bearing scan in reproducible mode.

    Called both in-process and from a child interpreter (a distinct
    ``PYTHONHASHSEED``) so a test can prove the serialized bytes do not depend on
    set/dict iteration order across processes (#196).
    """
    result = _build_result_with_probe("/opt/homebrew/opt/openssl@3.5/bin/openssl")
    return _render_reproducible_bytes(result)


@contextlib.contextmanager
def _forced_non_english_lc_time() -> object:
    """Force a non-English LC_TIME if one is installed; restore it on exit (#116).

    Never skips: where no non-English locale is available on the runner, the
    body still asserts correct parsing under the default locale.
    """
    original = locale.setlocale(locale.LC_TIME)
    try:
        for candidate in ("de_DE.UTF-8", "de_DE.utf8", "fr_FR.UTF-8", "German_Germany.1252"):
            with contextlib.suppress(locale.Error):
                locale.setlocale(locale.LC_TIME, candidate)
                break
        yield
    finally:
        locale.setlocale(locale.LC_TIME, original)


class TestCycloneDx17Contract:
    """Pin the deterministic and attribution-honest CycloneDX 1.7 shape."""

    def test_declares_cyclonedx_17(self) -> None:
        payload = _render(_build_result())

        assert payload["specVersion"] == "1.7"
        assert payload["$schema"] == "http://cyclonedx.org/schema/bom-1.7.schema.json"

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
        # #162: --reproducible omits the per-run identity so the same scan is
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


class TestCbomSemanticGuard:
    """Pin BreachSAFE checks that structural validators do not all enforce."""

    @staticmethod
    def _base() -> dict:
        return _render(_build_result())

    def test_rejects_wrong_spec_version(self) -> None:
        payload = self._base()
        payload["specVersion"] = "1.6"

        with pytest.raises(ValueError, match=r"exactly 1\.7"):
            validate_cbom_semantics(payload)

    def test_rejects_dangling_reference(self) -> None:
        payload = self._base()
        endpoint = next(item for item in payload["dependencies"] if item["ref"] == "endpoint")
        endpoint["provides"].append("crypto/algorithm/missing")

        with pytest.raises(ValueError, match="dangling"):
            validate_cbom_semantics(payload)

    def test_rejects_dangling_cipher_suite_algorithm_ref(self) -> None:
        # #144: the runtime validator must catch a dangling cipher-suite algorithm ref,
        # not only the CI harness.
        payload = self._base()
        protocol = next(
            component
            for component in payload["components"]
            if component.get("cryptoProperties", {}).get("protocolProperties")
        )
        protocol["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["algorithms"].append(
            "crypto/algorithm/missing"
        )

        with pytest.raises(ValueError, match="dangling"):
            validate_cbom_semantics(payload)

    def test_rejects_duplicate_reference(self) -> None:
        payload = self._base()
        payload["components"].append(dict(payload["components"][0]))

        with pytest.raises(ValueError, match="duplicate"):
            validate_cbom_semantics(payload)

    def test_rejects_duplicate_tool_reference(self) -> None:
        payload = self._base()
        duplicate = dict(payload["metadata"]["tools"]["components"][0])
        duplicate["bom-ref"] = "endpoint"
        payload["metadata"]["tools"]["components"].append(duplicate)

        with pytest.raises(ValueError, match="duplicate"):
            validate_cbom_semantics(payload)

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("note", "-----BEGIN DSA PRIVATE KEY-----"),
            ("note", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("access_token", "not-a-real-token-but-still-secret"),
            ("credential", "username:password"),
            ("session_key", "session-secret-value"),
        ],
    )
    def test_rejects_secret_like_material(self, name: str, value: str) -> None:
        payload = self._base()
        payload["metadata"]["properties"].append(
            {
                "name": name,
                "value": value,
            }
        )

        with pytest.raises(ValueError, match="secret-like"):
            validate_cbom_semantics(payload)


def _command_hash_property(payload: dict) -> str:
    """Extract the probe command digest from a component's evidence occurrences (#287).

    The command hash rides in the occurrence ``additionalContext`` (``command_sha256=<hex>``)
    now that evidence is attached to the asset it describes, not a flat metadata block.
    """
    components = [payload["metadata"].get("component", {}), *payload.get("components", [])]
    for component in components:
        for occurrence in component.get("evidence", {}).get("occurrences", []):
            match = re.search(
                r"command_sha256=([0-9a-f]{64})", occurrence.get("additionalContext", "")
            )
            if match:
                return match.group(1)
    msg = "no command_sha256 in any component's evidence occurrences"
    raise AssertionError(msg)


class TestReproducibleHostPathCanonicalization:
    """Reproducible CBOM must not encode host-specific probe executable paths (#207)."""

    _HOST_A = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
    _HOST_B = "/usr/bin/openssl"

    def test_reproducible_cbom_is_byte_identical_across_host_openssl_paths(self) -> None:
        # #207: two hosts observing identical crypto, differing only in where their
        # openssl binary lives, must produce byte-identical reproducible CBOM.
        host_a = _render_reproducible_bytes(_build_result_with_probe(self._HOST_A))
        host_b = _render_reproducible_bytes(_build_result_with_probe(self._HOST_B))
        assert host_a == host_b

    def test_reproducible_command_hash_is_over_basename_not_absolute_path(self) -> None:
        # The hashed command must attribute the openssl subcommand (basename + args)
        # without binding to the host install location.
        payload = json.loads(_render_reproducible_bytes(_build_result_with_probe(self._HOST_A)))
        expected = hashlib.sha256(
            " ".join(["openssl", *_PROBE_ARGS]).encode(),
        ).hexdigest()
        assert _command_hash_property(payload) == expected

    def test_non_reproducible_output_retains_host_specific_path(self) -> None:
        # Guardrail: operator diagnostics still get the exact local path, so the two
        # hosts' non-reproducible command hashes DO differ. This also proves the fix
        # is scoped to reproducible mode (and that the path genuinely leaked before).
        payload_a = _render(_build_result_with_probe(self._HOST_A))
        payload_b = _render(_build_result_with_probe(self._HOST_B))
        assert _command_hash_property(payload_a) != _command_hash_property(payload_b)
        expected_a = hashlib.sha256(
            " ".join([self._HOST_A, *_PROBE_ARGS]).encode(),
        ).hexdigest()
        assert _command_hash_property(payload_a) == expected_a

    def test_reproducible_cbom_is_byte_identical_across_pythonhashseed(self) -> None:
        # #196: prove set/dict iteration order cannot alter emitted bytes across
        # processes by regenerating the same reproducible scan under two distinct
        # PYTHONHASHSEED values and comparing the final byte streams exactly.
        repo_root = Path(__file__).resolve().parents[1]
        child = (
            "import sys; from tests.test_cbom import _emit_reproducible_cbom_bytes; "
            "sys.stdout.write(_emit_reproducible_cbom_bytes())"
        )
        outputs: list[str] = []
        for seed in ("1", "2"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            completed = subprocess.run(  # noqa: S603 - fixed interpreter + literal script.
                [sys.executable, "-c", child],
                check=True,
                capture_output=True,
                text=True,
                cwd=repo_root,
                env=env,
            )
            outputs.append(completed.stdout)
        assert outputs[0] == outputs[1]
        # sanity: the compared bytes are a real CBOM, not empty/error output.
        assert json.loads(outputs[0])["bomFormat"] == "CycloneDX"
