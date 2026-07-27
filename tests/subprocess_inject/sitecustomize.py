# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Subprocess-only fault injection for installed-entrypoint contract tests."""

from __future__ import annotations

import os

if os.environ.get("QUREDDY_TEST_FORCE_TYPED_ERROR") == "1":
    from qureddy.core.errors import QureddyError
    from qureddy.scanners.tls.scanner import TLSScanner

    def _raise_typed_error(*_args: object, **_kwargs: object) -> None:
        raise QureddyError("forced typed scan failure")

    TLSScanner.scan = _raise_typed_error  # type: ignore[method-assign]

if os.environ.get("QUREDDY_TEST_FORCE_CLASSICAL_RESULT") == "1":
    from qureddy.core.models import ScanResult, ScanTarget
    from qureddy.scanners.tls.scanner import TLSScanner

    def _classical_result(
        _scanner: TLSScanner,
        target: ScanTarget,
        *,
        timeout_seconds: int,
    ) -> ScanResult:
        """Return a deterministic successful scan at the installed CLI boundary."""
        del timeout_seconds
        locator = target.locator
        return ScanResult.model_validate(
            {
                "scan": {
                    "scan_id": "installed-classical",
                    "started_at": "2026-07-17T07:18:11Z",
                    "completed_at": "2026-07-17T07:18:12Z",
                    "status": "completed",
                },
                "target": target,
                "dependencies": [
                    {
                        "path": "/fixture/openssl",
                        "version": "3.6.3",
                        "supports_tls13_groups": True,
                        "supports_x25519mlkem768": True,
                    }
                ],
                "assets": [
                    {
                        "id": "asset-classical",
                        "asset_type": "tls.endpoint",
                        "locator": locator,
                        "display_name": f"{target.host}:{target.port}",
                    }
                ],
                "evidence": [
                    {
                        "id": "evidence-classical",
                        "asset_id": "asset-classical",
                        "evidence_type": "tls.negotiation",
                        "observation_type": "negotiated",
                        "source": "installed-contract-fixture",
                        "protocol_version": "TLSv1.3",
                        "cipher_suite": "TLS_AES_256_GCM_SHA384",
                        "negotiated_group": "X25519",
                    },
                    {
                        "id": "evidence-certificate",
                        "asset_id": "asset-classical",
                        "evidence_type": "tls.cert.signature",
                        "observation_type": "observed",
                        "source": "installed-contract-fixture",
                        "certificate": {
                            "subject": "CN=classical.example.invalid",
                            "issuer": "CN=Fixture CA",
                            "not_before": "Jul 17 07:18:11 2026 GMT",
                            "not_after": "Jul 17 07:18:11 2027 GMT",
                            "serial": "0123456789ABCDEF",
                            "signature_algorithm": "ecdsa-with-SHA256",
                            "public_key_summary": "Public Key Algorithm: id-ecPublicKey",
                            "is_self_signed": False,
                            "is_post_quantum_signature": False,
                        },
                    },
                ],
                "findings": [],
                "summary": {
                    "target": locator,
                    "finding_count": 0,
                    "readiness": "quantum_vulnerable",
                },
            }
        )

    TLSScanner.scan = _classical_result  # type: ignore[method-assign]
