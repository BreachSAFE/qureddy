# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parse tls-scan JSON into protocol-specific observations.

The parser is deliberately separate from execution and evaluation.  QuReddy's
existing ``ProbeResult``, ``Evidence``, ``CollectionResult`` and evaluator own
those concerns; this module only converts the external JSON shape.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Evidence,
    ExternalToolDependency,
    ObservationType,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.common.process import run_bounded

_MAX_INPUT_BYTES = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class TLSScanObservation:
    """Lossless, typed projection of one tls-scan JSON record."""

    host: str | None
    ip: str | None
    port: int | None
    tls_version: str | None
    cipher: str | None
    temporary_key_algorithm: str | None
    temporary_key_size: int | None
    secure_renegotiation: bool | None
    compression: str | None
    expansion: str | None
    session_lifetime_hint: int | None
    session_reuse: bool | None
    ocsp_stapled: bool | None
    ocsp_valid: bool | None
    alpn: str | None
    protocol_versions: tuple[str, ...]
    supported_ciphers: tuple[str, ...]
    unsupported_ciphers: tuple[str, ...]
    certificate_chain: tuple[Mapping[str, Any], ...]


class TLSScanAdapter:
    """Run the real tls-scan binary and normalize its observations."""

    tool_id = "tls-scan"
    capabilities = frozenset({Capability.TLS_ENDPOINT})

    def __init__(self, binary_name: str = "tls-scan") -> None:
        """Resolve the configured executable without executing user input."""
        self._binary = shutil.which(binary_name)

    @property
    def version(self) -> str:
        """Return the external tool version, or ``unknown``."""
        if self._binary is None:
            return "unknown"
        result = run_bounded([self._binary, "--version"], timeout_seconds=5, output_limit=4096)
        text = (result.stdout or result.stderr).decode("utf-8", errors="replace")
        return text.splitlines()[0].strip() if result.return_code == 0 and text else "unknown"

    def available(self) -> bool:
        """Return whether the configured executable is on PATH."""
        return self._binary is not None

    def dependency(self) -> ExternalToolDependency:
        """Return executable provenance without making availability a scan failure."""
        return ExternalToolDependency(
            name=self.tool_id,
            path=self._binary,
            version=self.version if self.available() else None,
        )

    def run(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Execute a live endpoint scan and return existing evidence records."""
        if source.kind is not SourceKind.ENDPOINT or source.protocol != "tls":
            return self._failure(CollectionFailureKind.UNSUPPORTED, "source is not a TLS endpoint")
        if self._binary is None:
            return self._failure(CollectionFailureKind.UNAVAILABLE, "tls-scan is unavailable")
        target = urlparse(source.locator)
        if target.hostname is None or target.port is None:
            return self._failure(CollectionFailureKind.MALFORMED, "TLS source has no endpoint")
        argv = [
            self._binary,
            f"--connect={target.hostname}:{target.port}",
            "--all",
            "--show-unsupported-ciphers",
            "--pretty",
        ]
        if source.metadata.get("starttls"):
            argv.append(f"--starttls={source.metadata['starttls']}")
        output = run_bounded(argv, timeout_seconds=timeout_seconds, output_limit=10 * 1024 * 1024)
        probe = ProbeResult(
            command=ProbeCommand(
                executable=self._binary, args=tuple(argv[1:]), timeout_seconds=timeout_seconds
            ),
            return_code=output.return_code,
            stdout_sha256=hashlib.sha256(output.stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(output.stderr).hexdigest(),
            parser_input=output.stdout.decode("utf-8", errors="replace"),
            stdout_excerpt=output.stdout[:4000].decode("utf-8", errors="replace"),
            stderr_excerpt=output.stderr[:4000].decode("utf-8", errors="replace"),
            duration_ms=output.duration_ms,
        )
        try:
            observations = parse_tls_scan(output.stdout)
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
            return self._failure(CollectionFailureKind.MALFORMED, str(exc))
        asset_id = source.metadata.get("asset_id", new_id("asset"))
        evidence = tuple(
            _evidence(observation, asset_id=asset_id, probe=probe) for observation in observations
        )
        failure = None
        if not observations and output.return_code != 0:
            failure = CollectionFailure(
                CollectionFailureKind.EXECUTION, "tls-scan returned no JSON"
            )
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            evidence=evidence,
            failure=failure,
        )

    def _failure(self, kind: CollectionFailureKind, message: str) -> CollectionResult:
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            failure=CollectionFailure(kind=kind, message=message),
        )


def _evidence(observation: TLSScanObservation, *, asset_id: str, probe: ProbeResult) -> Evidence:
    """Map one external observation into the existing evidence contract."""
    return Evidence(
        id=new_id("ev"),
        asset_id=asset_id,
        evidence_type="tls.external.negotiation",
        observation_type=ObservationType.OBSERVED,
        source="tls-scan",
        protocol="tls",
        protocol_version=observation.tls_version,
        cipher_suite=observation.cipher,
        negotiated_group=observation.temporary_key_algorithm,
        key_bits=observation.temporary_key_size,
        probe_result=probe,
        notes=(
            f"supported_cipher_count={len(observation.supported_ciphers)}",
            f"unsupported_cipher_count={len(observation.unsupported_ciphers)}",
        ),
    )


def parse_tls_scan(raw: str | bytes) -> tuple[TLSScanObservation, ...]:
    """Parse one or more tls-scan JSON records with a bounded input."""
    text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw
    if len(text.encode("utf-8")) > _MAX_INPUT_BYTES:
        raise ValueError("tls-scan output exceeds bounded evidence limit")

    decoder = json.JSONDecoder()
    records: list[TLSScanObservation] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if not isinstance(value, Mapping):
            raise ValueError("tls-scan record must be a JSON object")
        records.append(_to_observation(value))
    return tuple(records)


def _to_observation(value: Mapping[str, Any]) -> TLSScanObservation:
    cipher_suite = value.get("cipherSuite")
    cipher_suite = cipher_suite if isinstance(cipher_suite, Mapping) else {}
    chain = value.get("certificateChain")
    chain = chain if isinstance(chain, list) else []
    versions = value.get("tlsVersions")
    versions = versions if isinstance(versions, list) else []

    return TLSScanObservation(
        host=_string(value.get("host")),
        ip=_string(value.get("ip")),
        port=_integer(value.get("port")),
        tls_version=_string(value.get("tlsVersion")),
        cipher=_string(value.get("cipher")),
        temporary_key_algorithm=_string(value.get("tempPublicKeyAlg")),
        temporary_key_size=_integer(value.get("tempPublicKeySize")),
        secure_renegotiation=_boolean(value.get("secureRenego")),
        compression=_string(value.get("compression")),
        expansion=_string(value.get("expansion")),
        session_lifetime_hint=_integer(value.get("sessionLifetimeHint")),
        session_reuse=_boolean(value.get("sessionReuse")),
        ocsp_stapled=_boolean(value.get("ocspStapled")),
        ocsp_valid=_boolean(value.get("verifyOcspResult")),
        alpn=_string(value.get("alpn")),
        protocol_versions=_strings(versions),
        supported_ciphers=_cipher_names(cipher_suite.get("supported")),
        unsupported_ciphers=_cipher_names(
            cipher_suite.get("unsupported", cipher_suite.get("notSupported"))
        ),
        certificate_chain=tuple(item for item in chain if isinstance(item, Mapping)),
    )


def _cipher_names(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _strings(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        return ()
    return tuple(item for item in value if isinstance(item, str))


def _string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _integer(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _boolean(value: object) -> bool | None:
    return value if isinstance(value, bool) else None
