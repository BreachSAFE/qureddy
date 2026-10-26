# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Expose the native IKEv2 prober through the adapter contract ``scanner.py`` uses.

``IKEScanner`` is written against a single ``run(source, *, timeout_seconds)``
method, so a second backend needs no scanner change. The two adapters differ
only in how a ``ParsedIKEResponse`` is obtained, which keeps ``parser.py``,
``classify.py`` and ``evidence.py`` shared rather than duplicated per backend.

The native backend is IKEv2 only. An IKEv1 mode is reported as unsupported
rather than silently probed over IKEv2, because a caller asking for Main Mode
and receiving IKEv2 evidence would read a version it never tested.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from qureddy.core.contracts import (
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.core.models import (
    ExternalToolDependency,
    FailureCategory,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.ike._packet import PORT_NAT_T, available_methods
from qureddy.scanners.ike.evidence import response_evidence
from qureddy.scanners.ike.native import (
    LocalProbeError,
    NativeProbe,
    sweep,
)
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

if TYPE_CHECKING:  # pragma: no cover
    from qureddy.core.models import Evidence

#: Reported as the tool name so provenance distinguishes a native run from an
#: ``ike-scan`` run in the same result set.
TOOL_ID = "qureddy-native-ike"

#: Set to "0" to suppress the native pass. Present for hermetic tests: they stub
#: the ike-scan subprocess, and a probe that speaks the protocol directly would
#: reach the network regardless of that stub.
NATIVE_IKE_ENV = "QUREDDY_NATIVE_IKE"

#: The probe calls OpenSSL only to generate ephemeral public values, so a host
#: whose OpenSSL lacks ML-KEM can still probe the classical methods. Absence of
#: every method is the dependency failure; a partial set is not.
_EMPTY = FailureCategory.LOCAL_OPENSSL_MISSING

#: A responder that sent a notify answered, so REJECTED carries no failure: the
#: refusal is the observation. Only silence and an unbindable reply are faults.
_FAILURE_BY_STATUS: dict[IKEParseStatus, FailureCategory | None] = {
    IKEParseStatus.RESPONDED: None,
    IKEParseStatus.REJECTED: None,
    IKEParseStatus.NO_RESPONSE: FailureCategory.IKE_PROBE_TIMEOUT,
    IKEParseStatus.UNBOUND: FailureCategory.IKE_OUTPUT_MALFORMED,
}


#: The scanner-wide OpenSSL override. Named here rather than imported from the
#: TLS package so the IKE scanner does not depend on a sibling scanner; the
#: variable is part of the CLI contract, not of either scanner.
OPENSSL_ENV = "QUREDDY_OPENSSL"


def _default_openssl() -> str:
    """Resolve the OpenSSL to use, honouring the scanner-wide override.

    A bare ``openssl`` is the fallback and is deliberately last: on a host with
    several formulae installed the newest owns the unversioned symlink, so the
    override is what keeps a probe on the pinned series.
    """
    return os.environ.get(OPENSSL_ENV) or "openssl"


def _openssl_version(openssl: str) -> str | None:
    """Return the OpenSSL version string, or None when it cannot be read."""
    try:
        out = subprocess.run(  # noqa: S603 - argv list, shell=False
            [openssl, "version"], capture_output=True, text=True, check=False, timeout=10
        ).stdout.strip()
    except OSError, subprocess.SubprocessError:
        return None
    return out or None


class NativeIkeAdapter:
    """IKEv2 backend that speaks the protocol instead of invoking ``ike-scan``."""

    tool_id = TOOL_ID

    #: Exchanges the last run sent, read by the scanner for total_attempts.
    last_probe_count = 0

    def __init__(
        self, *, openssl: str | None = None, timeout: float = 4.0, retries: int = 1
    ) -> None:
        """Configure the OpenSSL path, per-probe timeout and silent-probe retries."""
        # The OpenSSL path is server-owned, matching the TLS scanner: a caller
        # naming an executable is the primitive the tool contract forbids.
        self._openssl = openssl or _default_openssl()
        self._timeout = timeout
        self._retries = retries

    def available(self) -> bool:
        """True when at least one key exchange method can be generated locally."""
        return bool(available_methods(self._openssl))

    def version(self) -> str:
        """Report the probe's own contract version, not a third-party tool's."""
        return "ikev2-sa-init/1"

    def dependency(self) -> ExternalToolDependency:
        """Describe the external runtime this backend actually uses."""
        methods = available_methods(self._openssl)
        return ExternalToolDependency(
            name="openssl",
            path=self._openssl,
            # The real version. Capability is reported through the failure
            # category, because a version string that encodes a count cannot be
            # compared against a pinned release.
            version=_openssl_version(self._openssl),
            failure_category=None if methods else _EMPTY,
        )

    def run(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Probe one endpoint and project every exchange onto canonical Evidence."""
        rejection = self._reject(source)
        if rejection is not None:
            return rejection

        parsed = urlparse(source.locator)
        asset_id = source.metadata["asset_id"]
        started = time.monotonic()
        try:
            probes = sweep(
                parsed.hostname, parsed.port, timeout=min(self._timeout, timeout_seconds)
            )
        except LocalProbeError as exc:
            # A fault on this host is never a statement about the responder, so
            # it surfaces as a collection failure rather than as no_response.
            return self._failure(CollectionFailureKind.UNAVAILABLE, str(exc))

        elapsed_ms = int((time.monotonic() - started) * 1000)
        nat_t = parsed.port == PORT_NAT_T or source.metadata.get("nat_t") == "true"
        evidence: list[Evidence] = []
        for probe in probes:
            evidence.extend(
                response_evidence(
                    probe.response,
                    asset_id=asset_id,
                    source=self._source_name(probe),
                    probe_result=self._probe_result(probe, elapsed_ms // max(len(probes), 1)),
                    nat_t=nat_t,
                )
            )
        # The sweep sends one datagram per key exchange method and per
        # additional-key-exchange offer, so the count is the number of
        # exchanges attempted on the wire rather than the number of adapter
        # calls. Reporting 1 would understate the probing a target saw.
        self.last_probe_count = len(probes)
        return CollectionResult(
            collector=TOOL_ID,
            collector_version=self.version(),
            evidence=tuple(evidence),
            # Findings stay in classify.py. A backend emitting its own would be
            # a second place severity is decided.
            findings=(),
        )

    def _reject(self, source: ScanSource) -> CollectionResult | None:
        """Refuse a source this backend cannot answer for, or return None.

        An IKEv1 mode is refused rather than silently probed over IKEv2: a
        caller asking for Main Mode and receiving IKEv2 evidence would read a
        version it never tested.
        """
        if source.kind is not SourceKind.ENDPOINT or source.protocol != "ike":
            return self._failure(CollectionFailureKind.UNSUPPORTED, "source is not an IKE endpoint")
        if not self.available():
            return self._failure(
                CollectionFailureKind.UNAVAILABLE, "no key exchange method can be generated locally"
            )
        mode = source.metadata.get("mode")
        if mode and IKEMode(mode) is not IKEMode.IKEV2:
            return self._failure(
                CollectionFailureKind.UNSUPPORTED, f"native backend probes IKEv2 only, not {mode}"
            )
        parsed = urlparse(source.locator)
        if (
            source.metadata.get("asset_id") is None
            or parsed.hostname is None
            or parsed.port is None
        ):
            return self._failure(CollectionFailureKind.MALFORMED, "invalid IKE source metadata")
        return None

    def _source_name(self, probe: NativeProbe) -> str:
        """Name the exchange so one probe is distinguishable in the evidence set."""
        name = f"{TOOL_ID}:ke={probe.key_exchange}"
        if probe.additional_key_exchange is not None:
            name = f"{name}:addke1={probe.additional_key_exchange}"
        return name

    def _probe_result(self, probe: NativeProbe, duration_ms: int) -> ProbeResult:
        """Record what was sent, as the subprocess adapter records its argv.

        There is no stdout or stderr to digest, so the request's own parameters
        stand in: they are what a reader needs to reproduce the exchange.
        """
        args = (f"--key-exchange={probe.key_exchange}",)
        if probe.additional_key_exchange is not None:
            args = (*args, f"--addke1={probe.additional_key_exchange}")
        failure = _FAILURE_BY_STATUS.get(probe.response.status)
        return ProbeResult(
            command=ProbeCommand(
                executable=TOOL_ID,
                args=args,
                timeout_seconds=int(self._timeout),
            ),
            return_code=0,
            stdout_sha256=hashlib.sha256((probe.responder_spi or "").encode()).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            duration_ms=duration_ms,
            failure_category=failure,
        )

    def _failure(self, kind: CollectionFailureKind, message: str) -> CollectionResult:
        return CollectionResult(
            collector=TOOL_ID,
            collector_version=self.version(),
            failure=CollectionFailure(kind=kind, message=message),
        )
