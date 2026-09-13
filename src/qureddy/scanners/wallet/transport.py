# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Transport evidence: HTTP transcripts and the indexer's TLS certificate.

A REST call is a probe like any other, so it travels as a `ProbeResult` beside
every subprocess probe. The certificate describes the endpoint that served the
chain data; the chain itself defines none.
"""

from __future__ import annotations

import os
import shutil
from typing import TYPE_CHECKING

from qureddy.core.errors import CertificateParseError, QureddyError
from qureddy.core.ids import new_id
from qureddy.core.models import Evidence, ProbeResult
from qureddy.core.vocabulary import Confidence, ObservationType
from qureddy.scanners.tls._cert_findings import evidence_from_certificate
from qureddy.scanners.tls.cert_probe import fetch_certificate_pem, parse_certificate
from qureddy.scanners.tls.openssl_probe import resolve_openssl_path
from qureddy.scanners.tls.openssl_probe._results import build_probe_result
from qureddy.scanners.wallet.record import _note

if TYPE_CHECKING:  # pragma: no cover - typing only
    from qureddy.scanners.wallet.indexer import HttpExchange
    from qureddy.scanners.wallet.record import Builder

_OPENSSL_ENV = "QUREDDY_OPENSSL"
_HTTP_TIMEOUT_SECONDS = 12
_HTTP_OK = 200
#: Candidates tried in order until one passes the capability gate unchanged. The
#: gate itself is untouched: a candidate is used only when `resolve_openssl_path`
#: accepts it. PATH alone is unreliable, because a box can carry LibreSSL at
#: /usr/bin/openssl and a 3.6 series build ahead of the 3.5 LTS one, and neither
#: satisfies the platform pin.
_OPENSSL_CANDIDATES: tuple[str, ...] = (
    "/opt/homebrew/opt/openssl@3.5/bin/openssl",
    "/usr/local/opt/openssl@3.5/bin/openssl",
)


def _probe_result(exchange: HttpExchange) -> ProbeResult:
    """One HTTP exchange as a ProbeResult, the structure every probe here uses.

    A REST call is a probe like any other: a command went out, bytes came back,
    and it took time. Using `ProbeResult` puts the transcript in `scan.json`
    beside every subprocess probe's, with no structure invented for it.

    `build_probe_result` is the shared builder, so the evidence-integrity
    contract from issue 202 holds here too: each stream's sha256 and excerpt
    derive from one value, which makes the excerpt a verifiable prefix of the
    hashed stream. `stdout` is the curl shaped transcript, the deepest trace
    this lane can produce.
    """
    return build_probe_result(
        args=[exchange.method, exchange.url, *([exchange.operation] if exchange.operation else [])],
        return_code=exchange.status,
        stdout=exchange.transcript(),
        stderr=exchange.error,
        parser_input="",
        duration_ms=exchange.duration_ms,
        attempt_number=1,
        timeout_seconds=_HTTP_TIMEOUT_SECONDS,
        failure_category=None,
    )


def record_exchanges(builder: Builder, exchanges: list[HttpExchange]) -> None:
    """Attach every HTTP round trip as its own evidence record."""
    for index, exchange in enumerate(exchanges, start=1):
        succeeded = exchange.status == _HTTP_OK and not exchange.error
        item = Evidence(
            id=new_id("evidence"),
            asset_id=builder.asset.id,
            evidence_type="wallet.http",
            observation_type=(
                ObservationType.OBSERVED if succeeded else ObservationType.NO_RESPONSE
            ),
            source="chain",
            protocol=builder.protocol,
            confidence=Confidence.HIGH if succeeded else Confidence.LOW,
            probe_result=_probe_result(exchange),
            notes=(
                "lane=chain",
                f"source=HTTP exchange {index} of {len(exchanges)}",
            ),
        )
        builder.evidence.append(item)


def _resolve_openssl() -> str | None:
    """First OpenSSL the existing capability gate accepts, or None.

    Precedence matches the TLS lane: the environment override first, then the
    known LTS keg locations, then PATH. Each candidate goes through
    `resolve_openssl_path`, so the gate decides and this function only chooses
    what to offer it.
    """
    candidates = [
        os.environ.get(_OPENSSL_ENV),
        *_OPENSSL_CANDIDATES,
        shutil.which("openssl"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return resolve_openssl_path(candidate)
        except QureddyError:
            continue
    return None


def record_indexer_certificate(builder: Builder, host: str, port: int) -> None:
    """Record the indexer's TLS certificate, reusing the TLS lane's own probe.

    The endpoint contacted is an ordinary TLS server, so `fetch_certificate_pem`
    and `parse_certificate` apply unchanged and `evidence_from_certificate`
    builds the record. Setting `certificate_pem` also makes `--output-dir` write
    `certificate.pem`, because `_write_certificate_artifact` looks for exactly
    that field.

    This certificate authenticates the API host and says nothing about the
    account, which the finding states. The probe needs an OpenSSL 3.5 LTS
    binary, so an unusable one yields not tested in place of a gap.
    """
    openssl = _resolve_openssl()
    if openssl is None:
        builder.not_tested(
            "indexer.certificate",
            "no OpenSSL on this host passes the capability gate; "
            f"set {_OPENSSL_ENV} to a 3.5 LTS build",
            lane="transport",
        )
        return
    try:
        pem = fetch_certificate_pem(openssl, host, port, host, timeout_seconds=15)
    except QureddyError as exc:
        builder.not_tested("indexer.certificate", str(exc), lane="transport")
        return
    if not pem:
        builder.not_tested(
            "indexer.certificate", "the handshake returned no leaf", lane="transport"
        )
        return
    try:
        certificate = parse_certificate(openssl, pem)
    except (CertificateParseError, QureddyError) as exc:
        builder.not_tested(
            "indexer.certificate", f"the leaf did not parse: {exc}", lane="transport"
        )
        return

    record = evidence_from_certificate(builder.asset, certificate)
    # The TLS builder writes its own note and knows nothing of C1, so the lane
    # and source join it rather than replace it.
    builder.evidence.append(
        record.model_copy(
            update={
                "certificate_pem": pem,
                "notes": (*record.notes, *_note("transport", "openssl s_client leaf")),
            }
        )
    )
    builder.record(
        "indexer.certificate",
        f"{certificate.subject}",
        lane="transport",
        source="openssl s_client leaf, parsed with openssl x509",
        observation=ObservationType.OBSERVED,
        description=(
            f"Issued by {certificate.issuer}, valid to {certificate.not_after}, "
            f"signed with {certificate.signature_algorithm}. This authenticates the "
            f"API host and carries no statement about the account."
        ),
    )
