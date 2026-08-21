# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""``qureddy:``-namespaced ``metadata.properties`` emitters for the CBOM.

These functions append QuReddy provenance to ``bom.metadata`` (the local
OpenSSL capability flags, scan status/target identity, the evidence trail,
and per-finding verdicts). They are split out of ``cbom.py`` to keep that
module under the file-size ceiling; the rendered CBOM is unchanged (#171).
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import TYPE_CHECKING

from cyclonedx.model import Property

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import OpenSSLDependency, ScanResult


def openssl_tool_properties(
    dependency: OpenSSLDependency, *, reproducible: bool = False
) -> list[Property]:
    """Carry the local OpenSSL capability flags (and path) onto the tool component.

    The CBOM kept only openssl's version, dropping the flags JSON's dependencies[]
    carries. Those flags decide whether a "no hybrid found" result is a real negative
    or a prober blind-spot: a consumer can't trust the inventory without them (#151).
    The absolute local path is host-specific, so it is omitted in reproducible mode so
    two hosts observing identical crypto produce the same digest (#162/#147 audit).
    """
    properties = [
        Property(name="qureddy:collector.role", value="local-probe-runtime"),
        Property(
            name="qureddy:openssl.supports_tls13_groups",
            value=str(dependency.supports_tls13_groups).lower(),
        ),
        Property(
            name="qureddy:openssl.supports_x25519mlkem768",
            value=str(dependency.supports_x25519mlkem768).lower(),
        ),
    ]
    if dependency.path is not None and not reproducible:
        properties.append(Property(name="qureddy:openssl.path", value=dependency.path))
    return properties


def add_scan_status_properties(bom: Bom, result: ScanResult) -> None:
    """Mirror scan.status/readiness/failure_category onto bom.metadata.properties.

    `bom.metadata.properties` is the standard CycloneDX extension point.
    Without this, a CBOM from a hard-failed scan (e.g. tls_handshake_failed)
    is structurally indistinguishable from a successful-but-sparse one —
    both can contain a real, valid certificate component (the certificate
    probe in cli.py runs independently of the main scan's forced-group
    probes and can succeed even when they fail), and there was previously
    no field anywhere in the CBOM itself recording that the scan failed.
    A consumer that stores/forwards only the CBOM JSON (no external exit
    code) had no way to tell these apart (issue #195).

    The readiness verdict is qureddy's headline conclusion and is carried in
    `--format json`; emitting it here keeps the CBOM self-describing so a
    consumer sees what qureddy concluded without re-deriving it (issue #132).
    """
    bom.metadata.properties.add(Property(name="qureddy:scan.status", value=result.scan.status))
    bom.metadata.properties.add(
        Property(name="qureddy:scan.readiness", value=result.summary.readiness.value)
    )
    if result.summary.failure_category is not None:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.failure_category",
                value=result.summary.failure_category.value,
            )
        )


def add_scan_target_metadata(bom: Bom, result: ScanResult, *, reproducible: bool = False) -> None:
    """Carry scan-identity/timing and structured target fields as metadata.properties.

    JSON exposes these; the CBOM previously kept only the emission timestamp and a
    `host:port` component name, so a CBOM-only consumer lost the scan id, timing,
    attempt count, and (critically) the SNI that determined what was actually
    probed (#152). In ``reproducible`` mode the per-run scan id and start/finish
    times are omitted so the output is content-addressable (#162).
    """
    scan = result.scan
    target = result.target
    pairs: list[tuple[str, str]] = [
        ("qureddy:scan.scanner_name", scan.scanner_name),
        ("qureddy:target.original_input", target.original_input),
        ("qureddy:target.host", target.host),
        ("qureddy:target.port", str(target.port)),
        ("qureddy:target.scheme", target.scheme),
        ("qureddy:target.locator", target.locator),
    ]
    if not reproducible:
        # total_attempts can vary with transient retries, so it is per-run too.
        pairs = [
            ("qureddy:scan.id", scan.scan_id),
            ("qureddy:scan.total_attempts", str(scan.total_attempts)),
            ("qureddy:scan.started_at", scan.started_at.isoformat()),
            ("qureddy:scan.completed_at", scan.completed_at.isoformat()),
            *pairs,
        ]
    if target.sni is not None:
        pairs.append(("qureddy:target.sni", target.sni))
    for name, value in pairs:
        bom.metadata.properties.add(Property(name=name, value=value))


def add_evidence_provenance(bom: Bom, result: ScanResult, *, reproducible: bool) -> None:
    """Attach the scan's evidence/provenance trail as namespaced metadata properties (#149).

    JSON carries `evidence[]` (source, observation_type, probe_role, and the probe_result
    command/return_code/hashes), but the CBOM dropped all of it and so could not answer
    "how do you know?". Emit one indexed block per evidence record, in deterministic scan
    order, so a CBOM consumer can audit/reproduce each observation without also parsing the
    JSON. The per-run probe duration is omitted in reproducible mode (#162).
    """
    for index, evidence in enumerate(result.evidence):
        # Zero-padded so the property names sort lexicographically in scan order
        # (evidence.02 before evidence.10), matching how CycloneDX serializes them (#147).
        prefix = f"qureddy:evidence.{index:02d}"
        pairs: list[tuple[str, str | None]] = [
            (f"{prefix}.type", evidence.evidence_type),
            (f"{prefix}.observation", evidence.observation_type.value),
            (f"{prefix}.source", evidence.source),
            (f"{prefix}.protocol_version", evidence.protocol_version),
            (f"{prefix}.cipher_suite", evidence.cipher_suite),
            (f"{prefix}.negotiated_group", evidence.negotiated_group),
            (f"{prefix}.probe_role", evidence.probe_role.value if evidence.probe_role else None),
            (f"{prefix}.expected_group", evidence.expected_group),
        ]
        probe = evidence.probe_result
        if probe is not None:
            # The probe executable is an absolute, host-specific path (e.g.
            # /opt/homebrew/opt/openssl@3.5/bin/openssl vs /usr/bin/openssl). In
            # reproducible mode canonicalize it to its basename before joining and
            # hashing, so two hosts that ran the same openssl subcommand from
            # different install locations produce a byte-identical command digest
            # (#207). The subcommand args are semantic (target host:port, forced
            # group), not host paths, so they are preserved verbatim. Non-
            # reproducible output keeps the exact local path for operator diagnostics.
            executable = (
                PurePosixPath(probe.command.executable).name
                if reproducible
                else probe.command.executable
            )
            command = " ".join([executable, *probe.command.args])
            pairs.extend(
                [
                    (f"{prefix}.command_sha256", hashlib.sha256(command.encode()).hexdigest()),
                    (f"{prefix}.return_code", str(probe.return_code)),
                    (f"{prefix}.stdout_sha256", probe.stdout_sha256),
                    (f"{prefix}.stderr_sha256", probe.stderr_sha256),
                    (f"{prefix}.attempt_number", str(probe.attempt_number)),
                ]
            )
            if not reproducible:
                pairs.append((f"{prefix}.duration_ms", str(probe.duration_ms)))
        for name, value in pairs:
            if value is not None:
                bom.metadata.properties.add(Property(name=name, value=value))


def add_finding_verdicts(bom: Bom, result: ScanResult) -> None:
    """Carry each finding's verdict (severity/readiness/rule) as metadata properties (#147).

    JSON's findings[] drive the posture; the CBOM previously carried only the top-level
    readiness (#132), so a consumer could not see per-finding severity or which rule fired.
    Emit one indexed block per finding; every field is deterministic (reproducible-safe).
    """
    for index, finding in enumerate(result.findings):
        prefix = f"qureddy:finding.{index:02d}"
        pairs = [
            (f"{prefix}.rule_id", finding.rule_id),
            (f"{prefix}.finding_type", finding.finding_type),
            (f"{prefix}.severity", finding.severity.value),
            (f"{prefix}.readiness", finding.readiness.value),
            (f"{prefix}.title", finding.title),
            (f"{prefix}.confidence", finding.confidence.value),
        ]
        for name, value in pairs:
            bom.metadata.properties.add(Property(name=name, value=value))
