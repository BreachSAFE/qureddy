# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""SSH server-banner identity evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.ids import new_id
from qureddy.core.models import Asset, Evidence, ObservationType

if TYPE_CHECKING:
    from qureddy.scanners.ssh.probe import SSHServerIdentity


def server_identity_evidence(asset: Asset, identity: SSHServerIdentity) -> Evidence:
    """Record banner identity without treating it as a readiness signal."""
    version = identity.version or "unknown"
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="ssh.server",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.ssh.probe",
        protocol="ssh",
        protocol_version="2.0",
        server_software=identity.software,
        server_version=identity.version,
        notes=(f"SSH server software: {identity.software}", f"SSH server version: {version}"),
    )


def server_identity_observations(
    asset: Asset, identity: SSHServerIdentity | None
) -> tuple[Evidence, ...]:
    """Return zero or one identity observations for the scanner evidence list."""
    return () if identity is None else (server_identity_evidence(asset, identity),)
