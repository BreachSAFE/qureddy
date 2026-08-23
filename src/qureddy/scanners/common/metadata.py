# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Shared construction of run metadata for every scanner path."""

from __future__ import annotations

import os
from datetime import UTC, datetime

from qureddy.core.models import ScanMetadata, ScanProvenance


def _provenance_from_environment() -> ScanProvenance:
    """Read advisory build context without guessing absent Git/container state."""
    digest = os.environ.get("QUREDDY_CONTAINER_DIGEST") or os.environ.get("IMAGE_DIGEST")
    distribution = os.environ.get("QUREDDY_DISTRIBUTION")
    if distribution is None:
        distribution = "container" if digest else "unknown"
    dirty_raw = os.environ.get("QUREDDY_SOURCE_DIRTY")
    dirty = None if dirty_raw is None else dirty_raw.lower() == "true"
    return ScanProvenance(
        distribution=distribution,
        source_revision=os.environ.get("QUREDDY_SOURCE_REVISION") or os.environ.get("BUILD_COMMIT"),
        source_dirty=dirty,
        container_digest=digest,
    )


def build_scan_metadata(
    *,
    scan_id: str,
    started_at: datetime,
    scanner_name: str,
    status: str,
    total_attempts: int,
    completed_at: datetime | None = None,
) -> ScanMetadata:
    """Build immutable run metadata with one version/status contract."""
    return ScanMetadata(
        scan_id=scan_id,
        started_at=started_at,
        completed_at=completed_at or datetime.now(UTC),
        scanner_name=scanner_name,
        status=status,
        total_attempts=total_attempts,
        provenance=_provenance_from_environment(),
    )
