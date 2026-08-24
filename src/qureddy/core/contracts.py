# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Typed seams shared by protocol-specific scanners.

The contract deliberately stops at ``ScanResult``. Serialization and OSCAL
projection remain downstream concerns. Outputs consume canonical core models
and neutral semantic facts; they must not import protocol-private scanner
modules. A future scanner may reuse this result boundary, but a general scanner
registry is intentionally deferred until a third source is approved.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, TypeVar, runtime_checkable

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

SubjectT_contra = TypeVar("SubjectT_contra", contravariant=True)


@runtime_checkable
class Scanner(Protocol[SubjectT_contra]):
    """A protocol-specific collector with one canonical result boundary."""

    scanner_name: str

    def scan(self, subject: SubjectT_contra, *, timeout_seconds: int) -> ScanResult:
        """Collect protocol evidence and return the canonical scan result."""
