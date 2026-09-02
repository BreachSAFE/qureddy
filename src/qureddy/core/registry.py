# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Deterministic collector registration and selection.

Execution, timeout, retry, and partial-result aggregation deliberately live outside
this module. Keeping selection pure makes source extensibility testable without
network or subprocess fixtures.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from qureddy.core.contracts import (
    Capability,
    Collector,
    ScanCollector,
    ScanSource,
    SourceKind,
    ToolPolicy,
)


class CollectorSelectionError(ValueError):
    """Raised when no registered collector can satisfy a source request."""


@dataclass(slots=True)
class CollectorRegistry:
    """Registry with deterministic, capability-based collector selection."""

    _collectors: list[Collector] = field(default_factory=list)

    def register(self, collector: Collector) -> None:
        """Register one collector by unique name."""
        if any(item.collector_name == collector.collector_name for item in self._collectors):
            raise ValueError(f"collector already registered: {collector.collector_name}")
        self._collectors.append(collector)

    def select(self, source: ScanSource, *, tool_policy: ToolPolicy = ToolPolicy.AUTO) -> Collector:
        """Select the first registered collector satisfying source and policy."""
        capability = _capability_for(source)
        candidates = [item for item in self._collectors if capability in item.capabilities]
        if tool_policy is not ToolPolicy.AUTO:
            candidates = [item for item in candidates if _matches_policy(item, tool_policy)]
        if not candidates:
            policy = tool_policy.value
            raise CollectorSelectionError(
                f"no collector for source={source.kind.value!r}, protocol={source.protocol!r}, "
                f"tool_policy={policy!r}"
            )
        return candidates[0]

    def select_scanner(
        self, source: ScanSource, *, tool_policy: ToolPolicy = ToolPolicy.AUTO
    ) -> ScanCollector:
        """Select a collector that is safe to use as a live scanner."""
        selected = self.select(source, tool_policy=tool_policy)
        if not isinstance(selected, ScanCollector):
            raise CollectorSelectionError(
                f"collector {selected.collector_name!r} cannot execute a scan"
            )
        return selected


def _capability_for(source: ScanSource) -> Capability:
    if source.kind is SourceKind.CERTIFICATE:
        return Capability.X509_CERTIFICATE
    if source.kind is SourceKind.SSH_PUBLIC_KEY:
        return Capability.SSH_PUBLIC_KEY
    if source.kind is SourceKind.SSH_CONFIG:
        return Capability.SSH_CONFIG
    if source.protocol == "tls":
        return Capability.TLS_ENDPOINT
    if source.protocol == "ssh":
        return Capability.SSH_ENDPOINT
    if source.protocol == "ike":
        return Capability.IKE_ENDPOINT
    raise CollectorSelectionError(
        f"source protocol is required for endpoint selection: {source.protocol!r}"
    )


def _matches_policy(collector: Collector, policy: ToolPolicy) -> bool:
    if policy is ToolPolicy.NATIVE:
        return collector.collector_name.startswith("native-")
    return collector.collector_name == policy.value
