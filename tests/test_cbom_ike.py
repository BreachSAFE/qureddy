# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKE-specific CBOM provenance and protocol-version tests."""

from __future__ import annotations

from cyclonedx.model.bom import Bom

from qureddy.core.models import ExternalToolDependency
from qureddy.output.cbom import _add_tool_provenance
from qureddy.output.cbom_components import _bare_protocol_version
from qureddy.output.cbom_metadata import tool_dependency_properties
from tests._cbom_fixtures import _build_result


def test_ike_protocol_version_uses_cyclonedx_major_minor_form() -> None:
    assert _bare_protocol_version("ike", "IKEv2") == "2.0"


def test_external_tool_provenance_preserves_path_only_when_nondeterministic() -> None:
    dependency = ExternalToolDependency(name="ike-scan", path="/usr/bin/ike-scan", version="1.9.5")
    result = _build_result().model_copy(update={"dependencies": (dependency,)})
    bom = Bom()

    _add_tool_provenance(bom, result)

    tool = next(item for item in bom.metadata.tools.components if item.name == "ike-scan")
    properties = {item.name: item.value for item in tool.properties}
    assert properties["qureddy:collector.role"] == "external-tool-adapter"
    assert properties["qureddy:collector.path"] == "/usr/bin/ike-scan"
    deterministic = tool_dependency_properties(dependency, reproducible=True)
    assert [item.name for item in deterministic] == ["qureddy:collector.role"]
