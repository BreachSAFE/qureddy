# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The one endpoint-asset builder shared by every scanner (#248).

Both the TLS and SSH scanners emit exactly one ``Asset`` per scanned endpoint,
identical but for ``asset_type`` and ``protocol``. This is that single builder;
previously each scanner carried its own near-duplicate copy.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.ids import new_id
from qureddy.core.models import Asset

if TYPE_CHECKING:
    from qureddy.core.models import ScanTarget


def build_endpoint_asset(target: ScanTarget, *, asset_type: str, protocol: str = "tls") -> Asset:
    """Build the single endpoint ``Asset`` for one scan.

    ``asset_type`` is the protocol-qualified kind (``tls.endpoint`` / ``ssh.endpoint``)
    and ``protocol`` is the transport (defaults to ``tls`` to match ``Asset``'s own
    default). Everything else is identical across scanners.
    """
    return Asset(
        id=new_id("asset"),
        asset_type=asset_type,
        locator=target.locator,
        display_name=f"{target.host}:{target.port}",
        protocol=protocol,
    )
