# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Short record-ID minting shared by every scanner + the policy engine (#248).

One scheme for asset/evidence/finding/scan identifiers so the prefix format and
hex length can't drift between protocols. Previously this lived as SSH's local
``_uid`` helper AND ~13 inline ``uuid.uuid4().hex[:12]`` copies across the TLS
scanner and the policy engine; a change to the length or shape in one copy would
silently diverge the others.
"""

from __future__ import annotations

import uuid

_ID_HEX_LEN = 12


def new_id(prefix: str) -> str:
    """Return a unique short id like ``ev-a1b2c3d4e5f6`` for ``prefix``.

    The prefix names the record kind (``asset`` / ``ev`` / ``finding`` / ``scan``);
    the suffix is the first ``_ID_HEX_LEN`` hex chars of a UUID4.
    """
    return f"{prefix}-{uuid.uuid4().hex[:_ID_HEX_LEN]}"
