# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the container publication safety boundary."""

from __future__ import annotations

from pathlib import Path

WORKFLOW = (Path(__file__).parents[1] / ".github" / "workflows" / "container.yml").read_text()


def test_mutable_image_tags_are_promoted_only_after_signature_verification() -> None:
    """A signing failure must leave only the immutable staging tag published."""
    staged_create = WORKFLOW.index(
        'docker buildx imagetools create --tag "ghcr.io/breachsafe/qureddy:sha-'
    )
    sign = WORKFLOW.index("cosign sign --yes")
    verify = WORKFLOW.index('cosign verify "$IMAGE@$digest"')
    promotion = WORKFLOW.index("Promote verified digest to release tags")
    mutable_promotion = WORKFLOW.index('docker buildx imagetools create --tag "$IMAGE:$tag"')

    assert staged_create < sign < verify < promotion < mutable_promotion
    assert 'for tag in "$QUREDDY_VERSION" latest' not in WORKFLOW[:promotion]
