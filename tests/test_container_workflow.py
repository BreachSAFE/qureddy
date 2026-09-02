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
    verify = WORKFLOW.index('scripts/verify_container_signature.sh "$IMAGE@$digest"')
    promotion = WORKFLOW.index("Promote verified digest to release tags")
    mutable_promotion = WORKFLOW.index('docker buildx imagetools create --tag "$IMAGE:$tag"')

    assert staged_create < sign < verify < promotion < mutable_promotion
    assert 'for tag in "$QUREDDY_VERSION" latest' not in WORKFLOW[:promotion]


def test_docker_hub_tags_move_only_after_destination_signature_verifies() -> None:
    """A mirror-signing failure must not move Docker Hub release tags."""
    mirror = WORKFLOW[WORKFLOW.index("Promote the signed digest to Docker Hub") :]
    staging = mirror.index('--tag "$DEST_IMAGE:sha-${GITHUB_SHA::12}"')
    sign = mirror.index('cosign sign --yes "$DEST_IMAGE@$destination_digest"')
    verify = mirror.index('scripts/verify_container_signature.sh "$DEST_IMAGE@$destination_digest"')
    promotion = mirror.index('for tag in "$QUREDDY_VERSION" latest')
    mutable_tag = mirror.index('--tag "$DEST_IMAGE:$tag"')

    assert staging < sign < verify < promotion < mutable_tag
    assert "cosign copy" not in mirror


def test_all_container_signature_checks_use_the_bounded_helper() -> None:
    """Every registry verification must share the tested propagation policy."""
    assert "cosign verify" not in WORKFLOW
    assert WORKFLOW.count("scripts/verify_container_signature.sh") == 4


def test_manifest_job_checks_out_repository_before_using_its_scripts() -> None:
    """Artifact-only jobs must fetch source before invoking repository scripts."""
    manifest = WORKFLOW[WORKFLOW.index("\n  manifest:\n") :]
    checkout = manifest.index("uses: actions/checkout@")
    no_credentials = manifest.index("persist-credentials: false", checkout)
    download = manifest.index("uses: actions/download-artifact@")
    verify = manifest.index("scripts/verify_container_signature.sh")

    assert checkout < no_credentials < download < verify
