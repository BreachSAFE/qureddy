# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Contract tests for the container publication safety boundary."""

from __future__ import annotations

from pathlib import Path

WORKFLOW = (Path(__file__).parents[1] / ".github" / "workflows" / "container.yml").read_text()
DOCKERFILE = (Path(__file__).parents[1] / "Dockerfile").read_text()


def test_runtime_image_bundles_pinned_stock_ike_scan() -> None:
    """The published image must run the advertised IKE scanner without mutation."""
    runtime = DOCKERFILE[DOCKERFILE.rindex("FROM python:3.14-slim-bookworm") :]

    assert "ARG IKE_SCAN_VERSION=1.9.5-1+b1" in runtime
    assert '"ike-scan=${IKE_SCAN_VERSION}"' in runtime
    assert "rm -rf /var/lib/apt/lists/*" in runtime
    assert "/usr/share/doc/ike-scan/copyright" in runtime
    assert "GPL-3.0-or-later WITH openvpn-openssl-exception" in runtime
    assert 'io.breachsafe.qureddy.ike-scan.version="${IKE_SCAN_VERSION}"' in runtime
    assert runtime.index('"ike-scan=${IKE_SCAN_VERSION}"') < runtime.index("USER qureddy")


def test_container_smoke_executes_bundled_ike_scan() -> None:
    """CI must fail when the stock IKE dependency is absent or drifts."""
    smoke = WORKFLOW[: WORKFLOW.index("\n  version:\n")]

    assert "--entrypoint ike-scan" in smoke
    assert "--version" in smoke
    assert "io.breachsafe.qureddy.ike-scan.version" in smoke
    assert "-W -f='${Version}' ike-scan" in smoke
    assert 'test "$actual" = "$expected"' in smoke
    assert "test -r /usr/share/doc/ike-scan/copyright" in smoke


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
