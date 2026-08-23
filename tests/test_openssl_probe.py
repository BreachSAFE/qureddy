# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for openssl_probe capability detection using fake binaries.

Use Case 4 (Detect Unsupported Local OpenSSL) is covered here.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import Mock, patch

import pytest

import qureddy.scanners.tls.openssl_probe as openssl_probe_api
import qureddy.scanners.tls.openssl_probe._constants as constants_module
import qureddy.scanners.tls.openssl_probe.capability as capability_module
import qureddy.scanners.tls.openssl_probe.probe as probe_module
import qureddy.scanners.tls.openssl_probe.resolver as resolver_module
from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionMismatch,
    LocalOpenSSLVersionUnreadable,
    QureddyError,
)
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.openssl_probe import (
    probe_capability,
    raise_if_unusable,
    resolve_openssl_path,
    run_hybrid_probe,
)
from qureddy.scanners.tls.openssl_probe.capability import resolve_openssl_with_capability
from tests._fake_openssl import fake_openssl


def _probe_synthetic_version(
    version_banner: str,
    *,
    openssl_path: str = "/synthetic/openssl",
) -> OpenSSLDependency:
    """Probe a deterministic version banner with the required TLS group available."""
    with patch.object(
        capability_module,
        "run_openssl",
        side_effect=[version_banner, "X25519MLKEM768:x25519"],
    ):
        return probe_capability(openssl_path)


def test_public_api_exports_exact_adr_symbols_by_identity() -> None:
    """ADR 0005 compatibility symbols remain real re-exports, not copies."""
    expected = {
        "CLASSICAL_GROUP",
        "DEFAULT_TIMEOUT_SECONDS",
        "EXCERPT_LIMIT",
        "HYBRID_GROUP",
        "HYBRID_GROUPS",
        "MIN_OPENSSL_VERSION",
        "_classify_failure",
        "probe_capability",
        "raise_if_unusable",
        "resolve_openssl_path",
        "run_classical_probe",
        "run_hybrid_probe",
    }
    assert set(openssl_probe_api.__all__) == expected
    assert openssl_probe_api.MIN_OPENSSL_VERSION is constants_module.MIN_OPENSSL_VERSION
    assert constants_module.MIN_OPENSSL_VERSION is constants_module.PINNED_OPENSSL_VERSION
    assert openssl_probe_api.EXCERPT_LIMIT is constants_module.EXCERPT_LIMIT
    assert openssl_probe_api.DEFAULT_TIMEOUT_SECONDS is constants_module.DEFAULT_TIMEOUT_SECONDS
    assert openssl_probe_api.CLASSICAL_GROUP is constants_module.CLASSICAL_GROUP
    assert openssl_probe_api.HYBRID_GROUP is constants_module.HYBRID_GROUP
    assert openssl_probe_api.HYBRID_GROUPS is constants_module.HYBRID_GROUPS
    assert openssl_probe_api.run_classical_probe is probe_module.run_classical_probe
    assert openssl_probe_api.run_hybrid_probe is probe_module.run_hybrid_probe
    assert openssl_probe_api.probe_capability is capability_module.probe_capability
    assert openssl_probe_api.raise_if_unusable is capability_module.raise_if_unusable
    assert openssl_probe_api.resolve_openssl_path is capability_module.resolve_openssl_path


class TestResolveOpenSSLPath:
    def test_explicit_override_wins(self) -> None:
        binary = fake_openssl("openssl_ok")
        assert resolve_openssl_path(binary) == binary

    def test_missing_path_raises(self) -> None:
        with pytest.raises(LocalOpenSSLMissing) as exc_info:
            resolve_openssl_path("/this/path/does/not/exist/openssl")
        message = str(exc_info.value)
        assert "pip installs QuReddy, not OpenSSL" in message
        assert "macOS:" in message
        assert "Linux:" in message
        assert "Windows:" in message
        assert "--openssl PATH" in message
        assert "checksum-verified OpenSSL 3.5" in message
        assert "moving channel" in message

    def test_non_executable_raises(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        non_exec = tmp_path / "fake_openssl"
        non_exec.write_text("not executable\n")
        monkeypatch.setattr(
            "qureddy.scanners.tls.openssl_probe.capability.os.access",
            lambda *_args: False,
        )
        with pytest.raises(LocalOpenSSLMissing):
            resolve_openssl_path(str(non_exec))

    def test_search_retries_after_invalid_candidate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        dependency = OpenSSLDependency(path="/good/openssl", version="3.5.7")
        monkeypatch.delenv("QUREDDY_OPENSSL", raising=False)
        monkeypatch.setattr(
            resolver_module, "_candidate_paths", lambda: ["/bad/openssl", "/good/openssl"]
        )
        monkeypatch.setattr(
            resolver_module,
            "_validate_candidate",
            Mock(side_effect=[QureddyError("off-series"), dependency]),
        )

        path, result = resolve_openssl_with_capability(None)

        assert path == "/good/openssl"
        assert result is dependency

    def test_explicit_invalid_candidate_does_not_fall_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(resolver_module, "_candidate_paths", lambda: ["/good/openssl"])
        monkeypatch.setattr(
            resolver_module,
            "_validate_candidate",
            Mock(side_effect=QureddyError("invalid override")),
        )

        with pytest.raises(LocalOpenSSLMissing, match="invalid override"):
            resolve_openssl_with_capability("/explicit/openssl")


class TestProbeCapability:
    def test_non_launchable_binary_is_typed_local_failure(self) -> None:
        with (
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                side_effect=OSError(193, "not a valid application"),
            ),
            pytest.raises(LocalOpenSSLBroken, match="could not be launched"),
        ):
            probe_capability(fake_openssl("openssl_ok"))

    def test_probe_launch_oserror_is_typed_local_failure(self) -> None:
        with (
            patch(
                "qureddy.scanners.tls.openssl_probe.executor.subprocess.run",
                side_effect=OSError(193, "not a valid application"),
            ),
            # #296: launch failures are now centralized in executor.raise_for_launch,
            # so both call sites report the same canonical "could not be launched".
            pytest.raises(LocalOpenSSLBroken, match="could not be launched"),
        ):
            run_hybrid_probe(
                fake_openssl("openssl_ok"),
                host="example.invalid",
                port=443,
                sni="example.invalid",
            )

    def test_too_old_version_flagged(self) -> None:
        dep = probe_capability(fake_openssl("openssl_too_old"))
        assert dep.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD
        assert dep.version == "3.4.0"

    def test_lacks_group_flagged(self) -> None:
        dep = probe_capability(fake_openssl("openssl_lacks_group"))
        assert dep.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP
        assert dep.supports_tls13_groups is True
        assert dep.supports_x25519mlkem768 is False

    def test_supported_capability(self) -> None:
        dep = probe_capability(fake_openssl("openssl_ok"))
        assert dep.failure_category is None
        assert dep.supports_x25519mlkem768 is True
        assert dep.version == "3.5.7"

    def test_broken_returncode_flagged(self) -> None:
        with pytest.raises(LocalOpenSSLBroken) as exc_info:
            probe_capability(fake_openssl("openssl_broken_returncode"))
        assert "exited with code 139" in str(exc_info.value)
        assert "Library not loaded" in str(exc_info.value)
        assert exc_info.value.dependency is not None
        assert exc_info.value.dependency.failure_category is FailureCategory.LOCAL_OPENSSL_BROKEN

    def test_unparseable_version_flagged(self) -> None:
        dep = probe_capability(fake_openssl("openssl_unparseable_version"))
        assert dep.version is None
        assert dep.supports_tls13_groups is True
        assert dep.supports_x25519mlkem768 is True
        assert dep.failure_category is FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE

    def test_libressl_flagged_distinctly_not_as_unparseable(self) -> None:
        """Issue #188: macOS ships LibreSSL as /usr/bin/openssl by default.

        `OPENSSL_VERSION_PATTERN` never matches "LibreSSL 3.3.6" (it
        requires the literal "OpenSSL" prefix), so before this fix
        LibreSSL fell into the generic LOCAL_OPENSSL_VERSION_UNREADABLE
        bucket with no actionable fix-it message. It must instead be
        recognized as LibreSSL specifically.
        """
        dep = probe_capability(fake_openssl("openssl_libressl"))
        assert dep.failure_category is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL
        assert dep.version == "3.3.6"


class TestOpenSSLLtsSeriesContract:
    def test_exact_baseline_is_accepted(self) -> None:
        dep = _probe_synthetic_version("OpenSSL 3.5.7 7 Apr 2026")

        assert dep.failure_category is None
        assert dep.version == "3.5.7"
        assert dep.supports_x25519mlkem768 is True

    @pytest.mark.parametrize(
        ("version_banner", "expected_category"),
        [
            pytest.param(
                "OpenSSL 3.5.6 1 Apr 2026",
                "local_openssl_too_old",
                id="lower-patch",
            ),
            pytest.param(
                "OpenSSL 3.5.8 1 Jun 2026",
                None,
                id="higher-patch-accepted",
            ),
            pytest.param(
                "OpenSSL 3.4.99 1 Jan 2026",
                "local_openssl_too_old",
                id="different-minor",
            ),
            pytest.param(
                "OpenSSL 4.0.0 1 Jan 2027",
                "local_openssl_version_mismatch",
                id="different-major",
            ),
        ],
    )
    def test_lts_series_or_outside_series_is_classified(
        self,
        version_banner: str,
        expected_category: str | None,
    ) -> None:
        dep = _probe_synthetic_version(version_banner)

        if expected_category is None:
            assert dep.failure_category is None
        else:
            assert dep.failure_category is not None
            assert dep.failure_category.value == expected_category

    def test_moving_alias_accepts_supported_lts_patch(self) -> None:
        dep = _probe_synthetic_version(
            "OpenSSL 3.5.8 1 Jun 2026",
            openssl_path="/opt/homebrew/opt/openssl@3/bin/openssl",
        )

        assert dep.failure_category is None

    @pytest.mark.parametrize(
        "version_banner",
        [
            pytest.param("OpenSSL 3.5.7-dev 1 Jun 2026", id="development-suffix"),
            pytest.param("OpenSSL 3.5.7-beta1 1 Jun 2026", id="prerelease-suffix"),
        ],
    )
    def test_release_suffix_cannot_satisfy_exact_baseline(self, version_banner: str) -> None:
        dep = _probe_synthetic_version(version_banner)

        assert dep.failure_category is not None
        assert dep.failure_category.value == "local_openssl_too_old"

    def test_linked_library_must_remain_on_supported_lts_series(self) -> None:
        dep = _probe_synthetic_version(
            "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.8 1 Jun 2026)",
        )

        assert dep.failure_category is None

    def test_matching_cli_and_linked_library_versions_are_accepted(self) -> None:
        dep = _probe_synthetic_version(
            "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.7 9 Jun 2026)",
        )

        assert dep.failure_category is None
        assert dep.version == "3.5.7"

    @pytest.mark.parametrize(
        ("version_banner", "expected_category"),
        [
            pytest.param(
                "OpenSSL 3",
                FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
                id="moving-major-channel",
            ),
            pytest.param(
                "OpenSSL 3.5",
                FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
                id="moving-minor-channel",
            ),
            pytest.param(
                "LibreSSL rolling",
                FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL,
                id="different-product",
            ),
            pytest.param(
                "VendorTLS development snapshot",
                FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
                id="unparseable",
            ),
        ],
    )
    def test_nonexact_version_inputs_keep_specific_failure_categories(
        self,
        version_banner: str,
        expected_category: FailureCategory,
    ) -> None:
        dep = _probe_synthetic_version(version_banner)

        assert dep.failure_category is expected_category

    @pytest.mark.parametrize(
        ("version_banner", "expected_error"),
        [
            pytest.param(
                "OpenSSL 3.5.6 1 Apr 2026",
                LocalOpenSSLTooOld,
                id="lower-patch",
            ),
            pytest.param(
                "OpenSSL 4.0.0 1 Jan 2027",
                LocalOpenSSLVersionMismatch,
                id="different-major",
            ),
        ],
    )
    def test_parseable_outside_series_error_names_detected_and_required_versions(
        self,
        version_banner: str,
        expected_error: type[QureddyError],
    ) -> None:
        dep = _probe_synthetic_version(version_banner)

        with pytest.raises(expected_error) as exc_info:
            raise_if_unusable(dep)

        message = str(exc_info.value)
        assert dep.version is not None
        assert dep.version in message
        assert "3.5.x" in message
        assert "3.5.7+" not in message
        assert "or newer" not in message.lower()

    def test_libressl_guidance_names_exact_supported_release(self) -> None:
        dep = _probe_synthetic_version("LibreSSL rolling")

        with pytest.raises(LocalOpenSSLIsLibreSSL) as exc_info:
            raise_if_unusable(dep)

        message = str(exc_info.value)
        assert "LibreSSL rolling" in message
        assert "3.5.x" in message
        assert "3.5.7+" not in message
        assert "--openssl" in message
        assert "QUREDDY_OPENSSL" in message
        assert "checksum-verified" in message
        assert "moving channel" in message


class TestRaiseIfUnusable:
    def test_too_old_raises(self) -> None:
        dep = probe_capability(fake_openssl("openssl_too_old"))
        with pytest.raises(LocalOpenSSLTooOld) as exc_info:
            raise_if_unusable(dep)
        message = str(exc_info.value)
        assert "OpenSSL 3.4.0 is below the required 3.5.x LTS series" in message
        assert "pip installs QuReddy, not OpenSSL" in message
        assert "QUREDDY_OPENSSL" in message

    def test_unparseable_version_message_is_readable(self) -> None:
        dep = probe_capability(fake_openssl("openssl_unparseable_version"))
        with pytest.raises(LocalOpenSSLVersionUnreadable) as exc_info:
            raise_if_unusable(dep)
        message = str(exc_info.value)
        assert "unparseable version output" in message
        assert fake_openssl("openssl_unparseable_version") in message
        assert "OpenSSL None" not in message

    def test_lacks_group_raises(self) -> None:
        dep = probe_capability(fake_openssl("openssl_lacks_group"))
        with pytest.raises(LocalOpenSSLLacksGroup):
            raise_if_unusable(dep)

    def test_libressl_message_names_libressl_and_the_fix(self) -> None:
        """The whole point of #188: the message must say *why* (this is
        LibreSSL, not old/broken OpenSSL) and *how to fix it*
        (--openssl / QUREDDY_OPENSSL), not just "unparseable version"."""
        dep = probe_capability(fake_openssl("openssl_libressl"))
        with pytest.raises(LocalOpenSSLIsLibreSSL) as exc_info:
            raise_if_unusable(dep)
        message = str(exc_info.value)
        assert "LibreSSL" in message
        assert "3.3.6" in message
        assert "--openssl" in message
        assert "QUREDDY_OPENSSL" in message

    def test_ok_does_not_raise(self) -> None:
        dep = probe_capability(fake_openssl("openssl_ok"))
        raise_if_unusable(dep)


class TestLocalOpenSSLExceptionsCarryDependency:
    """`raise_if_unusable` and `resolve_openssl_path` must populate the
    exception's `dependency` attribute so the CLI doesn't have to
    re-probe to build a capability-failure result.
    """

    def test_too_old_exception_carries_dependency(self) -> None:
        dep = probe_capability(fake_openssl("openssl_too_old"))
        with pytest.raises(LocalOpenSSLTooOld) as exc_info:
            raise_if_unusable(dep)
        assert exc_info.value.dependency is dep
        assert exc_info.value.dependency.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD

    def test_lacks_group_exception_carries_dependency(self) -> None:
        dep = probe_capability(fake_openssl("openssl_lacks_group"))
        with pytest.raises(LocalOpenSSLLacksGroup) as exc_info:
            raise_if_unusable(dep)
        assert exc_info.value.dependency is dep

    def test_resolve_missing_exception_carries_dependency(self) -> None:
        with pytest.raises(LocalOpenSSLMissing) as exc_info:
            resolve_openssl_path("/this/path/does/not/exist/openssl")
        # Even on the resolve path (no probe ran), the exception still
        # carries a populated OpenSSLDependency so callers don't have
        # to construct a default in the catch block.
        assert exc_info.value.dependency is not None
        assert exc_info.value.dependency.failure_category is FailureCategory.LOCAL_OPENSSL_MISSING
