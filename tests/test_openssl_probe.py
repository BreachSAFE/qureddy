# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Tests for openssl_probe capability detection using fake binaries.

Use Case 4 (Detect Unsupported Local OpenSSL) is covered here.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest

import qureddy.scanners.tls.openssl_probe as openssl_probe_api
import qureddy.scanners.tls.openssl_probe._constants as constants_module
import qureddy.scanners.tls.openssl_probe.capability as capability_module
import qureddy.scanners.tls.openssl_probe.probe as probe_module
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
from qureddy.core.models import FailureCategory, OpenSSLDependency, ProbeResult
from qureddy.scanners.tls.openssl_probe import (
    _classify_failure,
    probe_capability,
    raise_if_unusable,
    resolve_openssl_path,
    run_hybrid_probe,
)
from qureddy.scanners.tls.openssl_probe._results import result_from_timeout
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
        assert "checksum-verified OpenSSL 3.5.7" in message
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


class TestProbeCapability:
    def test_non_launchable_binary_is_typed_local_failure(self) -> None:
        with (
            patch("subprocess.run", side_effect=OSError(193, "not a valid application")),
            pytest.raises(LocalOpenSSLBroken, match="could not be launched"),
        ):
            probe_capability(fake_openssl("openssl_ok"))

    def test_probe_launch_oserror_is_typed_local_failure(self) -> None:
        with (
            patch("subprocess.run", side_effect=OSError(193, "not a valid application")),
            pytest.raises(LocalOpenSSLBroken, match="became unlaunchable"),
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


class TestExactOpenSSLVersionContract:
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
                "local_openssl_version_mismatch",
                id="higher-patch",
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
    def test_every_parseable_nonbaseline_release_is_rejected(
        self,
        version_banner: str,
        expected_category: str,
    ) -> None:
        dep = _probe_synthetic_version(version_banner)

        assert dep.failure_category is not None
        assert dep.failure_category.value == expected_category

    def test_moving_alias_cannot_bypass_exact_release_gate(self) -> None:
        dep = _probe_synthetic_version(
            "OpenSSL 3.5.8 1 Jun 2026",
            openssl_path="/opt/homebrew/opt/openssl@3/bin/openssl",
        )

        assert dep.failure_category is not None
        assert dep.failure_category.value == "local_openssl_version_mismatch"

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
        assert dep.failure_category.value == "local_openssl_version_mismatch"

    def test_linked_library_must_match_cli_version_and_exact_baseline(self) -> None:
        dep = _probe_synthetic_version(
            "OpenSSL 3.5.7 9 Jun 2026 (Library: OpenSSL 3.5.8 1 Jun 2026)",
        )

        assert dep.failure_category is not None
        assert dep.failure_category.value == "local_openssl_version_mismatch"
        with pytest.raises(LocalOpenSSLVersionMismatch) as exc_info:
            raise_if_unusable(dep)

        message = str(exc_info.value)
        assert "Library" in message
        assert "3.5.8" in message
        assert "required 3.5.7" in message

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
                "OpenSSL 3.5.8 1 Jun 2026",
                LocalOpenSSLVersionMismatch,
                id="higher-patch",
            ),
            pytest.param(
                "OpenSSL 4.0.0 1 Jan 2027",
                LocalOpenSSLVersionMismatch,
                id="different-major",
            ),
        ],
    )
    def test_parseable_nonbaseline_error_names_detected_and_required_versions(
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
        assert "3.5.7" in message
        assert "3.5.7+" not in message
        assert "or newer" not in message.lower()

    def test_libressl_guidance_names_exact_supported_release(self) -> None:
        dep = _probe_synthetic_version("LibreSSL rolling")

        with pytest.raises(LocalOpenSSLIsLibreSSL) as exc_info:
            raise_if_unusable(dep)

        message = str(exc_info.value)
        assert "LibreSSL rolling" in message
        assert "3.5.7" in message
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
        assert "OpenSSL 3.4.0 is below required 3.5.7" in message
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


class TestTimeoutClassification:
    """A timeout is unreachable only when the TCP connect never completed (#138)."""

    @staticmethod
    def _timeout_result(output: bytes) -> ProbeResult:
        exc = subprocess.TimeoutExpired(cmd=["openssl"], timeout=2, output=output, stderr=b"")
        return result_from_timeout(["openssl"], exc, datetime.now(UTC), 2, 1)

    def test_timeout_before_connect_is_unreachable(self) -> None:
        result = self._timeout_result(b"")
        assert result.failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_timeout_after_connect_stays_handshake(self) -> None:
        result = self._timeout_result(b"CONNECTED(00000003)\n")
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED


class TestStderrClassification:
    """Probe-level stderr classification per blocker 4.

    The probe module itself classifies nonzero exits into specific
    failure categories so retry policy and policy classification get
    the right signal. Collapsing to TLS_HANDSHAKE_FAILED later loses
    that fidelity.
    """

    def test_connect_refused_is_target_connect_failed(self) -> None:
        result = run_hybrid_probe(
            fake_openssl("openssl_connect_refused"),
            "192.0.2.1",
            443,
            None,
            timeout_seconds=5,
        )
        assert result.return_code != 0
        assert result.failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_handshake_failure_is_tls_handshake_failed(self) -> None:
        result = run_hybrid_probe(
            fake_openssl("openssl_handshake_failure"),
            "104.154.89.105",
            1012,
            None,
            timeout_seconds=5,
        )
        assert result.return_code != 0
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED

    def test_classify_failure_dispatch(self) -> None:
        """Direct check that _classify_failure picks the most specific category."""
        assert _classify_failure("connect:errno=61") is FailureCategory.TARGET_CONNECT_FAILED
        assert (
            _classify_failure("getaddrinfo: nodename nor servname provided")
            is FailureCategory.TARGET_CONNECT_FAILED
        )
        assert (
            _classify_failure("ssl/tls alert handshake failure")
            is FailureCategory.TLS_HANDSHAKE_FAILED
        )
        assert (
            _classify_failure("tlsv1 alert unrecognized name")
            is FailureCategory.SNI_REQUIRED_OR_WRONG
        )
        assert (
            _classify_failure("Connection reset by peer")
            is FailureCategory.MIDDLEBOX_OR_MTU_FAILURE
        )
        # Unknown stderr shape falls back to TLS_HANDSHAKE_FAILED.
        assert _classify_failure("") is FailureCategory.TLS_HANDSHAKE_FAILED
        assert _classify_failure("some weird unknown error") is FailureCategory.TLS_HANDSHAKE_FAILED


# Parametrized coverage for every classifier pattern. Lifted from
# the pre-archive test suite; each row is a real OpenSSL
# stderr fragment seen in the wild. Adding a new pattern to
# `_STDERR_SIGNATURES` should mean adding a row here in the same PR.
@pytest.mark.parametrize(
    ("stderr_fragment", "expected_category"),
    [
        # DNS / resolver
        ("getaddrinfo: nodename nor servname provided", FailureCategory.TARGET_CONNECT_FAILED),
        ("name or service not known", FailureCategory.TARGET_CONNECT_FAILED),
        ("could not resolve", FailureCategory.TARGET_CONNECT_FAILED),
        ("Temporary failure in name resolution", FailureCategory.TARGET_CONNECT_FAILED),
        # TCP-layer connect failures
        ("connect:errno=61", FailureCategory.TARGET_CONNECT_FAILED),
        ("connection refused on port 443", FailureCategory.TARGET_CONNECT_FAILED),
        ("Connection timed out", FailureCategory.TARGET_CONNECT_FAILED),
        ("Operation timed out", FailureCategory.TARGET_CONNECT_FAILED),
        ("No route to host", FailureCategory.TARGET_CONNECT_FAILED),
        ("Network is unreachable", FailureCategory.TARGET_CONNECT_FAILED),
        ("Host is down", FailureCategory.TARGET_CONNECT_FAILED),
        # SNI failures
        ("alert handshake failure", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("alert unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
        ("SSL alert number 112", FailureCategory.SNI_REQUIRED_OR_WRONG),
        ("tlsv1 unrecognized name", FailureCategory.SNI_REQUIRED_OR_WRONG),
        # TLS handshake-level alerts
        ("SSL alert number 40", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("alert protocol version", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("inappropriate fallback", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("no shared cipher", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("no shared groups", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("wrong version number", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("unsupported protocol", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("decode error", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("decrypt error", FailureCategory.TLS_HANDSHAKE_FAILED),
        ("bad record mac", FailureCategory.TLS_HANDSHAKE_FAILED),
        # Middlebox / MTU patterns
        ("EPIPE", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Broken pipe", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Connection reset by peer", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("ssl_read returned 0", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("ssl_read_internal: bad something", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("unexpected EOF while reading", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Message too long", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("Fragmentation needed", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
        ("premature close", FailureCategory.MIDDLEBOX_OR_MTU_FAILURE),
    ],
)
def test_classify_failure_recognizes_known_patterns(
    stderr_fragment: str, expected_category: FailureCategory
) -> None:
    """Every entry in `_STDERR_SIGNATURES` has at least one test row.

    Lifted from the pre-archive implementation before that staging tree
    was archived. Ensures regressions don't quietly drop a pattern.
    """
    assert _classify_failure(stderr_fragment) is expected_category


class TestTimeoutPreservesPartialOutput:
    """`subprocess.TimeoutExpired` carries any output produced before
    the kill. The probe must NOT discard it.

    Reviewer-flagged bug: the legacy timeout branch replaced
    stdout/stderr with sha256(b"") and a synthetic message, losing
    forensic data. This test asserts the new behavior preserves bytes.
    """

    def test_timeout_preserves_partial_stdout_hash(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["openssl"],
            timeout=1,
            output=b"CONNECTED(00000003)\npartial-stdout-marker\n",
            stderr=b"",
        )
        with patch("subprocess.run", side_effect=timeout):
            result = run_hybrid_probe(
                fake_openssl("openssl_ok"),
                "192.0.2.99",
                443,
                None,
                timeout_seconds=1,
            )
        empty_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert result.failure_category is FailureCategory.TLS_HANDSHAKE_FAILED
        assert result.return_code == -1
        # Stdout came through; hash is NOT the empty-string hash.
        assert result.stdout_sha256 != empty_hash, (
            "timeout branch lost partial stdout — should preserve bytes received before the kill"
        )
        assert "partial-stdout-marker" in result.stdout_excerpt

    def test_timeout_preserves_partial_stderr_with_marker(self) -> None:
        timeout = subprocess.TimeoutExpired(
            cmd=["openssl"],
            timeout=1,
            output=b"partial-stdout-marker\n",
            stderr=b"CONNECTION ESTABLISHED\n",
        )
        with patch("subprocess.run", side_effect=timeout):
            result = run_hybrid_probe(
                fake_openssl("openssl_ok"),
                "192.0.2.99",
                443,
                None,
                timeout_seconds=1,
            )
        # stderr captured the connection lines AND the timeout marker
        # the probe added on the timeout branch.
        assert "CONNECTION ESTABLISHED" in result.stderr_excerpt
        assert "[qureddy] timeout after 1s" in result.stderr_excerpt


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
