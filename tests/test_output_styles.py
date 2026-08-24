# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for Rich style policy and unknown-readiness recommendations."""

from __future__ import annotations

from qureddy.core.models import (
    FailureCategory,
    HndlExposure,
    HygieneStatus,
    Readiness,
    Severity,
)
from qureddy.output._styles import (
    style_hndl,
    style_hygiene,
    unknown_headline,
    unknown_recommendation,
)
from qureddy.output.console import _style_group, _style_readiness, _style_severity


class TestColorStyleRules:
    """Helper-level tests verifying the documented color discipline.

    Color emission depends on terminal detection; testing the *styles*
    directly proves the color rules are wired correctly without
    depending on whether the test runner is a TTY.
    """

    def test_quantum_vulnerable_renders_yellow_not_red(self) -> None:
        """Routine classical findings must not be red — every scan
        produces one and red would be a false alarm."""
        styled = _style_readiness(Readiness.QUANTUM_VULNERABLE)
        assert "yellow" in str(styled.style)
        assert "red" not in str(styled.style)

    def test_classically_weak_renders_bold_red(self) -> None:
        """Genuine breakage gets the alarm color."""
        styled = _style_readiness(Readiness.CLASSICALLY_WEAK)
        assert styled.style == "bold red"

    def test_transitional_hybrid_renders_bold_green(self) -> None:
        styled = _style_readiness(Readiness.TRANSITIONAL_HYBRID)
        assert styled.style == "bold green"

    def test_pq_group_renders_bold_green(self) -> None:
        styled = _style_group("X25519MLKEM768")
        assert styled.style == "bold green"

    def test_classical_group_renders_yellow(self) -> None:
        styled = _style_group("X25519")
        assert styled.style == "yellow"

    def test_unknown_group_has_no_style(self) -> None:
        styled = _style_group("some_unknown_group")
        assert styled.style == ""

    def test_severity_critical_is_bold_red(self) -> None:
        assert _style_severity(Severity.CRITICAL).style == "bold red"

    def test_severity_info_is_dim(self) -> None:
        assert _style_severity(Severity.INFO).style == "dim"

    def test_hndl_defeasible_is_amber(self) -> None:
        assert style_hndl(HndlExposure.PROTECTED_DEFEASIBLE).style == "bold yellow"

    def test_hygiene_weak_is_red(self) -> None:
        assert style_hygiene(HygieneStatus.WEAK).style == "bold red"


class TestUnknownRecommendationLibreSSL:
    """Issue #188: the UNKNOWN-readiness recommendation must be LibreSSL-
    specific and actionable, not the generic "install OpenSSL 3.5.7 LTS" copy
    every other local-capability failure gets."""

    def test_headline_names_libressl_category(self) -> None:
        headline = unknown_headline(FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL)
        assert "local_openssl_is_libressl" in str(headline)

    def test_recommendation_names_the_fix(self) -> None:
        recommendation = unknown_recommendation(FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL)
        assert "LibreSSL" in recommendation
        assert "--openssl" in recommendation
        assert "QUREDDY_OPENSSL" in recommendation
        assert "checksum-verified" in recommendation
        assert "moving channel" in recommendation

    def test_other_local_categories_keep_generic_message(self) -> None:
        """Regression guard: the new branch must not swallow the existing
        generic message for other local-capability categories."""
        for category in (
            FailureCategory.LOCAL_OPENSSL_TOO_OLD,
            FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH,
        ):
            recommendation = unknown_recommendation(category)
            assert "Install OpenSSL 3.5.x LTS" in recommendation
            assert "3.5.7+" not in recommendation
