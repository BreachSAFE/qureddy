# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Color and style tables for the Rich console adapter.

Extracted from console.py to keep that file under the 400-line hard
ceiling per docs/contributors/coding-rules.md Rule 2.2. Pure functions and tables —
no rendering, no I/O. The only consumers are the renderers in
console.py and tests under tests/test_output.py.

Color discipline (mirrored in console.py module docstring):

- PQ-positive signals (transitional_hybrid, quantum_safe, hybrid groups,
  supported capabilities) render in green so the eye can spot them.
- Routine quantum-vulnerable findings (classical X25519 from the control
  probe) render in yellow, not red. Every scan produces at least one
  classical-control finding by design; coloring it red would teach
  operators to ignore the alarm.
- Bold red is reserved for genuine breakage: classically_weak findings,
  critical/high severities, missing OpenSSL.
- Unknowns render dimly so attention falls on actionable cells.
"""

from __future__ import annotations

from rich.text import Text

from qureddy.core.models import (
    FailureCategory,
    OpenSSLDependency,
    Readiness,
    Severity,
)

DASH = "—"

PQ_GROUPS: frozenset[str] = frozenset(
    {"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"},
)
CLASSICAL_GROUPS: frozenset[str] = frozenset(
    {"X25519", "secp256r1", "secp384r1", "secp521r1"},
)

READINESS_STYLE: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "bold green",
    Readiness.TRANSITIONAL_HYBRID: "bold green",
    Readiness.QUANTUM_VULNERABLE: "yellow",
    Readiness.CLASSICALLY_WEAK: "bold red",
    Readiness.UNKNOWN: "dim",
    Readiness.NOT_APPLICABLE: "dim",
}

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "yellow",
    Severity.INFO: "dim cyan",
}

STATUS_STYLE: dict[str, str] = {
    "READY": "bold green",
    "NOT READY": "bold yellow",
    "FAIL": "bold red",
    "UNKNOWN": "dim",
}

VERDICT_BORDER: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "green",
    Readiness.TRANSITIONAL_HYBRID: "green",
    Readiness.QUANTUM_VULNERABLE: "yellow",
    Readiness.CLASSICALLY_WEAK: "red",
    Readiness.UNKNOWN: "dim",
    Readiness.NOT_APPLICABLE: "dim",
}

# Static recommendation text per readiness category. Recommendation copy
# is intentionally opinionated — that is the entire purpose of the row
# from a user perspective. Vendor names are deliberately avoided; the
# advice points at standards and capabilities, not products.
RECOMMENDATION_TEXT: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "No action required.",
    Readiness.TRANSITIONAL_HYBRID: (
        "Monitor; certificate and signature chain remain classical "
        "(cert scanning lands at MVP 0.2)."
    ),
    Readiness.QUANTUM_VULNERABLE: (
        "Plan PQ migration. Move TLS termination behind an edge that "
        "supports X25519MLKEM768, or upgrade to OpenSSL 3.5+ with PQ "
        "groups enabled."
    ),
    Readiness.CLASSICALLY_WEAK: (
        "Migrate immediately. Weak classical crypto is exploitable "
        "today; PQ readiness is moot until this is fixed."
    ),
    Readiness.NOT_APPLICABLE: "No applicable check for this target.",
}

LOCAL_CAPABILITY_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {
        FailureCategory.LOCAL_OPENSSL_MISSING,
        FailureCategory.LOCAL_OPENSSL_BROKEN,
        FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE,
        FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL,
        FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
    },
)


def style_readiness(readiness: Readiness) -> Text:
    """Render `readiness` as a colored Text per the readiness palette."""
    return Text(readiness.value, style=READINESS_STYLE.get(readiness, ""))


def style_severity(severity: Severity) -> Text:
    """Render `severity` as a colored Text per the severity palette."""
    return Text(severity.value, style=SEVERITY_STYLE.get(severity, ""))


def style_group(group: str | None) -> Text:
    """Render a TLS 1.3 group name with PQ/classical/unknown styling."""
    if not group:
        return Text(DASH, style="dim")
    if group in PQ_GROUPS:
        return Text(group, style="bold green")
    if group in CLASSICAL_GROUPS:
        return Text(group, style="yellow")
    return Text(group)


def style_path(dep: OpenSSLDependency) -> Text:
    """Render `dep.path`, marking missing paths in red `(missing)`."""
    if not dep.path:
        return Text("(missing)", style="red")
    return Text(dep.path)


def style_capability(dep: OpenSSLDependency) -> Text:
    """Render `dep.supports_x25519mlkem768` as a colored yes/no."""
    if dep.supports_x25519mlkem768:
        return Text("yes", style="green")
    return Text("no", style="red")


def styled_or_dash(value: str | None) -> Text:
    """Render `value` plain, falling back to a dim em dash on None."""
    if value is None:
        return Text(DASH, style="dim")
    return Text(value)


def verdict_border_style(readiness: Readiness) -> str:
    """Return the panel-border color matching the verdict readiness."""
    return VERDICT_BORDER.get(readiness, "dim")


def compose_status(word: str, trailing: str, *, group: str | None = None) -> Text:
    """Compose a status headline: bold colored verdict word + trailing prose.

    Optionally appends a styled group name after `trailing`. Used by
    `_summary_headline_and_recommendation` to build the verdict-panel
    body in the renderer module.
    """
    out = Text(word, style=STATUS_STYLE.get(word, ""))
    out.append(trailing)
    if group is not None:
        out.append(style_group(group))
    return out


def unknown_headline(failure: FailureCategory | None) -> Text:
    """Build the UNKNOWN-readiness headline given a failure category.

    Distinguishes local-capability failures (operator's openssl is the
    problem) from probe failures (the target wasn't reachable) so the
    one-line verdict tells the user where to look.
    """
    out = Text("UNKNOWN", style=STATUS_STYLE["UNKNOWN"])
    if failure is None:
        out.append(" — no signal")
    elif failure in LOCAL_CAPABILITY_CATEGORIES:
        out.append(f" — local OpenSSL cannot test ({failure.value})")
    else:
        out.append(f" — probe failed ({failure.value})")
    return out


def unknown_recommendation(failure: FailureCategory | None) -> str:
    """Recommendation copy for the UNKNOWN-readiness branch.

    Mirrors the local/probe split in `unknown_headline` so the headline
    and recommendation always agree on which side of the boundary the
    failure sits.
    """
    if failure is None:
        return "Re-run the scan with -v for diagnostics."
    if failure is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        return (
            "The openssl on this machine is LibreSSL, not OpenSSL — macOS ships "
            "LibreSSL as /usr/bin/openssl by default. Install real OpenSSL and "
            "point at it: brew install openssl@3, then pass "
            "--openssl $(brew --prefix openssl@3)/bin/openssl or export "
            "QUREDDY_OPENSSL to the same path."
        )
    if failure in LOCAL_CAPABILITY_CATEGORIES:
        return (
            "Install OpenSSL 3.5+ with PQ group support and re-run. "
            "The target's PQ posture is genuinely unknown until then."
        )
    return "Re-run the scan. Check connectivity, SNI, and that the target accepts TLS 1.3."
