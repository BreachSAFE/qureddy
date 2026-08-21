# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Property-based tests for the target parsers (issue #131).

QuReddy makes security claims about targets parsed from untrusted, user-supplied
strings. Example tests found #128 (non-canonical ports) and #130 (trailing-dot
FQDN) only after they shipped; property tests fuzz the parser's whole contract.

Two properties are asserted here:

  1. Crash-invariant: `parse_target` / `parse_ssh_target` return a ScanTarget or
     raise exactly `TargetParseError` for ANY input string -- never a leaked
     ValueError / IndexError / UnicodeError (the strong invariant #131 verified
     held on 12,000+ fuzzed inputs).
  2. Round-trip: a syntactically valid `host:port` parses to that host and port,
     and re-parsing the emitted `tls://` / `ssh://` locator yields the same
     endpoint (parsing is idempotent on its own canonical output).

Deterministic and fast: a module-local Hypothesis profile pins `derandomize`
(fixed example stream) and disables the per-example deadline (CI-jitter-proof).
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from qureddy.core.errors import TargetParseError
from qureddy.core.models import ScanTarget
from qureddy.core.targets import DEFAULT_PORT, DEFAULT_SSH_PORT, parse_ssh_target, parse_target

_FAST = settings(
    max_examples=200,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)

# Hostnames that always satisfy HOSTNAME_PATTERN and are never a numeric-IP form:
# 1-3 alphabetic labels. Kept alphabetic on purpose so the strategy never strays
# into the noncanonical-numeric-IP rejection path (#255), which is a separate
# (also tested) contract from these round-trip / crash properties.
_labels = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12)
_hostnames = st.lists(_labels, min_size=1, max_size=3).map(".".join)
_ports = st.integers(min_value=1, max_value=65535)


class TestCrashInvariant:
    """Only TargetParseError may escape, for any input -- issue #131."""

    @_FAST
    @given(raw=st.text(max_size=64))
    def test_parse_target_raises_only_target_parse_error(self, raw: str) -> None:
        try:
            result = parse_target(raw)
        except TargetParseError:
            return
        assert isinstance(result, ScanTarget)

    @_FAST
    @given(raw=st.text(max_size=64))
    def test_parse_ssh_target_raises_only_target_parse_error(self, raw: str) -> None:
        try:
            result = parse_ssh_target(raw)
        except TargetParseError:
            return
        assert isinstance(result, ScanTarget)

    @_FAST
    @given(host=_hostnames, port=st.text(alphabet="0123456789:", max_size=8))
    def test_host_colon_arbitrary_never_leaks_untyped_error(self, host: str, port: str) -> None:
        """`host:port`-shaped strings with arbitrary digit/colon tails still
        raise only the declared error type (the shape #128 regressed on)."""
        try:
            result = parse_target(f"{host}:{port}")
        except TargetParseError:
            return
        assert isinstance(result, ScanTarget)


class TestRoundTrip:
    """Valid endpoints parse to their components and re-parse idempotently."""

    @_FAST
    @given(host=_hostnames, port=_ports)
    def test_tls_host_port_round_trips_through_locator(self, host: str, port: int) -> None:
        target = parse_target(f"{host}:{port}")
        assert target.host == host
        assert target.port == port
        # Re-parsing the emitted canonical locator yields the same endpoint.
        reparsed = parse_target(target.locator)
        assert reparsed.host == host
        assert reparsed.port == port

    @_FAST
    @given(host=_hostnames)
    def test_tls_bare_host_defaults_to_443(self, host: str) -> None:
        assert parse_target(host).port == DEFAULT_PORT

    @_FAST
    @given(host=_hostnames, port=_ports)
    def test_ssh_host_port_round_trips_through_locator(self, host: str, port: int) -> None:
        target = parse_ssh_target(f"{host}:{port}")
        assert target.host == host
        assert target.port == port
        reparsed = parse_ssh_target(target.locator)
        assert reparsed.host == host
        assert reparsed.port == port

    @_FAST
    @given(host=_hostnames)
    def test_ssh_bare_host_defaults_to_22(self, host: str) -> None:
        assert parse_ssh_target(host).port == DEFAULT_SSH_PORT
