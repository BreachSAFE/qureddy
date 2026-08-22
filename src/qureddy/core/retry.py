# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Retry orchestration for the TLS scanner."""

from __future__ import annotations

import time
from collections.abc import Callable

from qureddy.core.errors import RetryConfigError
from qureddy.core.models import FailureCategory, ProbeResult

RETRYABLE_CATEGORIES: frozenset[FailureCategory] = frozenset(
    {
        FailureCategory.TARGET_CONNECT_FAILED,
        FailureCategory.TLS_HANDSHAKE_FAILED,
        FailureCategory.MIDDLEBOX_OR_MTU_FAILURE,
        FailureCategory.PARSE_NO_GROUP,
    },
)
MAX_RETRIES = 3
MAX_RETRY_DELAY_SECONDS = 10.0


def _parse_retry_category(token: str) -> FailureCategory:
    """Resolve one --retry-on token to a retryable category or raise."""
    try:
        category = FailureCategory(token)
    except ValueError as exc:
        msg = f"unknown failure category: {token!r}"
        raise RetryConfigError(msg) from exc
    if category not in RETRYABLE_CATEGORIES:
        allowed = ", ".join(sorted(c.value for c in RETRYABLE_CATEGORIES))
        msg = f"failure category {category.value!r} is not retryable; allowed: {allowed}"
        raise RetryConfigError(msg)
    return category


def parse_retry_on(value: str | None) -> frozenset[FailureCategory]:
    """Parse a comma-separated --retry-on argument into a category set.

    Raises RetryConfigError for unknown categories or categories outside
    the retryable allowlist.
    """
    if not value:
        return frozenset()

    parsed: set[FailureCategory] = set()
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            continue
        parsed.add(_parse_retry_category(token))
    return frozenset(parsed)


def validate_retry_args(
    retries: int,
    retry_delay: float,
    retry_on: frozenset[FailureCategory],
) -> None:
    """Validate retry CLI arguments. Raises RetryConfigError on bad input."""
    if not 0 <= retries <= MAX_RETRIES:
        msg = f"--retries must be in [0, {MAX_RETRIES}]; got {retries}"
        raise RetryConfigError(msg)
    if not 0.0 <= retry_delay <= MAX_RETRY_DELAY_SECONDS:
        msg = f"--retry-delay must be in [0.0, {MAX_RETRY_DELAY_SECONDS}]; got {retry_delay}"
        raise RetryConfigError(msg)
    if retries > 0 and not retry_on:
        msg = "--retries N > 0 requires --retry-on; no retry categories specified"
        raise RetryConfigError(msg)


def run_with_retries(
    probe: Callable[[int], ProbeResult],
    *,
    retries: int,
    retry_delay: float,
    retry_on: frozenset[FailureCategory],
    sleep: Callable[[float], None] = time.sleep,
) -> list[ProbeResult]:
    """Run `probe` once, then retry under the allowlist.

    Args:
        probe: Callable that takes the 1-based attempt number and returns
            a ProbeResult.
        retries: Number of additional attempts after the first.
        retry_delay: Seconds to sleep between attempts.
        retry_on: Allowlist of failure categories that trigger a retry.
        sleep: Injectable sleep function (defaults to time.sleep). Tests
            substitute a deterministic recorder.

    Returns:
        All ProbeResult records, in attempt order. Always at least one.
    """
    results: list[ProbeResult] = []
    first = probe(1)
    results.append(first)

    if not _should_retry(first.failure_category, retry_on):
        return results

    for attempt in range(2, retries + 2):
        sleep(retry_delay)
        result = probe(attempt)
        results.append(result)
        if not _should_retry(result.failure_category, retry_on):
            return results

    return results


def _should_retry(
    category: FailureCategory | None,
    retry_on: frozenset[FailureCategory],
) -> bool:
    """True when the failure category is inside the retry_on allowlist."""
    return category is not None and category in retry_on
