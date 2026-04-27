# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for the retry orchestrator and CLI argument validation."""

from __future__ import annotations

import hashlib

import pytest

from qureddy.core.errors import RetryConfigError
from qureddy.core.models import FailureCategory, ProbeCommand, ProbeResult
from qureddy.core.retry import (
    parse_retry_on,
    run_with_retries,
    validate_retry_args,
)


def _result(
    *,
    return_code: int = 0,
    failure_category: FailureCategory | None = None,
    attempt: int = 1,
) -> ProbeResult:
    return ProbeResult(
        command=ProbeCommand(
            executable="openssl",
            args=("s_client",),
            timeout_seconds=30,
        ),
        return_code=return_code,
        stdout_sha256=hashlib.sha256(b"").hexdigest(),
        stderr_sha256=hashlib.sha256(b"").hexdigest(),
        duration_ms=10,
        attempt_number=attempt,
        failure_category=failure_category,
    )


class TestParseRetryOn:
    def test_empty_input_yields_empty_set(self) -> None:
        assert parse_retry_on(None) == frozenset()
        assert parse_retry_on("") == frozenset()

    def test_single_retryable_category(self) -> None:
        assert parse_retry_on("target_connect_failed") == {
            FailureCategory.TARGET_CONNECT_FAILED,
        }

    def test_multiple_retryable_categories(self) -> None:
        result = parse_retry_on("target_connect_failed,tls_handshake_failed")
        assert FailureCategory.TARGET_CONNECT_FAILED in result
        assert FailureCategory.TLS_HANDSHAKE_FAILED in result

    def test_unknown_category_raises(self) -> None:
        with pytest.raises(RetryConfigError, match="unknown failure category"):
            parse_retry_on("nonsense_category")

    def test_non_retryable_category_raises(self) -> None:
        with pytest.raises(RetryConfigError, match="not retryable"):
            parse_retry_on("local_openssl_missing")

    def test_local_openssl_broken_is_not_retryable(self) -> None:
        with pytest.raises(RetryConfigError, match="not retryable"):
            parse_retry_on("local_openssl_broken")

    def test_parse_ambiguous_is_not_retryable(self) -> None:
        with pytest.raises(RetryConfigError, match="not retryable"):
            parse_retry_on("parse_ambiguous")


class TestValidateRetryArgs:
    def test_defaults_are_valid(self) -> None:
        validate_retry_args(retries=0, retry_delay=1.0, retry_on=frozenset())

    def test_negative_retries_rejected(self) -> None:
        with pytest.raises(RetryConfigError):
            validate_retry_args(retries=-1, retry_delay=1.0, retry_on=frozenset())

    def test_too_many_retries_rejected(self) -> None:
        with pytest.raises(RetryConfigError):
            validate_retry_args(retries=4, retry_delay=1.0, retry_on=frozenset())

    def test_negative_delay_rejected(self) -> None:
        with pytest.raises(RetryConfigError):
            validate_retry_args(retries=0, retry_delay=-0.1, retry_on=frozenset())

    def test_too_long_delay_rejected(self) -> None:
        with pytest.raises(RetryConfigError):
            validate_retry_args(retries=0, retry_delay=11.0, retry_on=frozenset())

    def test_retries_without_retry_on_rejected(self) -> None:
        with pytest.raises(RetryConfigError, match="no retry categories"):
            validate_retry_args(retries=2, retry_delay=1.0, retry_on=frozenset())


class TestRunWithRetries:
    def test_first_success_skips_retries(self) -> None:
        sleeps: list[float] = []
        results = run_with_retries(
            lambda n: _result(attempt=n),
            retries=3,
            retry_delay=1.0,
            retry_on=frozenset({FailureCategory.TARGET_CONNECT_FAILED}),
            sleep=sleeps.append,
        )
        assert len(results) == 1
        assert sleeps == []

    def test_retries_fire_on_matching_category(self) -> None:
        sleeps: list[float] = []
        results = run_with_retries(
            lambda n: _result(
                failure_category=FailureCategory.TARGET_CONNECT_FAILED,
                attempt=n,
            ),
            retries=3,
            retry_delay=0.5,
            retry_on=frozenset({FailureCategory.TARGET_CONNECT_FAILED}),
            sleep=sleeps.append,
        )
        assert len(results) == 4
        assert [r.attempt_number for r in results] == [1, 2, 3, 4]
        assert sleeps == [0.5, 0.5, 0.5]

    def test_non_matching_category_does_not_retry(self) -> None:
        sleeps: list[float] = []
        results = run_with_retries(
            lambda n: _result(
                failure_category=FailureCategory.TARGET_CONNECT_FAILED,
                attempt=n,
            ),
            retries=3,
            retry_delay=1.0,
            retry_on=frozenset({FailureCategory.TLS_HANDSHAKE_FAILED}),
            sleep=sleeps.append,
        )
        assert len(results) == 1
        assert sleeps == []

    def test_mid_stream_category_change_stops_retries(self) -> None:
        attempts: list[int] = []

        def probe(n: int) -> ProbeResult:
            attempts.append(n)
            if n == 1:
                return _result(
                    failure_category=FailureCategory.TARGET_CONNECT_FAILED,
                    attempt=n,
                )
            return _result(
                failure_category=FailureCategory.TLS_HANDSHAKE_FAILED,
                attempt=n,
            )

        results = run_with_retries(
            probe,
            retries=3,
            retry_delay=0.0,
            retry_on=frozenset({FailureCategory.TARGET_CONNECT_FAILED}),
            sleep=lambda _: None,
        )
        assert len(results) == 2
        assert results[1].failure_category is FailureCategory.TLS_HANDSHAKE_FAILED

    def test_recovery_to_success_stops_retries(self) -> None:
        attempts: list[int] = []

        def probe(n: int) -> ProbeResult:
            attempts.append(n)
            if n == 1:
                return _result(
                    failure_category=FailureCategory.TARGET_CONNECT_FAILED,
                    attempt=n,
                )
            return _result(attempt=n)

        results = run_with_retries(
            probe,
            retries=3,
            retry_delay=0.0,
            retry_on=frozenset({FailureCategory.TARGET_CONNECT_FAILED}),
            sleep=lambda _: None,
        )
        assert len(results) == 2
        assert results[1].failure_category is None
