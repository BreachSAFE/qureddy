# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Certificate-domain projection tests."""

from __future__ import annotations

import pytest

from qureddy.core.certificate import parse_openssl_date


@pytest.mark.parametrize(
    "value",
    [
        "",
        "Foo 17 07:18:11 2026 GMT",
        "Feb 30 07:18:11 2026 GMT",
    ],
)
def test_invalid_openssl_date_is_absent(value: str) -> None:
    assert parse_openssl_date(value) is None
