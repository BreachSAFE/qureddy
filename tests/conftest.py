# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Shared pytest fixtures and helpers for QuReddy tests."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest


@pytest.fixture
def fixed_timestamp() -> datetime:
    """A fixed UTC timestamp so models built in tests are deterministic."""
    return datetime(2026, 4, 26, 17, 0, 0, tzinfo=UTC)
