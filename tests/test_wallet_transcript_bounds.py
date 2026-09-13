# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""A5 for the wallet transcript: a bound that shapes output states itself.

The chain lane keeps a bounded copy of each response body so a transcript stays
readable. A `/txs` page runs past 200 KB, so the bound bites on ordinary input
rather than on an edge case. Before this, the body was sliced with no marker: a
transcript printed `received 227802 bytes`, stopped mid-object, and the sha256
that travels with it covered the shortened text.
"""

from __future__ import annotations

from qureddy.scanners.wallet.indexer import _MAX_BODY_TRACE, HttpExchange, bounded_body

_MARKER = "body truncated at"


def test_a_body_inside_the_bound_is_untouched() -> None:
    body = "x" * (_MAX_BODY_TRACE - 1)
    assert bounded_body(body) == body


def test_a_body_exactly_at_the_bound_is_untouched() -> None:
    body = "x" * _MAX_BODY_TRACE
    assert bounded_body(body) == body


def test_a_body_past_the_bound_states_the_bound_and_the_loss() -> None:
    body = "y" * (_MAX_BODY_TRACE + 260_000)
    bounded = bounded_body(body)
    assert bounded.startswith("y" * _MAX_BODY_TRACE)
    assert _MARKER in bounded
    assert str(_MAX_BODY_TRACE) in bounded
    assert "260000 dropped" in bounded


def test_the_marker_reaches_the_transcript_the_probe_result_carries() -> None:
    """The marker has to survive into the text that gets hashed and shown."""
    exchange = HttpExchange(method="GET", url="https://indexer.example/api/address/x")
    exchange.status = 200
    exchange.response_bytes = 300_000
    exchange.body_text = bounded_body("z" * 300_000)
    transcript = exchange.transcript()
    assert "* received 300000 bytes" in transcript
    assert _MARKER in transcript
