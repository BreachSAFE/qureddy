# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Atheris fuzz harnesses for QuReddy's untrusted-input parsers (issue #86).

Each ``fuzz_*.py`` module is a standalone libFuzzer/Atheris entrypoint, not a
pytest test: the ``fuzz_`` filename prefix keeps pytest from collecting them,
and ``atheris`` is an optional (fuzz-only) dependency imported behind a guard.
See ``tests/fuzz/README.md`` for how to run them locally.
"""
