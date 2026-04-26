# SPDX-License-Identifier: Apache-2.0
# Common dev commands. Run `just` to see the list. Run `just <task>` to invoke.
# Install just: https://github.com/casey/just

set shell := ["bash", "-cu"]

# Default: list available tasks.
default:
    @just --list

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Create the dev virtual environment with uv.
setup:
    uv venv
    uv pip install -e ".[dev]"

# ---------------------------------------------------------------------------
# Tier 1 quality gates (run on every code-touching task)
# ---------------------------------------------------------------------------

# Run the full Tier 1 gate suite.
gates: lint format-check typecheck test bandit pip-audit deptry reuse-lint

# Lint only.
lint:
    uv run ruff check .

# Verify formatting (does NOT rewrite). Use `just format` for the rewrite.
format-check:
    uv run ruff format --check .

# Rewrite formatting. Use only when explicitly doing a formatting-only task.
format:
    uv run ruff format .

# Strict type check.
typecheck:
    uv run mypy src/qureddy --strict

# Run the test suite with coverage.
test:
    uv run pytest --cov=qureddy --cov-fail-under=80

# Run only unit tests (excludes tests/live/).
test-unit:
    uv run pytest --ignore=tests/live --cov=qureddy --cov-fail-under=80

# Run only live tests (network required).
test-live:
    uv run pytest tests/live/

# Static security analysis.
bandit:
    uv run bandit -r src/qureddy

# Known vulnerable dependency scan.
pip-audit:
    uv run pip-audit

# Catch unused / missing dependencies.
deptry:
    uv run deptry .

# Verify SPDX headers on all source files.
reuse-lint:
    uv run reuse lint

# Semgrep is report-only at MVP 0.1; do not block on findings.
semgrep:
    uv run semgrep scan --config auto .

# Secret scan. Requires gitleaks installed externally; falls back to trufflehog.
secrets:
    @if command -v gitleaks > /dev/null; then \
        gitleaks detect --no-git --source .; \
    elif command -v trufflehog > /dev/null; then \
        trufflehog filesystem --no-update .; \
    else \
        echo "neither gitleaks nor trufflehog installed; install one"; \
        exit 1; \
    fi

# ---------------------------------------------------------------------------
# Run the scanner (once MVP 0.1 implementation lands)
# ---------------------------------------------------------------------------

# Scan a single TLS endpoint.
scan target:
    uv run qureddy scan tls {{target}}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Remove cache, build, and tooling artifacts.
clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info
    find . -type d -name __pycache__ -exec rm -rf {} +
