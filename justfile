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
    uv sync --locked --extra dev

# ---------------------------------------------------------------------------
# Tier 1 quality gates (run on every code-touching task)
# ---------------------------------------------------------------------------

# Run the full Tier 1 gate suite.
gates: lint format-check typecheck test bandit pip-audit deptry reuse-lint

# Lint only.
lint:
    uv run --locked ruff check .

# Verify formatting (does NOT rewrite). Use `just format` for the rewrite.
format-check:
    uv run --locked ruff format --check .

# Rewrite formatting. Use only when explicitly doing a formatting-only task.
format:
    uv run --locked ruff format .

# Strict type check.
typecheck:
    uv run --locked mypy src/qureddy --strict

# Run the test suite with coverage.
test:
    uv run --locked pytest --cov=qureddy --cov-fail-under=80

# Run only unit tests (excludes tests/live/).
test-unit:
    uv run --locked pytest --ignore=tests/live --cov=qureddy --cov-fail-under=80

# Run only live tests (network required).
test-live:
    uv run --locked pytest tests/live/

# Static security analysis.
bandit:
    uv run --locked bandit -r -ll src/qureddy scripts/

# Known vulnerable dependency scan.
pip-audit:
    uv run --locked pip-audit \
        --ignore-vuln PYSEC-2026-3481 \
        --ignore-vuln PYSEC-2026-3482 \
        --ignore-vuln PYSEC-2026-3483

# Catch unused / missing dependencies.
deptry:
    uv run --locked deptry .

# Verify SPDX headers on all source files.
reuse-lint:
    uv run --locked reuse lint

# Semgrep is report-only at MVP 0.1; do not block on findings.
semgrep:
    uv run --locked semgrep scan --config auto .

# Run pre-commit hooks against all files (CI-equivalent local check).
hooks:
    uv run --locked pre-commit run --all-files

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
    uv run --locked qureddy scan tls {{target}}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

# Remove cache, build, and tooling artifacts.
clean:
    rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov dist build *.egg-info
    find . -type d -name __pycache__ -exec rm -rf {} +
