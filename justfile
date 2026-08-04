# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
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

# Semgrep is report-only and runs in an isolated tool environment.
# It is deliberately outside the release/dev lock because Semgrep 1.171.0
# exact-pins a vulnerable MCP SDK that QuReddy does not use.
semgrep:
    uvx --from semgrep==1.171.0 semgrep scan --config auto .

# Run pre-commit hooks against all files (CI-equivalent local check).
hooks:
    uv run --locked pre-commit run --all-files

# Validate documentation structure and Markdown style locally. This target is
# intentionally local: QuReddy does not spend hosted-runner credits on docs.
docs:
    uv run --locked python scripts/check_docs.py
    npm exec --yes --package markdownlint-cli2@0.23.2 -- markdownlint-cli2

# Check external documentation links manually. Install Lychee first, for example
# with `brew install lychee` on macOS; external sites are not a PR-time gate.
docs-links:
    lychee --root-dir . --accept 200,206,429 --verbose --no-progress \
        "*.md" "docs/**/*.md" "tests/fixtures/**/*.md"

# Build and verify one release-candidate artifact set with local evidence.
release-gate:
    python3 scripts/release_gate.py

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
# Run the scanner.
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
