#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# Apply QuReddy branch protection rules to main.
#
# Branch protection on a private repo requires GitHub Pro ($4/mo) OR the
# repo to be public. If you see "Upgrade to GitHub Pro or make this
# repository public," that is the cause.
#
# Run this script after either:
#   - Flipping the repo public:
#       gh repo edit breachsafe/qureddy --visibility public \
#         --accept-visibility-change-consequences
#   - Upgrading to GitHub Pro
#
# This script is idempotent — running it twice produces the same final
# state. Re-run after adding new required CI status checks.

set -euo pipefail

REPO="${1:-breachsafe/qureddy}"
BRANCH="${2:-main}"

echo "Applying branch protection to ${REPO} branch ${BRANCH}..."

# Required status checks. Keep this list aligned with the live protection state
# when gates are added or renamed; PUT replaces the complete context set.
REQUIRED_CONTEXTS=(
  "Phase 1: Static (ubuntu-latest)"
  "Phase 1: Static (macos-latest)"
  "Phase 2: Unit (ubuntu-latest)"
  "Phase 2: Unit (macos-latest)"
  # Keep this independent context required: phase-3's `needs` edge is an
  # execution dependency, not a durable branch-protection contract. If the
  # workflow is refactored (as in #841), the Windows IKE gate must still block
  # a merge when its job fails.
  "Phase 2: IKE unit (windows-latest)"
  "CBOM: CycloneDX 1.7 final bytes"
  "Package: build and runtime audit"
  "Package: clean install (ubuntu-latest)"
  "Package: clean install (macos-latest)"
  "Package: clean install (windows-latest)"
  "Phase 6: Build"
  "MAX code-quality"
  "Changed-line coverage (100%)"
  "Local release gate (ubuntu-latest)"
  "Local release gate (macos-latest)"
  "Analyze (python)"
  "Phase 3: Integration (ubuntu-latest, OpenSSL 3.5.8)"
  "Phase 3: Integration (macos-latest, OpenSSL 3.5.8)"
)

# Build the gh api args.
ARGS=(
  -F "required_status_checks[strict]=true"
  -F "enforce_admins=false"
  -F "required_pull_request_reviews[required_approving_review_count]=0"
  -F "required_pull_request_reviews[dismiss_stale_reviews]=true"
  -F "required_pull_request_reviews[require_code_owner_reviews]=false"
  -F "restrictions=null"
  -F "required_linear_history=true"
  -F "allow_force_pushes=false"
  -F "allow_deletions=false"
  -F "required_conversation_resolution=true"
)

for ctx in "${REQUIRED_CONTEXTS[@]}"; do
  ARGS+=(-F "required_status_checks[contexts][]=${ctx}")
done

gh api -X PUT "repos/${REPO}/branches/${BRANCH}/protection" "${ARGS[@]}"

echo
echo "Setting merge defaults: squash-only, delete branch on merge..."

gh api -X PATCH "repos/${REPO}" \
  -F "allow_merge_commit=false" \
  -F "allow_squash_merge=true" \
  -F "allow_rebase_merge=false" \
  -F "delete_branch_on_merge=true" \
  -F "allow_auto_merge=true"

echo
echo "Done. Branch protection is active on ${REPO}/${BRANCH}."
echo
echo "Calibration choices baked in:"
echo "  - required_approving_review_count=0  (solo project; bump to 1 when collaborators join)"
echo "  - enforce_admins=false               (you can override in genuine emergencies)"
echo "  - required_linear_history=true       (no merge commits)"
echo "  - allow_force_pushes=false           (no force-push to main)"
echo "  - squash-and-merge only              (clean history)"
echo "  - delete_branch_on_merge=true        (no stale branches)"
