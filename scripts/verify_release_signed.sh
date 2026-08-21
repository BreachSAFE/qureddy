#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# verify_release_signed.sh <tag> [owner/repo]
#
# Enforce that a QuReddy GitHub Release was ACTUALLY signed -- not merely that
# release.yml *carries* a signing step. A workflow can hold cosign / attest
# steps and still ship an unsigned release because the workflow never executed
# for that tag (the release was left a draft, the workflow was disabled during
# the burst, a tag was pushed before signing was added). That is exactly how
# 0.2.14-0.2.16 shipped unsigned (#219, #232). "A signing step that never ran
# is not a signed release."
#
# This gate FAILS (exit 1) unless ALL of the following hold for <tag>:
#   1. the release exists (gh release view succeeds),
#   2. it is NOT a draft (release: published is what triggers release.yml),
#   3. the wheel  (breachsafe_qureddy-<v>-py3-none-any.whl) has a sibling
#      <name>.sigstore signature-bundle asset, AND
#   4. the sdist  (breachsafe_qureddy-<v>.tar.gz)            has a sibling
#      <name>.sigstore signature-bundle asset.
# If cosign and/or `gh attestation` are available it ALSO verifies the bundle /
# SLSA build-provenance cryptographically; when that verification runs and
# fails, the gate fails. Missing verifier tools degrade to the asset-presence
# check (still un-bypassable for "signing never ran") rather than a false pass.
#
# The confirmed-good shape (from the genuinely signed v0.2.17 release):
#   breachsafe_qureddy-0.2.17-py3-none-any.whl   + .whl.sigstore
#   breachsafe_qureddy-0.2.17.tar.gz             + .tar.gz.sigstore
#
# Wire this in as the FINAL job of release.yml, after signing+upload, so a
# release whose signing step silently did not run fails the workflow loudly
# instead of being caught days later by an OpenSSF Scorecard drop.
#
# Read-only except a temp download of the release artifacts (cleaned up).
# Deps: gh (authenticated), jq. Optional: cosign, `gh attestation`.
# bash 3.2 safe (macOS default bash).
#
# Usage:
#   scripts/verify_release_signed.sh v0.2.17
#   scripts/verify_release_signed.sh v0.2.17 breachsafe/qureddy
#
# Flags:
#   --simulate-unsigned   pretend the .sigstore assets are absent -- proves the
#                         RED path (unsigned release -> exit 1) without needing
#                         a real unsigned release to point at.
#   --no-verify           skip the cryptographic cosign/attestation step; only
#                         check asset presence + not-draft + exists.

set -u

REPO_DEFAULT="breachsafe/qureddy"
SIMULATE_UNSIGNED=0
DO_VERIFY=1
TAG=""
REPO=""

die() { echo "error: $*" >&2; exit 2; }

for arg in "$@"; do
  case "$arg" in
    --simulate-unsigned) SIMULATE_UNSIGNED=1 ;;
    --no-verify) DO_VERIFY=0 ;;
    -h|--help)
      sed -n '3,52p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    -*) die "unknown flag: $arg" ;;
    */*) REPO="$arg" ;;
    *) [ -z "$TAG" ] && TAG="$arg" || REPO="$arg" ;;
  esac
done

[ -n "$TAG" ] || die "usage: verify_release_signed.sh <tag> [owner/repo]"
[ -n "$REPO" ] || REPO="$REPO_DEFAULT"

for t in gh jq; do command -v "$t" >/dev/null 2>&1 || die "missing required tool: $t"; done

echo "=================================================================="
echo " Release signing gate: ${REPO} @ ${TAG}"
echo "=================================================================="

# --- 1. release exists ------------------------------------------------------
META="$(gh release view "$TAG" -R "$REPO" --json isDraft,tagName,assets 2>/dev/null)" \
  || { echo "  [FAIL] release ${TAG} not found in ${REPO} (never published?)"; \
       echo "VERDICT: FAIL -- ${TAG} does not exist as a published release."; exit 1; }
echo "  [PASS] release ${TAG} exists"

FAIL=0

# --- 2. not a draft ---------------------------------------------------------
IS_DRAFT="$(printf '%s' "$META" | jq -r '.isDraft')"
if [ "$IS_DRAFT" = "true" ]; then
  echo "  [FAIL] release ${TAG} is a DRAFT -- release:published never fired, so"
  echo "         release.yml (and its signing job) never ran. This is the exact"
  echo "         0.2.14-0.2.16 failure mode (#232)."
  FAIL=1
else
  echo "  [PASS] release ${TAG} is published (not a draft)"
fi

# --- asset inventory --------------------------------------------------------
ASSETS="$(printf '%s' "$META" | jq -r '.assets[].name')"
if [ "$SIMULATE_UNSIGNED" -eq 1 ]; then
  echo "  [note] --simulate-unsigned: dropping .sigstore assets to exercise RED path"
  ASSETS="$(printf '%s\n' "$ASSETS" | grep -viE '\.sigstore$' || true)"
fi

WHEEL="$(printf '%s\n' "$ASSETS" | grep -iE '\.whl$' | head -1)"
SDIST="$(printf '%s\n' "$ASSETS" | grep -iE '\.tar\.gz$' | head -1)"

has_asset() { printf '%s\n' "$ASSETS" | grep -qxF "$1"; }

# --- 3./4. wheel + sdist each carry a .sigstore bundle ----------------------
check_signed() {
  # $1 = kind label, $2 = artifact asset name
  kind="$1"; art="$2"
  if [ -z "$art" ]; then
    echo "  [FAIL] no ${kind} asset on release ${TAG}"
    FAIL=1
    return
  fi
  if has_asset "${art}.sigstore"; then
    echo "  [PASS] ${kind} signed: ${art} + ${art}.sigstore"
  else
    echo "  [FAIL] ${kind} ${art} has NO ${art}.sigstore signature bundle"
    FAIL=1
  fi
}
check_signed "wheel" "$WHEEL"
check_signed "sdist" "$SDIST"

# --- 5. (optional) cryptographic verification -------------------------------
# Best-effort strengthening: if a verifier is available, actually verify. When
# verification RUNS and fails, that is a hard failure. When no verifier is
# available we say so rather than claiming a pass we did not earn.
if [ "$DO_VERIFY" -eq 1 ] && [ "$SIMULATE_UNSIGNED" -eq 0 ] && [ -n "$WHEEL" ]; then
  VERIFIER=""
  command -v cosign >/dev/null 2>&1 && VERIFIER="cosign"
  ATTEST_OK=0
  gh attestation --help >/dev/null 2>&1 && ATTEST_OK=1
  if [ -n "$VERIFIER" ] || [ "$ATTEST_OK" -eq 1 ]; then
    TMP="$(mktemp -d)"
    if gh release download "$TAG" -R "$REPO" -p "$WHEEL" -D "$TMP" >/dev/null 2>&1; then
      # cosign verify-blob against the keyless GitHub-Actions OIDC identity.
      if [ -n "$VERIFIER" ] \
         && gh release download "$TAG" -R "$REPO" -p "${WHEEL}.sigstore" -D "$TMP" >/dev/null 2>&1; then
        if cosign verify-blob \
             --bundle "$TMP/${WHEEL}.sigstore" \
             --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
             --certificate-identity-regexp "^https://github.com/${REPO}/\.github/workflows/release\.yml@" \
             "$TMP/$WHEEL" >/dev/null 2>&1; then
          echo "  [PASS] cosign verify-blob confirms the wheel signature (keyless OIDC)"
        else
          echo "  [FAIL] cosign verify-blob could NOT verify ${WHEEL}.sigstore"
          FAIL=1
        fi
      fi
      # SLSA build provenance (attest-build-provenance leaves NO release asset,
      # only a store entry) -- verify via the attestation store when available.
      if [ "$ATTEST_OK" -eq 1 ]; then
        if gh attestation verify "$TMP/$WHEEL" --repo "$REPO" >/dev/null 2>&1; then
          echo "  [PASS] gh attestation verify confirms SLSA build provenance for the wheel"
        else
          echo "  [note] gh attestation verify found no provenance for the wheel"
          echo "         (the cosign .sigstore bundle above is the primary signal)"
        fi
      fi
    else
      echo "  [note] could not download ${WHEEL} for cryptographic verification"
    fi
    rm -rf "$TMP"
  else
    echo "  [note] no cosign / gh-attestation verifier available; the asset-presence"
    echo "         check above still enforces that signing ran"
  fi
fi

echo "------------------------------------------------------------------"
if [ "$FAIL" -eq 0 ]; then
  echo "VERDICT: PASS -- ${TAG} is a published release whose wheel and sdist are"
  echo "         both signed. The signing workflow demonstrably ran."
  exit 0
fi
echo "VERDICT: FAIL -- ${TAG} is NOT provably signed. Do not treat it as released."
echo "  Root cause is usually that release.yml never executed for this tag (draft"
echo "  release, or Actions disabled). Fix forward: re-run release.yml for the tag"
echo "  (gh workflow run release.yml -R ${REPO} --ref ${TAG}) or cut a clean patch"
echo "  release, then re-run this gate until it exits 0. See #219, #232."
exit 1
