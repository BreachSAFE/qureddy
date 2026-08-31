#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
#
# Guided QuReddy scan. Prompts for scan type, target, and an authorization
# confirmation, then runs the scan in Docker. Every prompt has a default, so
# pressing Enter through them scans mozilla.org (TLS) and github.com (SSH).
#
#   ./guided-scan.sh                 # interactive, Enter-through for the demo
#   DRY_RUN=1 ./guided-scan.sh       # print the docker commands instead of running
set -euo pipefail

IMAGE="${QUREDDY_IMAGE:-ghcr.io/breachsafe/qureddy:latest}"

run_scan() {
  kind=$1 host=$2 port=$3
  read -rp "Authorized to scan ${host}:${port} over ${kind}? [Y/n]: " ok || ok=Y
  case "${ok:-Y}" in
    [Yy]*) : ;;
    *) echo "  Skipped ${host}."; return 0 ;;
  esac
  if [ "${DRY_RUN:-0}" = 1 ]; then
    echo "  + docker run --rm $IMAGE scan $kind ${host}:${port}"
  else
    docker run --rm "$IMAGE" scan "$kind" "${host}:${port}"
  fi
}

read -rp "Scan TLS, SSH, or both? [tls/ssh/both] (default: both): " kind || kind=both
kind="${kind:-both}"

case "$kind" in
  tls)
    read -rp "TLS host (default: mozilla.org): " h || h=mozilla.org; h="${h:-mozilla.org}"
    read -rp "Port (default: 443): " p || p=443; p="${p:-443}"
    run_scan tls "$h" "$p"
    ;;
  ssh)
    read -rp "SSH host (default: github.com): " h || h=github.com; h="${h:-github.com}"
    read -rp "Port (default: 22): " p || p=22; p="${p:-22}"
    run_scan ssh "$h" "$p"
    ;;
  both)
    run_scan tls mozilla.org 443
    run_scan ssh github.com 22
    ;;
  *)
    echo "Unknown choice '${kind}'. Use tls, ssh, or both." >&2; exit 4 ;;
esac
