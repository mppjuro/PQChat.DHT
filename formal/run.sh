#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# PQChat.DHT Formal Verification Suite Redirector
#
# All formal verification models have been unified into docs/formal/.
# This script forwards execution to docs/formal/run_verification.sh.
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="${SCRIPT_DIR}/../docs/formal/run_verification.sh"

echo "[*] Forwarding to unified formal verification suite at docs/formal/run_verification.sh..."
exec bash "${TARGET_SCRIPT}" "$@"
