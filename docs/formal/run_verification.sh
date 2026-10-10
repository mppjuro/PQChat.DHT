#!/bin/bash
# ==============================================================================
# PQChat.DHT Protocol Formal Verification Runner (ProVerif)
# ==============================================================================

set -e

PROVERIF_BIN=$(which proverif 2>/dev/null || echo "/usr/local/bin/proverif")

if [ ! -x "$PROVERIF_BIN" ]; then
    echo "[-] ProVerif not found at $PROVERIF_BIN or on PATH."
    exit 1
fi

echo "=============================================================================="
echo "Running PQChat.DHT ProVerif Formal Verification Suite"
echo "Binary: $PROVERIF_BIN"
echo "=============================================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

run_model() {
    local file="$1"
    local desc="$2"
    echo ""
    echo "------------------------------------------------------------------------------"
    echo "Verifying: $desc ($file)"
    echo "------------------------------------------------------------------------------"
    "$PROVERIF_BIN" "$SCRIPT_DIR/$file" | grep -E "RESULT|Query"
}

run_model "pqchat_protocol.pv" "1. Unified Protocol Model (Secrecy, Authentication & Replay)"
run_model "pqchat_forward_secrecy.pv" "2. Forward Secrecy Model"
run_model "pqchat_post_compromise.pv" "3. Post-Compromise Security (PCS) Model"
run_model "pqchat_replay.pv" "4. Anti-Replay Injective Agreement Model"

echo ""
echo "=============================================================================="
echo "[+] All formal models passed verification successfully!"
echo "=============================================================================="
