#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# PQChat.DHT Formal Verification Suite (ProVerif 2.05)
#
# Formally verifies:
#   (1) Unified Protocol: Hybrid KEM (ML-KEM-512 + X25519), MasterKey &
#       ChainKey Secrecy, Payload Secrecy, SAS Anti-Grinding Authentication,
#       and Bidirectional Replay Protection.
#   (2) Secrecy & Key Confirmation (Dual Ratchet Chains & Hybrid Handshake).
#   (3) Forward Secrecy of Past Messages after subsequent state compromise.
#   (4) Post-Compromise Security (PCS / Self-Healing) via Hybrid KEM Rekey.
#       (5) Anti-Replay Injective Agreement for Handshake & Data Packets.
#   (6) Target Unlinkability & 900-Byte Safe Tombstone / Cover Traffic
#       Indistinguishability (Observational Equivalence).
#   (7) Group Chat Protocol & Key Rotation (PCS/FS, Frame 0x06 Secrecy,
#       and Group AAD Binding).
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/report.txt"

# 1. Resolve ProVerif executable
PROVERIF_CMD=""
if [[ -x "/usr/local/bin/proverif" ]]; then
    PROVERIF_CMD="/usr/local/bin/proverif"
elif [[ -x "/usr/bin/proverif" ]]; then
    PROVERIF_CMD="/usr/bin/proverif"
elif command -v proverif >/dev/null 2>&1; then
    PROVERIF_CMD="proverif"
elif command -v proverif.exe >/dev/null 2>&1; then
    PROVERIF_CMD="proverif.exe"
elif [[ -x "${SCRIPT_DIR}/bin/proverif" ]]; then
    PROVERIF_CMD="${SCRIPT_DIR}/bin/proverif"
elif [[ -x "${SCRIPT_DIR}/bin/proverif.exe" ]]; then
    PROVERIF_CMD="${SCRIPT_DIR}/bin/proverif.exe"
elif command -v wsl >/dev/null 2>&1; then
    if wsl /usr/local/bin/proverif --help >/dev/null 2>&1; then
        PROVERIF_CMD="wsl /usr/local/bin/proverif"
    elif wsl proverif --help >/dev/null 2>&1; then
        PROVERIF_CMD="wsl proverif"
    fi
fi

if [[ -z "${PROVERIF_CMD}" ]]; then
    echo "[-] ProVerif executable not found in PATH or standard locations."
    if [[ "$(uname -s)" == "Linux" ]]; then
        echo "[*] Attempting fast compilation of ProVerif 2.05 from source..."
        TMP_BUILD_DIR="$(mktemp -d)"
        (
            cd "${TMP_BUILD_DIR}"
            curl -s https://bblanche.gitlabpages.inria.fr/proverif/proverif2.05.tar.gz | tar -xzf -
            cd proverif2.05
            ./build -nointeract native >/dev/null 2>&1
            mkdir -p "${SCRIPT_DIR}/bin"
            cp proverif "${SCRIPT_DIR}/bin/proverif"
            chmod +x "${SCRIPT_DIR}/bin/proverif"
        ) || true
        rm -rf "${TMP_BUILD_DIR}"
        if [[ -x "${SCRIPT_DIR}/bin/proverif" ]]; then
            PROVERIF_CMD="${SCRIPT_DIR}/bin/proverif"
        fi
    fi
fi

if [[ -z "${PROVERIF_CMD}" ]]; then
    echo "[!] Error: ProVerif not available. Please install proverif or provide it in PATH."
    exit 1
fi

echo "=============================================================================="
echo " Starting PQChat.DHT Formal Verification Suite (ProVerif)"
echo " Engine:    ${PROVERIF_CMD}"
echo " Directory: ${SCRIPT_DIR}"
echo "=============================================================================="

# Helper function to run ProVerif on a model file
run_model() {
    local pv_file="$1"
    local full_path="${SCRIPT_DIR}/${pv_file}"
    local target_path="${full_path}"

    if [[ "${PROVERIF_CMD}" == *.exe ]]; then
        if command -v wslpath >/dev/null 2>&1; then
            target_path="$(wslpath -w "${full_path}")"
        elif command -v cygpath >/dev/null 2>&1; then
            target_path="$(cygpath -w "${full_path}")"
        fi
    elif [[ "${PROVERIF_CMD}" == wsl* ]]; then
        if command -v wslpath >/dev/null 2>&1; then
            target_path="$(wslpath -u "${full_path}")"
        else
            target_path="$(echo "${full_path}" | sed -E 's|^([A-Za-z]):|/mnt/\L\1|; s|\\|/|g')"
        fi
    fi

    ${PROVERIF_CMD} "${target_path}" | tr -d '\r'
}

rm -f "${REPORT_FILE}"
TIMESTAMP="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"

cat << EOF > "${REPORT_FILE}"
==============================================================================
PQChat.DHT Protocol Formal Verification Report
Generated: ${TIMESTAMP}
Verifier: ProVerif 2.05 (Symbolic Dolev-Yao Protocol Analyzer)
==============================================================================

Summary of Verified Security Lemmas:
------------------------------------------------------------------------------
(1) pqchat_protocol.pv (Unified Protocol & Hybrid KEM Model):
    - Lemma 1.1: Secrecy of MasterKey
    - Lemma 1.2: Secrecy of ChainKey A -> B
    - Lemma 1.3: Secrecy of ChainKey B -> A
    - Lemma 1.4: Secrecy of Message Payloads (Track A -> B)
    - Lemma 1.5: Secrecy of Message Payloads (Track B -> A)
    - Lemma 1.6: Secrecy of Reaction Micro-Payload (Type 0x07)
    - Lemma 1.7: Secrecy of Location Pin Micro-Payload (Type 0x08)
    - Lemma 1.8: Mutual Authentication & SAS Anti-Grinding Binding
    - Lemma 1.9: Injective Message Delivery (Track A -> B)
    - Lemma 1.10: Injective Message Delivery (Track B -> A)
    - Lemma 1.11: Authenticity and AAD Binding of Reaction (Type 0x07)
    - Lemma 1.12: Authenticity and AAD Binding of Location Pin (Type 0x08)
(2) pqchat_secrecy.pv (Dedicated Secrecy & Confirmation):
    - Lemma 2.1: Secrecy of ChainKey A -> B
    - Lemma 2.2: Secrecy of ChainKey B -> A
    - Lemma 2.3: Secrecy of Message Payloads (Track A -> B)
    - Lemma 2.4: Secrecy of Message Payloads (Track B -> A)
    - Lemma 2.5: Key Confirmation Agreement
(3) pqchat_forward_secrecy.pv (Forward Secrecy Model):
    - Lemma 3.1: Forward Secrecy of past messages (msg_0)
    - Lemma 3.2: Soundness of state compromise (msg_1 compromised)
(4) pqchat_post_compromise.pv (Post-Compromise Security Model):
    - Lemma 4.1: Post-Compromise Security of healed ChainKey
    - Lemma 4.2: Post-Compromise Security of post-rekey message payloads
(5) pqchat_replay.pv (Anti-Replay Injective Agreement Model):
    - Lemma 5.1: Injective Handshake Agreement (Type 0x01)
    - Lemma 5.2: Injective Message Delivery (Type 0x02)
(6) pqchat_unlinkability.pv (Target & 900B Tombstone Indistinguishability):
    - Lemma 6.1: Observational Equivalence of Ephemeral Targets & 900B Tombstones
(7) pqchat_group_protocol.pv (Group Chat Protocol & Key Rotation Model):
    - Lemma 7.1: Secrecy of senderGroupChainKey (Type 0x06 over 1-on-1 Hybrid Channel)
    - Lemma 7.2: Authenticity of Group Messages with AAD Binding
    - Lemma 7.3: Forward Secrecy of Past Group Messages
    - Lemma 7.4: Post-Compromise Security (PCS) in Epoch + 1
(8) pqchat_duress_wipe.pv (Duress Wipe & Row-Bound V2 Integrity Model):
    - Lemma 8.1: Secrecy of SQLite Payload & Irreversibility of Master Key Erasure
    - Lemma 8.2: Decoy Screen Activation Correspondence with Key Deletion
    - Lemma 8.3: Secrecy of Swapped Plaintext
    - Lemma 8.4: Non-Decryptability & Resistance to Row/Column Swap Attacks
------------------------------------------------------------------------------

EOF

echo "[*] 1/8 Verifying Unified Protocol (pqchat_protocol.pv)..."
echo "==============================================================================" >> "${REPORT_FILE}"
echo "1. Unified Protocol Model (pqchat_protocol.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_PROTOCOL="$(run_model "pqchat_protocol.pv" 2>&1)"
echo "${OUT_PROTOCOL}" >> "${REPORT_FILE}"

echo "[*] 2/8 Verifying Secrecy & Confirmation (pqchat_secrecy.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "2. Secrecy & Confirmation Model (pqchat_secrecy.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_SECRECY="$(run_model "pqchat_secrecy.pv" 2>&1)"
echo "${OUT_SECRECY}" >> "${REPORT_FILE}"

echo "[*] 3/8 Verifying Forward Secrecy (pqchat_forward_secrecy.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "3. Forward Secrecy Model (pqchat_forward_secrecy.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_FS="$(run_model "pqchat_forward_secrecy.pv" 2>&1)"
echo "${OUT_FS}" >> "${REPORT_FILE}"

echo "[*] 4/8 Verifying Post-Compromise Security (pqchat_post_compromise.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "4. Post-Compromise Security Model (pqchat_post_compromise.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_PCS="$(run_model "pqchat_post_compromise.pv" 2>&1)"
echo "${OUT_PCS}" >> "${REPORT_FILE}"

echo "[*] 5/8 Verifying Anti-Replay Injective Agreement (pqchat_replay.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "5. Anti-Replay Model (pqchat_replay.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_REPLAY="$(run_model "pqchat_replay.pv" 2>&1)"
echo "${OUT_REPLAY}" >> "${REPORT_FILE}"

echo "[*] 6/8 Verifying Target Unlinkability & 900B Tombstones (pqchat_unlinkability.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "6. Target Unlinkability & Tombstone Indistinguishability (pqchat_unlinkability.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_UNLINK="$(run_model "pqchat_unlinkability.pv" 2>&1)"
echo "${OUT_UNLINK}" >> "${REPORT_FILE}"

echo "[*] 7/8 Verifying Group Chat Protocol & Key Rotation (pqchat_group_protocol.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "7. Group Chat Protocol & Key Rotation Model (pqchat_group_protocol.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_GROUP="$(run_model "pqchat_group_protocol.pv" 2>&1)"
echo "${OUT_GROUP}" >> "${REPORT_FILE}"

echo "[*] 8/8 Verifying Duress Key Erasure & Row-Bound V2 Integrity (pqchat_duress_wipe.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "8. Duress Key Erasure & Row-Bound V2 Model (pqchat_duress_wipe.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_DURESS="$(run_model "pqchat_duress_wipe.pv" 2>&1)"
echo "${OUT_DURESS}" >> "${REPORT_FILE}"

# Validation of all 32 lemmas
if command -v python3 >/dev/null 2>&1; then
    python3 "${SCRIPT_DIR}/verify_lemmas.py" "${REPORT_FILE}"
else
    echo "[-] python3 not found, please install python3 for automated lemma verification."
    exit 1
fi
