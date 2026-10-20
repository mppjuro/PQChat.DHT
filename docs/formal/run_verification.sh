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
if command -v proverif >/dev/null 2>&1; then
    PROVERIF_CMD="proverif"
elif [[ -x "/usr/local/bin/proverif" ]]; then
    PROVERIF_CMD="/usr/local/bin/proverif"
elif [[ -x "/usr/bin/proverif" ]]; then
    PROVERIF_CMD="/usr/bin/proverif"
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

    ${PROVERIF_CMD} "${target_path}"
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
    - Lemma 1.6: Mutual Authentication & SAS Anti-Grinding Binding
    - Lemma 1.7: Injective Message Delivery (Track A -> B)
    - Lemma 1.8: Injective Message Delivery (Track B -> A)
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
------------------------------------------------------------------------------

EOF

echo "[*] 1/7 Verifying Unified Protocol (pqchat_protocol.pv)..."
echo "==============================================================================" >> "${REPORT_FILE}"
echo "1. Unified Protocol Model (pqchat_protocol.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_PROTOCOL="$(run_model "pqchat_protocol.pv" 2>&1)"
echo "${OUT_PROTOCOL}" >> "${REPORT_FILE}"

echo "[*] 2/7 Verifying Secrecy & Confirmation (pqchat_secrecy.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "2. Secrecy & Confirmation Model (pqchat_secrecy.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_SECRECY="$(run_model "pqchat_secrecy.pv" 2>&1)"
echo "${OUT_SECRECY}" >> "${REPORT_FILE}"

echo "[*] 3/7 Verifying Forward Secrecy (pqchat_forward_secrecy.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "3. Forward Secrecy Model (pqchat_forward_secrecy.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_FS="$(run_model "pqchat_forward_secrecy.pv" 2>&1)"
echo "${OUT_FS}" >> "${REPORT_FILE}"

echo "[*] 4/7 Verifying Post-Compromise Security (pqchat_post_compromise.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "4. Post-Compromise Security Model (pqchat_post_compromise.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_PCS="$(run_model "pqchat_post_compromise.pv" 2>&1)"
echo "${OUT_PCS}" >> "${REPORT_FILE}"

echo "[*] 5/7 Verifying Anti-Replay Injective Agreement (pqchat_replay.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "5. Anti-Replay Model (pqchat_replay.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_REPLAY="$(run_model "pqchat_replay.pv" 2>&1)"
echo "${OUT_REPLAY}" >> "${REPORT_FILE}"

echo "[*] 6/7 Verifying Target Unlinkability & 900B Tombstones (pqchat_unlinkability.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "6. Target Unlinkability & Tombstone Indistinguishability (pqchat_unlinkability.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_UNLINK="$(run_model "pqchat_unlinkability.pv" 2>&1)"
echo "${OUT_UNLINK}" >> "${REPORT_FILE}"

echo "[*] 7/7 Verifying Group Chat Protocol & Key Rotation (pqchat_group_protocol.pv)..."
echo "" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
echo "7. Group Chat Protocol & Key Rotation Model (pqchat_group_protocol.pv)" >> "${REPORT_FILE}"
echo "==============================================================================" >> "${REPORT_FILE}"
OUT_GROUP="$(run_model "pqchat_group_protocol.pv" 2>&1)"
echo "${OUT_GROUP}" >> "${REPORT_FILE}"

# Validation of all lemmas
ERRORS=0

validate_result() {
    local text="$1"
    local pattern="$2"
    local lemma_name="$3"
    if echo "${text}" | grep -q "${pattern}"; then
        echo "  [PASS] ${lemma_name}"
    else
        echo "  [FAIL] ${lemma_name} (Pattern '${pattern}' not found)"
        ERRORS=$((ERRORS + 1))
    fi
}

echo ""
echo "=============================================================================="
echo " Formal Verification Results:"
echo "=============================================================================="
echo "--- 1. Unified Protocol Model ---"
validate_result "${OUT_PROTOCOL}" "RESULT not attacker(secret_master_key\[\]) is true." "Lemma 1.1: Secrecy of MasterKey"
validate_result "${OUT_PROTOCOL}" "RESULT not attacker(secret_chain_A2B\[\]) is true." "Lemma 1.2: Secrecy of ChainKey A->B"
validate_result "${OUT_PROTOCOL}" "RESULT not attacker(secret_chain_B2A\[\]) is true." "Lemma 1.3: Secrecy of ChainKey B->A"
validate_result "${OUT_PROTOCOL}" "RESULT not attacker(secret_msg_A2B\[\]) is true." "Lemma 1.4: Secrecy of Payload Msg A->B"
validate_result "${OUT_PROTOCOL}" "RESULT not attacker(secret_msg_B2A\[\]) is true." "Lemma 1.5: Secrecy of Payload Msg B->A"
validate_result "${OUT_PROTOCOL}" "RESULT inj-event(AliceFinished(pkA_kem,pkA_x,seed,ckA2B,ckB2A,sas_2)) ==> inj-event(BobFinished(pkA_kem,pkA_x,seed,ckA2B,ckB2A,sas_2)) is true." "Lemma 1.6: Mutual Authentication & SAS Binding"
validate_result "${OUT_PROTOCOL}" "RESULT inj-event(BobRecvMsg(target_2,seq,msg)) ==> inj-event(AliceSentMsg(target_2,seq,msg)) is true." "Lemma 1.7: Injective Message Delivery A->B"
validate_result "${OUT_PROTOCOL}" "RESULT inj-event(AliceRecvReply(target_2,seq,msg)) ==> inj-event(BobSentReply(target_2,seq,msg)) is true." "Lemma 1.8: Injective Message Delivery B->A"

echo "--- 2. Secrecy & Confirmation Model ---"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_chain_A2B\[\]) is true." "Lemma 2.1: Secrecy of ChainKey A->B"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_chain_B2A\[\]) is true." "Lemma 2.2: Secrecy of ChainKey B->A"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_msg_A2B\[\]) is true." "Lemma 2.3: Secrecy of Payload Msg A->B"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_msg_B2A\[\]) is true." "Lemma 2.4: Secrecy of Payload Msg B->A"
validate_result "${OUT_SECRECY}" "RESULT inj-event(AliceFinished(pkA_kem,pkA_x,seed,ckA2B,ckB2A)) ==> inj-event(BobFinished(pkA_kem,pkA_x,seed,ckA2B,ckB2A)) is true." "Lemma 2.5: Key Confirmation Agreement"

echo "--- 3. Forward Secrecy Model ---"
validate_result "${OUT_FS}" "RESULT not attacker(secret_msg_0\[\]) is true." "Lemma 3.1: Forward Secrecy of past msg_0"
validate_result "${OUT_FS}" "RESULT not attacker(secret_msg_1\[\]) is false." "Lemma 3.2: Soundness of state compromise (msg_1 compromised)"

echo "--- 4. Post-Compromise Security Model ---"
validate_result "${OUT_PCS}" "RESULT not attacker(secret_new_chain_key\[\]) is true." "Lemma 4.1: Post-Compromise Security of ChainKey"
validate_result "${OUT_PCS}" "RESULT not attacker(secret_msg_post_rekey\[\]) is true." "Lemma 4.2: Post-Compromise Security of Post-Rekey Msg"

echo "--- 5. Anti-Replay Injective Agreement Model ---"
validate_result "${OUT_REPLAY}" "RESULT inj-event(HandshakeAccepted(target_2,ct,pkx,salt_2)) ==> inj-event(HandshakeSent(target_2,ct,pkx,salt_2)) is true." "Lemma 5.1: Injective Handshake Agreement"
validate_result "${OUT_REPLAY}" "RESULT inj-event(MessageAccepted(target_2,seq,msg)) ==> inj-event(MessageSent(target_2,seq,msg)) is true." "Lemma 5.2: Injective Message Delivery"

echo "--- 6. Target Unlinkability & 900B Tombstones ---"
validate_result "${OUT_UNLINK}" "RESULT Observational equivalence is true." "Lemma 6.1: Target Unlinkability & Tombstone Indistinguishability"

echo "--- 7. Group Chat Protocol & Key Rotation Model ---"
validate_result "${OUT_GROUP}" "RESULT not attacker(secret_sender_group_chain_key\[\]) is true." "Lemma 7.1: Secrecy of Group Sender Key (Type 0x06)"
validate_result "${OUT_GROUP}" "RESULT inj-event(BobRecvGroupMsg(target_x,g_id,sender_id,msg)) ==> inj-event(AliceSentGroupMsg(target_x,g_id,sender_id,msg)) is true." "Lemma 7.2: Authenticity of Group Messages with AAD Binding"
validate_result "${OUT_GROUP}" "RESULT not attacker(secret_group_msg_pre_leave\[\]) is true." "Lemma 7.3: Forward Secrecy of Past Group Messages"
validate_result "${OUT_GROUP}" "RESULT not attacker(secret_group_msg_post_leave\[\]) is true." "Lemma 7.4: Post-Compromise Security in Epoch + 1"

cat << EOF >> "${REPORT_FILE}"

==============================================================================
FINAL AUDIT VERDICT:
==============================================================================
$([ ${ERRORS} -eq 0 ] && echo "STATUS: ALL LEMMAS FORMALLY PROVED (PASS)" || echo "STATUS: VERIFICATION FAILED WITH ${ERRORS} ERRORS")
Total Lemmas Tested: 24
Failed: ${ERRORS}
==============================================================================
EOF

echo "=============================================================================="
if [[ ${ERRORS} -eq 0 ]]; then
    echo " [SUCCESS] All 7 formal verification models PROVED successfully (24/24 lemmas passed)."
    echo " Detailed report written to: ${REPORT_FILE}"
    echo "=============================================================================="
    exit 0
else
    echo " [FAILURE] Formal verification failed with ${ERRORS} errors."
    echo " Detailed report written to: ${REPORT_FILE}"
    echo "=============================================================================="
    exit 1
fi
