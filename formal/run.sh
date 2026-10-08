#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# PQChat.DHT Formal Verification Suite (ProVerif)
# 
# Verifies:
#   (a) Secrecy of ChainKeys (A->B, B->A) & Message Payloads + Key Confirmation
#   (b) Forward Secrecy of past messages after ephemeral key compromise
#   (c) Post-Compromise Security (self-healing) of ChainKey after ML-KEM-512 Rekey
#   (d) Identity Unlinkability / Metadata-free Rendezvous of Target_i = SHA-1(pk_i)
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_FILE="${SCRIPT_DIR}/report.txt"

# 1. Resolve ProVerif executable
PROVERIF_CMD=""
if command -v proverif >/dev/null 2>&1; then
    PROVERIF_CMD="proverif"
elif command -v proverif.exe >/dev/null 2>&1; then
    PROVERIF_CMD="proverif.exe"
elif [[ -x "${SCRIPT_DIR}/bin/proverif" ]]; then
    PROVERIF_CMD="${SCRIPT_DIR}/bin/proverif"
elif [[ -x "${SCRIPT_DIR}/bin/proverif.exe" ]]; then
    PROVERIF_CMD="${SCRIPT_DIR}/bin/proverif.exe"
elif command -v wsl >/dev/null 2>&1; then
    if wsl -d Ubuntu proverif --help >/dev/null 2>&1; then
        PROVERIF_CMD="wsl -d Ubuntu proverif"
    elif wsl proverif --help >/dev/null 2>&1; then
        PROVERIF_CMD="wsl proverif"
    fi
fi

if [[ -z "${PROVERIF_CMD}" ]]; then
    echo "[-] ProVerif executable not found in PATH or WSL."
    echo "[*] Attempting to install / download ProVerif..."
    mkdir -p "${SCRIPT_DIR}/bin"
    if [[ "$(uname -s)" == "Linux" ]]; then
        if command -v opam >/dev/null 2>&1; then
            opam install -y proverif
            PROVERIF_CMD="proverif"
        fi
    fi
    if [[ -z "${PROVERIF_CMD}" ]]; then
        echo "[!] Please ensure proverif is installed or available in PATH or WSL Ubuntu."
        exit 1
    fi
fi

echo "=============================================================================="
echo " Starting PQChat.DHT Formal Verification Suite"
echo " Engine: ${PROVERIF_CMD}"
echo " Directory: ${SCRIPT_DIR}"
echo "=============================================================================="

# Helper function to run ProVerif on a model file
run_model() {
    local pv_file="$1"
    local full_path="${SCRIPT_DIR}/${pv_file}"
    if [[ "${PROVERIF_CMD}" == wsl* ]]; then
        # Convert path to WSL format if running through WSL
        local wsl_path
        if command -v wslpath >/dev/null 2>&1; then
            wsl_path="$(wslpath -u "${full_path}")"
        else
            # Manual translation: C:/... -> /mnt/c/...
            wsl_path="$(echo "${full_path}" | sed -E 's|^([A-Za-z]):|/mnt/\L\1|; s|\\|/|g')"
        fi
        ${PROVERIF_CMD} "${wsl_path}"
    else
        ${PROVERIF_CMD} "${full_path}"
    fi
}

# Clean previous report
rm -f "${REPORT_FILE}"

TIMESTAMP="$(date -u +"%Y-%m-%d %H:%M:%S UTC")"

cat << EOF > "${REPORT_FILE}"
==============================================================================
PQChat.DHT Protocol Formal Verification Report
Generated: ${TIMESTAMP}
Verifier: ProVerif (Symbolic Dolev-Yao Protocol Analysis)
==============================================================================

Summary of Verified Security Lemmas:
------------------------------------------------------------------------------
(a) Lemma A1: Secrecy of ChainKey A -> B
    Query: not attacker(secret_chain_A2B[])
(a) Lemma A2: Secrecy of ChainKey B -> A
    Query: not attacker(secret_chain_B2A[])
(a) Lemma A3: Secrecy of Message Payloads (Track A -> B)
    Query: not attacker(secret_msg_A2B[])
(a) Lemma A4: Secrecy of Message Payloads (Track B -> A)
    Query: not attacker(secret_msg_B2A[])
(a) Lemma A5: Mutual Authentication & Key Confirmation Agreement
    Query: inj-event(AliceFinished) ==> inj-event(BobFinished)
(b) Lemma B1: Forward Secrecy after Ephemeral ChainKey Compromise
    Query: not attacker(secret_msg_0[])
(c) Lemma C1: Post-Compromise Security (PCS) of ChainKey after ML-KEM Rekey
    Query: not attacker(secret_new_chain_key[])
(c) Lemma C2: Post-Compromise Security (PCS) of Messages after ML-KEM Rekey
    Query: not attacker(secret_msg_post_rekey[])
(d) Lemma D1: Identity Unlinkability & Metadata-Free Rendezvous of Target_i
    Query: Observational Equivalence (choice[Target_Session_AB, Target_Session_CD])
------------------------------------------------------------------------------

==============================================================================
1. Verification of Goal (a): Secrecy & Authentication (pqchat_secrecy.pv)
==============================================================================
EOF

echo "[*] Verifying Goal (a): Secrecy & Authentication..."
OUT_SECRECY="$(run_model "pqchat_secrecy.pv" 2>&1)"
echo "${OUT_SECRECY}" >> "${REPORT_FILE}"

echo "[*] Verifying Goal (b): Forward Secrecy..."
cat << EOF >> "${REPORT_FILE}"

==============================================================================
2. Verification of Goal (b): Forward Secrecy (pqchat_forward_secrecy.pv)
==============================================================================
EOF
OUT_FS="$(run_model "pqchat_forward_secrecy.pv" 2>&1)"
echo "${OUT_FS}" >> "${REPORT_FILE}"

echo "[*] Verifying Goal (c): Post-Compromise Security..."
cat << EOF >> "${REPORT_FILE}"

==============================================================================
3. Verification of Goal (c): Post-Compromise Security (pqchat_post_compromise.pv)
==============================================================================
EOF
OUT_PCS="$(run_model "pqchat_post_compromise.pv" 2>&1)"
echo "${OUT_PCS}" >> "${REPORT_FILE}"

echo "[*] Verifying Goal (d): Target Unlinkability..."
cat << EOF >> "${REPORT_FILE}"

==============================================================================
4. Verification of Goal (d): Target Unlinkability (pqchat_unlinkability.pv)
==============================================================================
EOF
OUT_UNLINK="$(run_model "pqchat_unlinkability.pv" 2>&1)"
echo "${OUT_UNLINK}" >> "${REPORT_FILE}"

# Validation of results
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
echo " Verification Results:"
echo "=============================================================================="
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_chain_A2B\[\]) is true." "Lemma (a.1): Secrecy of ChainKey A->B"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_chain_B2A\[\]) is true." "Lemma (a.2): Secrecy of ChainKey B->A"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_msg_A2B\[\]) is true." "Lemma (a.3): Secrecy of Payload Msg A->B"
validate_result "${OUT_SECRECY}" "RESULT not attacker(secret_msg_B2A\[\]) is true." "Lemma (a.4): Secrecy of Payload Msg B->A"
validate_result "${OUT_SECRECY}" "RESULT inj-event(AliceFinished(pkA,seed,ckA2B,ckB2A)) ==> inj-event(BobFinished(pkA,seed,ckA2B,ckB2A)) is true." "Lemma (a.5): Key Confirmation Agreement"

validate_result "${OUT_FS}" "RESULT not attacker(secret_msg_0\[\]) is true." "Lemma (b.1): Forward Secrecy of msg_0"
validate_result "${OUT_FS}" "RESULT not attacker(secret_msg_1\[\]) is false." "Lemma (b.2): Soundness of compromise (msg_1 compromised)"

validate_result "${OUT_PCS}" "RESULT not attacker(secret_new_chain_key\[\]) is true." "Lemma (c.1): Post-Compromise Security of ChainKey"
validate_result "${OUT_PCS}" "RESULT not attacker(secret_msg_post_rekey\[\]) is true." "Lemma (c.2): Post-Compromise Security of Post-Rekey Msg"

validate_result "${OUT_UNLINK}" "RESULT Observational equivalence is true." "Lemma (d.1): Target_i Identity Unlinkability (Diff-Equivalence)"

cat << EOF >> "${REPORT_FILE}"

==============================================================================
FINAL AUDIT VERDICT:
==============================================================================
$([ ${ERRORS} -eq 0 ] && echo "STATUS: ALL LEMMAS FORMALLY PROVED (PASS)" || echo "STATUS: VERIFICATION FAILED WITH ${ERRORS} ERRORS")
Total Lemmas Tested: 10
Failed: ${ERRORS}
==============================================================================
EOF

echo "=============================================================================="
if [[ ${ERRORS} -eq 0 ]]; then
    echo " [SUCCESS] All 4 formal verification goals PROVED successfully."
    echo " Detailed report written to: ${REPORT_FILE}"
    echo "=============================================================================="
    exit 0
else
    echo " [FAILURE] Verification failed with ${ERRORS} errors."
    echo " Detailed report written to: ${REPORT_FILE}"
    echo "=============================================================================="
    exit 1
fi
