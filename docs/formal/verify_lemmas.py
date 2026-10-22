#!/usr/bin/env python3
import sys
import re

def main():
    report_file = sys.argv[1] if len(sys.argv) > 1 else "docs/formal/report.txt"
    try:
        with open(report_file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except Exception as e:
        print(f"[-] Error opening report file {report_file}: {e}")
        sys.exit(1)

    lemmas = [
        # (pattern, name)
        (r"RESULT not attacker\(secret_master_key\[\]\) is true\.", "Lemma 1.1: Secrecy of MasterKey"),
        (r"RESULT not attacker\(secret_chain_A2B\[\]\) is true\.", "Lemma 1.2: Secrecy of ChainKey A->B"),
        (r"RESULT not attacker\(secret_chain_B2A\[\]\) is true\.", "Lemma 1.3: Secrecy of ChainKey B->A"),
        (r"RESULT not attacker\(secret_msg_A2B\[\]\) is true\.", "Lemma 1.4: Secrecy of Payload Msg A->B"),
        (r"RESULT not attacker\(secret_msg_B2A\[\]\) is true\.", "Lemma 1.5: Secrecy of Payload Msg B->A"),
        (r"RESULT not attacker\(secret_reaction_emoji\[\]\) is true\.", "Lemma 1.6: Secrecy of Reaction Micro-Payload (0x07)"),
        (r"RESULT not attacker\(secret_location_pin\[\]\) is true\.", "Lemma 1.7: Secrecy of Location Pin Micro-Payload (0x08)"),
        (r"RESULT inj-event\(AliceFinished\(pkA_kem,pkA_x,seed,ckA2B,ckB2A,sas_2\)\) ==> inj-event\(BobFinished\(pkA_kem,pkA_x,seed,ckA2B,ckB2A,sas_2\)\) is true\.", "Lemma 1.8: Mutual Authentication & SAS Binding"),
        (r"RESULT inj-event\(BobRecvMsg\(target_.*,seq_.*,msg\)\) ==> inj-event\(AliceSentMsg\(target_.*,seq_.*,msg\)\) is true\.", "Lemma 1.9: Injective Message Delivery A->B"),
        (r"RESULT inj-event\(AliceRecvReply\(target_.*,seq_.*,msg\)\) ==> inj-event\(BobSentReply\(target_.*,seq_.*,msg\)\) is true\.", "Lemma 1.10: Injective Message Delivery B->A"),
        (r"RESULT inj-event\(BobRecvReaction\(target_.*,seq_.*,emoji\)\) ==> inj-event\(AliceSentReaction\(target_.*,seq_.*,emoji\)\) is true\.", "Lemma 1.11: Authenticity and AAD Binding of Reaction (0x07)"),
        (r"RESULT inj-event\(AliceRecvLocationPin\(target_.*,seq_.*,loc\)\) ==> inj-event\(BobSentLocationPin\(target_.*,seq_.*,loc\)\) is true\.", "Lemma 1.12: Authenticity and AAD Binding of Location Pin (0x08)"),

        (r"RESULT not attacker\(secret_chain_A2B\[\]\) is true\.", "Lemma 2.1: Secrecy of ChainKey A->B"),
        (r"RESULT not attacker\(secret_chain_B2A\[\]\) is true\.", "Lemma 2.2: Secrecy of ChainKey B->A"),
        (r"RESULT not attacker\(secret_msg_A2B\[\]\) is true\.", "Lemma 2.3: Secrecy of Payload Msg A->B"),
        (r"RESULT not attacker\(secret_msg_B2A\[\]\) is true\.", "Lemma 2.4: Secrecy of Payload Msg B->A"),
        (r"RESULT inj-event\(AliceFinished\(pkA_kem,pkA_x,seed,ckA2B,ckB2A\)\) ==> inj-event\(BobFinished\(pkA_kem,pkA_x,seed,ckA2B,ckB2A\)\) is true\.", "Lemma 2.5: Key Confirmation Agreement"),

        (r"RESULT not attacker\(secret_msg_0\[\]\) is true\.", "Lemma 3.1: Forward Secrecy of past msg_0"),
        (r"RESULT not attacker\(secret_msg_1\[\]\) is false\.", "Lemma 3.2: Soundness of state compromise (msg_1 compromised)"),

        (r"RESULT not attacker\(secret_new_chain_key\[\]\) is true\.", "Lemma 4.1: Post-Compromise Security of ChainKey"),
        (r"RESULT not attacker\(secret_msg_post_rekey\[\]\) is true\.", "Lemma 4.2: Post-Compromise Security of Post-Rekey Msg"),

        (r"RESULT inj-event\(HandshakeAccepted\(target_.*,ct,pkx,salt_.*\)\) ==> inj-event\(HandshakeSent\(target_.*,ct,pkx,salt_.*\)\) is true\.", "Lemma 5.1: Injective Handshake Agreement"),
        (r"RESULT inj-event\(MessageAccepted\(target_.*,seq,msg\)\) ==> inj-event\(MessageSent\(target_.*,seq,msg\)\) is true\.", "Lemma 5.2: Injective Message Delivery"),

        (r"RESULT Observational equivalence is true\.", "Lemma 6.1: Target Unlinkability & Tombstone Indistinguishability"),

        (r"RESULT not attacker\(secret_sender_group_chain_key\[\]\) is true\.", "Lemma 7.1: Secrecy of Group Sender Key (Type 0x06)"),
        (r"RESULT inj-event\(BobRecvGroupMsg\(target_.*,g_id,sender_id,msg\)\) ==> inj-event\(AliceSentGroupMsg\(target_.*,g_id,sender_id,msg\)\) is true\.", "Lemma 7.2: Authenticity of Group Messages with AAD Binding"),
        (r"RESULT not attacker\(secret_group_msg_pre_leave\[\]\) is true\.", "Lemma 7.3: Forward Secrecy of Past Group Messages"),
        (r"RESULT not attacker\(secret_group_msg_post_leave\[\]\) is true\.", "Lemma 7.4: Post-Compromise Security in Epoch + 1"),

        (r"RESULT not attacker\(secret_db_payload\[\]\) is true\.", "Lemma 8.1: Secrecy of SQLite Payload & Irreversibility of Master Key Erasure"),
        (r"RESULT inj-event\(DecoyModeActivated\) ==> inj-event\(MasterKeyDeleted\) is true\.", "Lemma 8.2: Decoy Screen Activation Correspondence with Key Deletion"),
        (r"RESULT not attacker\(secret_swapped_plaintext\[\]\) is true\.", "Lemma 8.3: Secrecy of Swapped Plaintext"),
        (r"RESULT not event\(SwappedRecordDecrypted\(secret_db_payload\[\]\)\) is true\.", "Lemma 8.4: Non-Decryptability & Resistance to Row/Column Swap Attacks")
    ]

    print("\n==============================================================================")
    print(" Formal Verification Results:")
    print("==============================================================================")

    current_section = ""
    errors = 0
    for pattern, name in lemmas:
        sec = name.split(":")[0].split()[1].split(".")[0]
        sec_names = {
            "1": "--- 1. Unified Protocol Model ---",
            "2": "--- 2. Secrecy & Confirmation Model ---",
            "3": "--- 3. Forward Secrecy Model ---",
            "4": "--- 4. Post-Compromise Security Model ---",
            "5": "--- 5. Anti-Replay Injective Agreement Model ---",
            "6": "--- 6. Target Unlinkability & 900B Tombstones ---",
            "7": "--- 7. Group Chat Protocol & Key Rotation Model ---",
            "8": "--- 8. Duress Wipe & Row-Bound V2 Model ---"
        }
        if sec != current_section:
            current_section = sec
            print(sec_names.get(sec, f"--- {sec} ---"))

        if re.search(pattern, text):
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name} (Pattern '{pattern}' not found)")
            errors += 1

    verdict = f"""
==============================================================================
FINAL AUDIT VERDICT:
==============================================================================
STATUS: {"ALL LEMMAS FORMALLY PROVED (PASS)" if errors == 0 else f"VERIFICATION FAILED WITH {errors} ERRORS"}
Total Lemmas Tested: {len(lemmas)}
Failed: {errors}
==============================================================================
"""
    with open(report_file, "a", encoding="utf-8") as f:
        f.write(verdict)

    print("==============================================================================")
    if errors == 0:
        print(f" [SUCCESS] All 8 formal verification models PROVED successfully ({len(lemmas)}/{len(lemmas)} lemmas passed).")
        print(f" Detailed report written to: {report_file}")
        print("==============================================================================")
        sys.exit(0)
    else:
        print(f" [FAILURE] Formal verification failed with {errors} errors.")
        print(f" Detailed report written to: {report_file}")
        print("==============================================================================")
        sys.exit(1)

if __name__ == "__main__":
    main()
