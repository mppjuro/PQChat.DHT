# Formal Security Verification of the PQChat.DHT Protocol (ProVerif 2.05)

This directory contains complete formal cryptographic models and automated machine-checked security proofs for the **PQChat.DHT** protocol in the symbolic Dolev-Yao model using the **ProVerif 2.05** protocol verifier.

---

## 1. Scope of Models and Verified Security Properties

The protocol combines:
* **Hybrid Key Encapsulation Mechanism (Hybrid KEM):** Combining post-quantum **ML-KEM-512** (FIPS 203) and classical **X25519 ECDH** (RFC 7748) for dual defense (*Dual-Defense / IND-CCA2*).
* **Dual Unidirectional Chains:** Based on **HKDF-SHA512** (RFC 5869), where track $A 	o B$ and track $B 	o A$ are completely decoupled numerically and in addressing space.
* **Context-Bound AEAD Payload Encryption:** **AES-256-GCM** with AAD binding to destination target and transmission direction.
* **Anti-Grinding Commitment and SAS:** **SHA-256** hash with transcript commitment $`Commitment = 	ext{SHA-256}(	ext{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)`$ and 8-digit **Short Authentication String (SAS)**.
* **One-Time Ed25519 Transport Signatures (BEP 44):** Used strictly as an ephemeral single-use token for writing to the DHT.
* **Key Hopping:** Ephemeral destination address $	ext{Target}_i = 	ext{SHA-1}(pk_i)$.
* **Secure Slot Sanitization (900-Byte Tombstone):** Overwriting consumed DHT records with a rigid 900-byte CSPRNG noise frame at sequence number $	ext{seq} + 1$, preventing DHT nodes and eavesdroppers from detecting message consumption timing.

Six fundamental security pillars were formally verified:

### (1) Secrecy
* **Secrecy of Master Key and Ratchet Chains (`pqchat_protocol.pv`, `pqchat_secrecy.pv`):**
  * `Query not attacker(secret_master_key[]) is true`
  * `Query not attacker(secret_chain_A2B[]) is true`
  * `Query not attacker(secret_chain_B2A[]) is true`
  * A public DHT network observer or physical observer of the plaintext QR code ($pk_A^{hybrid} \parallel Seed_{init}$) cannot learn the master key $MasterKey$ or channel keys $ChainKey_{A 	o B}$, $ChainKey_{B 	o A}$.
* **Secrecy of Message Payloads:**
  * `Query not attacker(secret_msg_A2B[]) is true`
  * `Query not attacker(secret_msg_B2A[]) is true`
  * Message contents exchanged in both directions are unreachable by a Dolev-Yao adversary.

### (2) Mutual Authentication and Transcript Binding (Authentication & SAS Binding)
* **Injective Correspondence Agreement (`pqchat_protocol.pv`, `pqchat_secrecy.pv`):**
  * `Query inj-event(AliceFinished(pkA_kem, pkA_x, seed, ckA2B, ckB2A, sas)) ==> inj-event(BobFinished(pkA_kem, pkA_x, seed, ckA2B, ckB2A, sas)) is true`
  * Completion of the handshake by Alice guarantees Bob participated in the identical session with matching transcript, identical hybrid KEM keys (ML-KEM-512 + X25519), and identical SAS code.
  * The anti-grinding commitment $Commitment$ prevents an adversary from manipulating parameters in transit while maintaining matching SAS codes.

### (3) Forward Secrecy
* **Resistance to Chain State Compromise (`pqchat_forward_secrecy.pv`):**
  * `Query not attacker(secret_msg_0[]) is true`
  * `Query not attacker(secret_msg_1[]) is false` (proof of non-triviality)
  * When an adversary obtains physical access to device RAM at step $i=1$ and learns $ChainKey_1$, the one-way property of HKDF-SHA512 guarantees that $ChainKey_0$ cannot be computed backward; message $msg_0$ remains fully secret.

### (4) Post-Compromise Security / PCS (Self-Healing State)
* **Secrecy Recovery after Hybrid KEM Rotation (`pqchat_post_compromise.pv`):**
  * `Query not attacker(secret_new_chain_key[]) is true`
  * `Query not attacker(secret_msg_post_rekey[]) is true`
  * Even if an adversary completely compromises the chain state ($ChainKey_{old}$), following an asymmetric hybrid ML-KEM-512 + X25519 rekey (Type `0x03` offer + Type `0x04` response), injecting a fresh secret:
    $$ChainKey_{new} \leftarrow 	ext{HKDF-Extract}(ChainKey_{old}, SS_{rekey}^{hybrid})$$
    restores full secrecy of subsequent session keys and all future messages.

### (5) Replay Resistance
* **Injective Packet Delivery (`pqchat_replay.pv` and `pqchat_protocol.pv`):**
  * `Query inj-event(HandshakeAccepted(target, ct, pkx, salt)) ==> inj-event(HandshakeSent(target, ct, pkx, salt)) is true`
  * `Query inj-event(BobRecvMsg(target, seq, msg)) ==> inj-event(AliceSentMsg(target, seq, msg)) is true`
  * `Query inj-event(AliceRecvReply(target, seq, msg)) ==> inj-event(BobSentReply(target, seq, msg)) is true`
  * No packet in the DHT can be accepted more than once, guaranteed by key-hopping targets $Target_i = 	ext{SHA-1}(pk_i)$, fresh IVs, AAD context binding, sequence windows, and slot sanitization via tombstones.

### (6) Unlinkability and Tombstone Indistinguishability
* **Observational Equivalence (`pqchat_unlinkability.pv`):**
  * `Query Observational equivalence is true`
  * DHT nodes observing queries to $`	ext{Target}_i = 	ext{SHA-1}(pk_i)`$ cannot distinguish queries of session $`(Alice, Bob)`$ from queries of session $`(Charlie, Dave)`$ (Metadata-Free Rendezvous).
  * The rigid 900-byte Tombstone record (CSPRNG noise) written upon message receipt is mathematically indistinguishable from normal 900-byte AES-256-GCM ciphertexts and from 900-byte Poisson cover traffic dummy packets.

### (7) Group Chat Protocol and Key Rotation (Group Protocol & PCS/FS)
* **Secrecy of Group Sender Chain Key (`pqchat_group_protocol.pv`):**
  * `Query not attacker(secret_sender_group_chain_key[]) is true`
  * Distribution of the group sender chain key in Type `0x06` frame (`TYPE_GROUP_CONTROL`, subtype `0x01` INVITE / `0x02` REKEY) over a 1-on-1 hybrid channel (ML-KEM-512 + X25519) guarantees full secrecy against a Dolev-Yao network adversary.
* **Authenticity of Group Messages with AAD Context Binding:**
  * `Query inj-event(BobRecvGroupMsg(target_x, g_id, sender_id, msg)) ==> inj-event(AliceSentGroupMsg(target_x, g_id, sender_id, msg)) is true`
  * AAD context binding $`AAD = 	ext{Target} \parallel GroupID \parallel SenderMemberID`$ in AES-256-GCM prevents sender spoofing, group substitution, or target slot swapping.
* **Forward Secrecy and Post-Compromise Security (PCS) in Groups:**
  * `Query not attacker(secret_group_msg_pre_leave[]) is true` (Forward Secrecy: prior group messages remain secret after a member leaves).
  * `Query not attacker(secret_group_msg_post_leave[]) is true` (Post-Compromise Security: messages transmitted in new epoch $`groupEpoch + 1`$ after member leave `GROUP_SUBTYPE_LEAVE` and key rotation are secret from the former group member).

---

## 2. Unified Formal Model Suite

| File | Description and Verified Properties |
| :--- | :--- |
| `pqchat_protocol.pv` | **Main Unified Protocol Model:** Proves secrecy of master key and chains, message payloads, injective mutual authentication with SAS and transcript binding, bidirectional exchange with AAD, replay resistance, and 900-byte secure tombstones. |
| `pqchat_secrecy.pv` | **Dedicated Secrecy & Key Confirmation Model:** Verification of $`ChainKey_{A 	o B}, ChainKey_{B 	o A}`$, payload secrecy, and injective agreement with hybrid X25519 + ML-KEM-512 handshake. |
| `pqchat_forward_secrecy.pv` | **Forward Secrecy Model:** Formal proof protecting past messages upon compromise of subsequent chain states in device RAM. |
| `pqchat_post_compromise.pv` | **Post-Compromise Security (PCS) Model:** Formal proof of self-healing state recovery following hybrid X25519 + ML-KEM-512 rotation. |
| `pqchat_replay.pv` | **Anti-Replay Model:** Proof of injective packet acceptance for handshake and data transmission with slot invalidation. |
| `pqchat_unlinkability.pv` | **Unlinkability & Tombstones Model:** Proof of observational equivalence (`diff-equivalence`) for target hopping and indistinguishability of 900-byte tombstones from normal frames and cover traffic. |
| `pqchat_group_protocol.pv` | **Group Chat Protocol & Key Rotation Model:** Proof of secrecy of group sender key distribution in `0x06` frame via 1-on-1 channel (ML-KEM-512 + X25519), authenticity of group messages with AAD binding ($`	ext{Target} \parallel GroupID \parallel SenderMemberID`$), and Forward Secrecy / Post-Compromise Security upon member departure ($`groupEpoch + 1`$). |
| `run_verification.sh` | Shell script automating execution of proofs in ProVerif, result aggregation, verification of all 24 lemmas, and generating `report.txt`. |
| `report.txt` | Full Dolev-Yao verification report generated by ProVerif. |

---

## 3. Running Formal Verification

Executing the formal models requires **ProVerif** (version $`\ge 2.04`$):

```bash
# Execute full verification suite (24 lemmas across 7 models):
bash docs/formal/run_verification.sh
```

The script automatically:
1. Detects ProVerif binaries in PATH, `/usr/local/bin`, WSL Ubuntu, or compiles from Inria sources in Linux/CI environments.
2. Executes symbolic analysis across each of the 7 `.pv` models.
3. Verifies exact lemma formulas (24/24 PASS).
4. Generates a detailed verification report in `docs/formal/report.txt`.
5. Returns exit code `0` when all lemmas pass.
