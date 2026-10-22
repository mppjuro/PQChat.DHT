# PQChat.DHT Protocol Specification (v2.0)

This document provides the complete technical specification of the **PQChat.DHT** communication protocol — a decentralized, post-quantum, asynchronous mobile messaging system for Android, leveraging the public BitTorrent Mainline DHT (BEP 44) as an ephemeral *Store-and-Forward* buffer.

---

## 1. System Architecture and Threat Model

### 1.1. Core Architectural Pillars
1. **Serverless & Zero Metadata:** Complete absence of centralized servers, push notification brokers (FCM/APNs), and static user identifiers or accounts.
2. **Client-Only Leaf Node Mode:** Mobile devices never route third-party KRPC packets and never buffer data for other nodes in RAM. They function exclusively as initiators of UDP `put` / `get` queries (BEP 44).
3. **Ephemeral DHT Buffer (Store-and-Forward):** Messages are stored as mutable BEP 44 records with a retention lifespan of 24–72 hours.
4. **Post-Quantum Cryptography (PQC):** Protection against *Harvest Now, Decrypt Later* attacks using the NIST-standardized **ML-KEM-512** algorithm (FIPS 203 / Kyber-512).
5. **Anti-Traffic Analysis:** Emission of Poisson-distributed dummy noise packets to eliminate temporal correlation between user activity and UDP frame transmissions.

### 1.2. Cryptographic Assumptions & Security Model (Security Assumptions)

> [!IMPORTANT]
> **Assumption 1: Public Seed in QR Code ($Seed_{init}$ is Public)**
> The QR code presented during out-of-band pairing (Handshake) contains:
> $$QR = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B}) \quad (\text{total } 864\text{ bytes})$$
> The protocol **does not assume confidentiality** of the QR code against physical observers (e.g., shoulder surfing or surveillance cameras).
> * $Seed_{init}$ is used exclusively for one-time deterministic derivation of the DHT rendezvous point:
>   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
>   as well as for transcript binding and collision avoidance.
> * Even if an adversary learns $pk_A$ and $Seed_{init}$, **they cannot decrypt messages or determine the shared secret**, because secrecy relies strictly on the hardness of ML-KEM-512 (Module Learning With Errors — M-LWE) and X25519 ECDH (DLP).
> * Man-in-the-Middle attacks (tampering with DHT responses) are prevented by the **Key Confirmation Tag** and **Short Authentication String (SAS)**.

> [!WARNING]
> **Assumption 2: Ed25519 Signature in BEP 44 is Not Post-Quantum**
> The public BitTorrent DHT network (BEP 44 specification) requires each mutable record to be signed with Ed25519 public key $k$ ($32\text{ B}$) and signature ($64\text{ B}$).
> * In PQChat.DHT, the Ed25519 key is a **one-time, ephemeral transport token** derived from the current ratchet chain state ($EdSeed_i$).
> * Ed25519 **does not encrypt payloads and does not participate in shared secret negotiation**.
> * An adversary with access to a quantum computer (Shor's algorithm) could break the Ed25519 signature and overwrite the DHT record (Denial of Service or in-flight frame tampering), but **cannot break payload encryption (ML-KEM + AES-256-GCM)**. Any tampered frames are immediately discarded by the recipient due to AEAD tag verification failure.

---

## 2. Rendezvous Phase and Handshake

The pairing workflow consists of 3 steps: QR generation by Alice, processing and publishing by Bob, and retrieval and verification by Alice.

```
       Alice                                                  Bob
  (Displays QR)                                          (Scans QR)
         |                                                    |
  1. Generates (pk_A, sk_A)                                   |
     Seed_init <- CSPRNG(32)                                  |
     Target_0 = SHA-1(...)                                    |
     Presents QR: pk_A || Seed_init                           |
         | ---------------- Scan QR (OOB) ------------------> |
         |                                                    |
         |                                            2. Encapsulate(pk_A) -> (SS_init, ct_B)
         |                                               Generates salt (24 B)
         |                                               Transcript = pk_A || ct_B || Seed_init || salt
         |                                               Commitment = SHA-256("PQChat_AntiGrind_v2" || Seed_init || Transcript)
         |                                               PRK = HKDF-Extract(salt, SS_init)
         |                                               MasterKey = HKDF-Expand(PRK, label || SHA-512(Transcript), 64)
         |                                               ConfirmTag = HKDF-Expand(MasterKey, "KeyConfirmationBob", 32)
         |                                               SAS = HKDF-Expand(MasterKey, "PQChat_SAS_v2_AntiGrind" || Commitment, 8)
         |                                               Builds Type 0x01 frame (ct_B, salt, ConfirmTag)
         |                                               DHT putMutable(Target_0, Frame_0x01, sk_Ed)
         | <================= DHT PUT/GET (Target_0) ======== |
         |
  3. DHT GET(Target_0) -> Receives Type 0x01 frame
     Decapsulate(sk_A, ct_B) -> SS_init
     Transcript = pk_A || ct_B || Seed_init || salt
     Commitment = SHA-256("PQChat_AntiGrind_v2" || Seed_init || Transcript)
     PRK = HKDF-Extract(salt, SS_init)
     MasterKey = HKDF-Expand(PRK, label || SHA-512(Transcript), 64)
     Verify ConfirmTag == computeConfirmationTag(MasterKey)
     [FAIL -> keep sk_A, continue awaiting valid frame]
     [SUCCESS -> zero sk_A, derive chains, SAS = computeSas(MasterKey, Commitment)]
```

### 2.1. Step 1 (Alice): Initialization and QR Presentation
1. Keypair Generation: $(pk_A, sk_A) \leftarrow \text{Hybrid-KEM.KeyGen}()$ (832 B public key: 800 B ML-KEM-512 + 32 B X25519).
2. Random Seed Generation: $Seed_{init} \leftarrow \text{CSPRNG}(32\text{ bytes})$.
3. Rendezvous Address Derivation ($Target_0$):
   $$HMAC_0 = \text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"})$$
   $$Target_0 = \text{SHA-1}(HMAC_0)$$
4. QR Payload Presentation (strict 864 bytes size):
   $$QR_{payload} = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B})$$

### 2.2. Step 2 (Bob): Scanning, Encapsulation, and BEP 44 Publication
1. QR Unpacking: extract $pk_A$ and $Seed_{init}$.
2. Hybrid Secret Encapsulation:
   $$(SS_{init}, ct_B) \leftarrow \text{Hybrid-KEM.Encapsulate}(pk_A)$$
   where $SS_{init} \in \{0,1\}^{256}$, $ct_B \in \{0,1\}^{6400}$ ($800\text{ bytes}$: 768 B ML-KEM + 32 B X25519 eph pk).
3. 24-Byte Cryptographic Salt Generation: $salt \leftarrow \text{CSPRNG}(24\text{ B})$.
4. Transcript Binding:
   $$Transcript = pk_A \parallel ct_B \parallel Seed_{init} \parallel salt \quad (1688\text{ bytes})$$
   $$TranscriptHash = \text{SHA-512}(Transcript) \quad (64\text{ bytes})$$
5. Master Key Derivation ($MasterKey$):
   $$PRK = \text{HKDF-Extract}(salt, SS_{init})$$
   $$MasterKey = \text{HKDF-Expand}(PRK, \text{"PQChat\_MasterKey\_Transcript"} \parallel TranscriptHash, 64)$$
6. Key Confirmation Tag Computation:
   $$ConfirmTag = \text{HKDF-Expand}(MasterKey, \text{"KeyConfirmationBob"}, 32)$$
7. Greeting Frame Transport Key Derivation:
   $$k_{hs} = \text{HKDF-Derive}(null, Seed_{init}, \text{"hs\_enc"}, 32)$$
   $$EdSeed_{hs} = \text{HKDF-Derive}(null, Seed_{init}, \text{"hs\_ed25519"}, 32)$$
8. Internal Payload Assembly (Type `0x01` — Handshake Finalize):
   * Header (13 B): $MsgType = 0x01$, $SeqNum = 0$, $AckNum = 0$, $TimestampUTC$.
   * $ct_B$ (800 B).
   * $salt$ (24 B).
   * $ConfirmTag$ (32 B).
   * CSPRNG Padding (3 B).
   AEAD encryption with key $k_{hs}$ and $\text{AAD} = Target_0 \parallel \text{"BobToAlice"}$.
9. Publication to DHT via `putMutable` at $Target_0$ signed with $EdSeed_{hs}$.
10. Unidirectional Chains and SAS Derivation:
    $$ChainKey_{A \to B} = \text{HKDF-Expand}(MasterKey, \text{"AliceToBob"}, 64)$$
    $$ChainKey_{B \to A} = \text{HKDF-Expand}(MasterKey, \text{"BobToAlice"}, 64)$$
    $$Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)$$
    $$SAS = \text{computeSas}(MasterKey, Commitment)$$

### 2.3. Step 3 (Alice): Retrieval from DHT, Decryption, and Verification
1. Alice periodically polls DHT at target address $Target_0$.
2. Upon receiving the packet, she decrypts the frame with key $k_{hs}$ and $\text{AAD} = Target_0 \parallel \text{"BobToAlice"}$.
3. Decapsulates the hybrid secret:
   $$SS_{init} \leftarrow \text{Hybrid-KEM.Decapsulate}(sk_A, ct_B)$$
4. Reconstructs $Transcript$, computes $TranscriptHash$, $PRK$, and $MasterKey$.
5. Verifies $ConfirmTag$ in constant time (`MessageDigest.isEqual`):
   * **Mismatch:** authenticity failure (e.g. invalid ciphertext or attack attempt). Alice **does not destroy** $sk_A$, remaining able to await Bob's genuine frame.
   * **Match Confirmed:** Alice immediately zeroes private key memory $sk_A$ (ML-KEM and X25519), initializes chains $ChainKey_{A \to B}$, $ChainKey_{B \to A}$, and computes an identical $SAS$ code.

---

## 3. Hardened SAS (Short Authentication String) with Anti-Grinding Commitment

### 3.1. Grinding Attack Threat
In classical 6-digit SAS codes ($10^6$ combinations), an active attacker eavesdropping on the QR code could manipulate their own contribution (KEM ciphertext or $salt$), performing an average of $5 \cdot 10^5$ offline hashing trials to induce a collision in the SAS code verified by victims.

### 3.2. Anti-Grinding Commitment
PQChat.DHT implements a cryptographic commitment bound to the complete transcript and initiator seed:
$$Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)$$

### 3.3. 8-Digit SAS Code Derivation
The SAS code is derived from $MasterKey$ and $Commitment$ using label `PQChat_SAS_v2_AntiGrind`:
$$\text{Entropy}_{SAS} = \text{HKDF-Expand}(MasterKey, \text{"PQChat\_SAS\_v2\_AntiGrind"} \parallel Commitment, 8)$$
The entropy bits are divided into two 4-digit groups modulo 10000:
$$Part_1 = (\text{Uint32BE}(\text{Entropy}_{SAS}[0..3]) \ \& \ \text{0x7FFFFFFF}) \pmod{10000}$$
$$Part_2 = (\text{Uint32BE}(\text{Entropy}_{SAS}[4..7]) \ \& \ \text{0x7FFFFFFF}) \pmod{10000}$$
$$SAS = \text{format}(\text{"\%04d-\%04d"}, Part_1, Part_2)$$
* **Search Space:** $10^8$ (100 million combinations, ~26.6 bits of entropy).
* **Commitment Property:** Any tampering with $pk_A$, $ct_B$, $Seed_{init}$, or $salt$ alters both $MasterKey$ and $Commitment$, producing a completely divergent SAS code.
* **UI Verification:** Users view the SAS code in `HandshakeScreen` and `ChatScreen` and can mark the contact as `isVerified = true` with a single tap.

---

## 4. Deterministic Track Separation (Dual Unidirectional Chains)

Communication between two contacts is governed by two completely disjoint, unidirectional ratchet chains:

1. **Track $A \to B$ (Alice to Bob):**
   * Initial state: $ChainKey_{A \to B}$.
   * Alice increments her $Counter_{out}$.
   * Bob increments his $Counter_{in}$.
2. **Track $B \to A$ (Bob to Alice):**
   * Initial state: $ChainKey_{B \to A}$.
   * Bob increments his $Counter_{out}$.
   * Alice increments her $Counter_{in}$.

Sending a message in one direction **never** consumes keys or alters sequence counters in the reverse track. This avoids deadlocks and state desynchronization in asynchronous DHT environments.

---

## 5. Ephemeral Address Hopping (Key Hopping)

For each consecutive message $i$ in a given track:

1. 128 bytes of entropy are expanded:
   $$Entropy_i = \text{HKDF-Expand}(ChainKey^i, \text{"step"} \parallel \text{Uint32BE}(i), 128)$$
2. Entropy Partitioning:
   * **Bytes 0–31 (32 B):** $MsgKey_i$ — AES-256 symmetric key for message payload encryption.
   * **Bytes 32–63 (32 B):** $EdSeed_i$ — one-time seed for the ephemeral Ed25519 keypair $(pk_i^{Ed}, sk_i^{Ed})$ required by BEP 44.
   * **Bytes 64–127 (64 B):** $ChainKey^{i+1}$ — updated chain key state for the subsequent message.
3. Target Address Derivation in DHT:
   $$Target_i = \text{SHA-1}(pk_i^{Ed})$$
4. Secure Memory Erasure: Upon completion, byte arrays containing $Entropy_i$, $EdSeed_i$, and $MsgKey_i$ are immediately cleared (`fill(0)`).

Consequently, address $Target_i$ is pseudorandom to outside observers and known strictly to the sender and recipient possessing $ChainKey^i$.

---

## 6. Post-Quantum Rotation (Rekeying every 50 messages)

To guarantee **Post-Compromise Security (PCS)** (self-healing after potential RAM key compromise), the protocol enforces asymmetric KEM key renegotiation every 50 messages sent.

```
       Sender (Counter_out == 50k)                        Receiver
            |                                                 |
  1. Generates fresh ML-KEM-512 pair                          |
     (pk_new, sk_new)                                         |
     Stores PendingOffer(epoch+1, sk_new)                     |
     Sends Type 0x03 packet (Rekey Offer: pk_new)             |
            | =================== DHT ======================> |
            |                                                 |
            |                                         2. Receives Type 0x03
            |                                            Encapsulate(pk_new) -> (SS_rekey, ct_rekey)
            |                                            Injects SS_rekey into input chain:
            |                                            ChainKey_in <- HKDF-Extract(ChainKey_in, SS_rekey)
            |                                            Sends Type 0x04 packet (ct_rekey) in return track
            | <================== DHT ======================= |
            |
  3. Receives Type 0x04 in return track
     Decapsulate(sk_new, ct_rekey) -> SS_rekey
     ChainKey_out <- HKDF-Extract(ChainKey_out, SS_rekey)
     Retires and zeroes sk_new
     Increments rekeyEpoch
```

### 6.1. Type 0x03: PQC Rekey Offer
When $Counter_{out} > 0$ and $Counter_{out} \equiv 0 \pmod{50}$:
* The sender generates a fresh keypair $(pk_{new}, sk_{new}) \leftarrow \text{Hybrid-KEM.KeyGen}()$.
* Securely stores $sk_{new}$ in the database (encrypted with Android Keystore) as a `PendingRekeyOfferEntity`.
* Transmits a Type `0x03` packet containing $RekeyEpoch$ and $pk_{new}$ ($832\text{ B}$: 800 B ML-KEM-512 + 32 B X25519).

### 6.2. Type 0x04: PQC Rekey Response
* Upon receiving the offer, the recipient executes `Encapsulate(pk_new)`, obtaining $(SS_{rekey}, ct_{rekey})$.
* Immediately injects the new shared secret into their incoming chain:
  $$ChainKey_{in} \leftarrow \text{HKDF-Extract}(ChainKey_{in}, SS_{rekey})$$
* In their return channel, transmits a Type `0x04` packet containing $RekeyEpoch$ and $ct_{rekey}$ ($800\text{ B}$: 768 B ML-KEM-512 + 32 B X25519 eph pk).

### 6.3. Response Consumption by Initiator
* The initiator receives the Type `0x04` packet and decapsulates the secret:
  $$SS_{rekey} \leftarrow \text{Hybrid-KEM.Decapsulate}(sk_{new}, ct_{rekey})$$
* Injects the secret into their outgoing chain:
  $$ChainKey_{out} \leftarrow \text{HKDF-Extract}(ChainKey_{out}, SS_{rekey})$$
* Destroys $sk_{new}$ (zeroing ML-KEM and X25519 private key memory) and deletes the entity from the database.

### 6.4. Unique BEP 44 Target Addresses per Recipient in Group Chats
In group chats, instead of using a single shared target address $Target = \text{RatchetChain.deriveSlot}(myChainKeyOut, counterOut)$ for all group members, the sender derives a unique target address for each member:
$$\text{memberTarget} = \text{HKDF-Expand}(myChainKeyOut, \text{"group\_target:"} \parallel groupId \parallel counterOut \parallel memberId, 32)$$
and then generates dedicated slot parameters (`msgKey`, `edPrivateKeySeed`, `target`) via `RatchetChain.deriveGroupRecipientSlot`.

The sender executes distinct `putMutable` operations under each unique target address ($N$ targets for $N$ members). In `pollGroupIncoming`, each member polls **only their unique target, never a shared one**.

**Security Rationale:** A same-target design for all members allows a DHT observer to correlate $N$ recipients through concurrent `GET` queries on the same slot, breaking group destination secrecy (Group Follower Correlation). Distributing slots across $N$ independent pseudorandom addresses guarantees that observers cannot correlate recipients or discover their co-membership in the group.

---

## 7. Binary Frame Format for DHT Records (BEP 44 Value)

Each binary record ('v') published in the DHT has a **strict, fixed size of exactly 900 bytes** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES = 900`).

### 7.1. 900 B Payload Size Justification and BEP 44 Compliance
According to BitTorrent BEP 44, the total size of the value field `'v'` after Bencode encoding **must not exceed 1000 bytes**:
* In Bencode format, a byte string is encoded with a length prefix: `<length>:<data>`.
* For a raw 900-byte payload, the encoded string is `"900:"` (4 bytes prefix) + 900 bytes of data = **exactly 904 bytes**, strictly complying with the BEP 44 limit ($\le 1000$ B).
* **Critical Note:** If the raw payload were 1000 bytes, its Bencode representation would be `"1000:"` (5 bytes prefix) + 1000 bytes of data = **1005 bytes**, which **exceeds the BEP 44 limit** and triggers immediate packet rejection by public BitTorrent DHT nodes!

```
+─────────────────────────────────────────────────────────────────────────────+
|                   BEP 44 VALUE RECORD (FIXED 900 BYTES)                     |
+────────────┬─────────────┬──────────────────────────────────────────────────+
| IV (Nonce) |  AEAD Tag   |              ENCRYPTED PAYLOAD                   |
|  12 bytes  |  16 bytes   |                 872 bytes                        |
+────────────┴─────────────┴─────────────────┬──────────────────┬─────────────+
                           | Header (13 B)   |   Type Data      | CSPRNG Noise|
                           +─────────────────┴──────────────────┴─────────────+
```

### 7.2. AEAD and AAD Authentication
* **Cipher:** AES-256-GCM.
* **AAD (Additional Authenticated Data):**
  $$\text{AAD} = Target \ (20\text{ B}) \parallel Direction \ (\text{"AliceToBob" or "BobToAlice"})$$
  AAD binding prevents reflection attacks and destination target substitution in DHT nodes.

### 7.3. Internal Plaintext Payload Header (13 bytes)
1. `MsgType` (1 B): Message type identifier.
   * `0x01` – Handshake Online Finalize
   * `0x02` – Standard Text Message
   * `0x03` – PQC Rekey Offer (Fresh Public Key)
   * `0x04` – PQC Rekey Response (Confirmation Ciphertext)
   * `0x05` – Block Transfer Segment (Chunk)
   * `0x06` – Group Control (`TYPE_GROUP_CONTROL`: Invite, Rekey, Leave)
   * `0x07` – Message Reaction (`TYPE_REACTION`: emoji bound to `(targetSeqEpoch, targetSeqNum)`)
   * `0x08` – Location Pin / Offline Safety Status (`TYPE_LOCATION_PIN`: coordinates and note)
2. `SeqNum` (2 B, UInt16 BE): Sender sequence counter $Counter_{out}$.
3. `AckNum` (2 B, UInt16 BE): Last acknowledged recipient sequence number.
4. `TimestampUTC` (8 B, Int64 BE): Unix epoch timestamp in milliseconds.

### 7.4. Message Types and Payload Structures (859 bytes after 13-byte header)
* **Type 0x01 (Handshake Finalize):**
  * `Hybrid Ciphertext`: 800 B (768 B ML-KEM-512 ct + 32 B X25519 eph pk)
  * `Salt`: 24 B
  * `Key Confirmation Tag`: 32 B
  * `CSPRNG Padding`: 3 B (859 - 856)
* **Type 0x02 (Text Message):**
  * `TextLength` ($L$): 2 B (UInt16, value $\le 857$)
  * `UTF-8 Payload`: $L$ bytes (up to 857 B of text)
  * `CSPRNG Padding`: $857 - L$ bytes
* **Type 0x03 (PQC Rekey Offer):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `Combined PublicKey`: 832 B (800 B ML-KEM-512 + 32 B X25519)
  * `CSPRNG Padding`: 23 B (859 - 836)
* **Type 0x04 (PQC Rekey Response):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `Hybrid Ciphertext`: 800 B (768 B ML-KEM-512 ct + 32 B X25519)
  * `CSPRNG Padding`: 55 B (859 - 804)
* **Type 0x05 (Block Transfer Segment — Chunk):**
  * `TransferID`: 16 B (UUID)
  * `ChunkIndex`: 2 B (UInt16 BE)
  * `TotalChunks`: 2 B (UInt16 BE)
  * `ChunkLength` ($C$): 2 B (UInt16, value $\le 837$)
  * `BinaryData`: $C$ bytes
  * `CSPRNG Padding`: $837 - C$ bytes
* **Type 0x06 (Group Control — TYPE_GROUP_CONTROL):**
  * `ControlSubType`: 1 B (`0x01` – `GROUP_SUBTYPE_INVITE`, `0x02` – `GROUP_SUBTYPE_REKEY`, `0x03` – `GROUP_SUBTYPE_LEAVE`)
  * `GroupID`: 16 B (Group UUID)
  * `GroupEpoch`: 4 B (UInt32 BE)
  * `SenderMemberID`: 16 B (Sender member UUID)
  * `SenderGroupChainKey`: 64 B (Current sender group ratchet chain key)
  * `CurrentCounter`: 4 B (UInt32 BE)
  * `GroupNameLength` ($N$): 2 B (UInt16, value $\le 64$)
  * `GroupName`: $N$ bytes UTF-8 (up to 64 bytes)
  * `MemberCount` ($M$): 2 B (UInt16, number of members, value $\le 64$)
  * `Members`: Array of $M$ entries: `MemberID` (16 B) + `NameLen` (1 B) + `MemberName` (up to 32 B UTF-8)
  * `CSPRNG Padding`: $859 - \text{length}$ bytes
* **Type 0x07 (Emoji Reaction — TYPE_REACTION):**
  * `TargetSeqEpoch`: 4 B (UInt32 BE)
  * `TargetSeqNum`: 2 B (UInt16 BE)
  * `EmojiLength` ($E$): 1 B (UInt8, value $\le 64$)
  * `Emoji`: $E$ bytes UTF-8 (up to 64 bytes)
  * `CSPRNG Padding`: $852 - E$ bytes (padding to 859 B)
* **Type 0x08 (Location Pin / Offline Safety Status — TYPE_LOCATION_PIN):**
  * `Latitude`: 8 B (Double IEEE 754 BE)
  * `Longitude`: 8 B (Double IEEE 754 BE)
  * `Altitude`: 8 B (Double IEEE 754 BE)
  * `Accuracy`: 4 B (Float IEEE 754 BE)
  * `NoteLength` ($P$): 2 B (UInt16 BE, value $\le 829$, or $\le 817$ for ephemeral messages)
  * `Note`: $P$ bytes UTF-8 (up to 829 bytes, or $\le 817$)
  * `Optional Ephemeral Header`: `MAGIC_EPHEMERAL` (8 bytes, `0x5051435F4550484DL`) + `EphemeralTtlSeconds` (4 bytes, UInt32 Big-Endian) – present only when $TTL > 0$
  * `CSPRNG Padding`: Padding to 859 B ($829 - P$ or $817 - P$ bytes)

### 7.5. Additional Fixed-Size 900 B Record Types
* **Cover-Traffic ACK:** Encrypted acknowledgement packet hidden in noise at target $Target_{ACK}$, formatted to exactly 900 bytes (`CoverAckProtocol`).
* **Cover Traffic Dummy:** Uncoordinated 900-byte record filled with pure CSPRNG noise (`DhtLeafNode.sendCoverTrafficDummy`).
* **Secure Tombstone (Slot Sanitization Upon Receipt):** Replaces consumed messages with a record of strict fixed size of exactly 900 bytes of pure CSPRNG noise under `seq = DEFAULT_MUTABLE_SEQ + 1` (`BinaryFrameCodec.createTombstonePayload`). This supersedes the vulnerable 0 B variant that revealed delivery timing to nodes and eavesdroppers. By maintaining a constant 900 B payload (904 B in Bencode), tombstone operations are indistinguishable from normal messages or cover traffic.

---

## 8. Group Chats, Key Distribution, and Database Tables

PQChat.DHT group messaging architecture is based on a decentralized **Sender Keys** protocol transported entirely across point-to-point (1-to-1) secure channels protected by hybrid KEM (ML-KEM-512 + X25519) and AES-256-GCM.

### 8.1. Group Key Distribution (Type 0x06 Frame)
1. Each participant generates an independent, dedicated 64-byte outgoing ratchet chain state $myChainKeyOut$.
2. The sender's key ($senderGroupChainKey$) is distributed to other members via Type `0x06` frames (`TYPE_GROUP_CONTROL`):
   * `GROUP_SUBTYPE_INVITE` (`0x01`): Group invitation, member roster, and initial sender chain key.
   * `GROUP_SUBTYPE_REKEY` (`0x02`): Sender key rotation (new epoch $groupEpoch + 1$, counter reset to 0).
   * `GROUP_SUBTYPE_LEAVE` (`0x03`): Member departure notification.
3. Type `0x06` frames are transmitted solely across 1-to-1 tracks between verified contacts, guaranteeing group key secrecy (proven in ProVerif Lemma 7.1).

### 8.2. Tracking-Free Addressing (Individual Recipient Slots)
To eliminate network observer correlation (Group Follower Correlation), the sender generates an **independent, unique DHT target address for each group message recipient**:
$$\text{Target}_{slot} = \text{RatchetChain.deriveGroupRecipientSlot}(ChainKey, Counter, GroupID, RecipientMemberID)$$
where the derivation context is:
$$\text{Info} = \text{"group\_target:"} \parallel GroupID \ (16\text{ B}) \parallel Counter \ (4\text{ B, BE}) \parallel RecipientMemberID \ (16\text{ B})$$
$$\text{memberEntropy} = \text{HKDF-Expand}(myChainKeyOut, \text{Info}, 64)$$
from which payload key $msgKey$ (first 32 bytes) and Ed25519 seed $edSeed$ (subsequent 32 bytes) are derived, yielding unique address $\text{Target} = \text{SHA-1}(pk_{Ed25519})$.

Broadcasting a message to $N$ members results in $N$ separate `putMutable` operations to pseudorandom targets, preventing DHT nodes from linking slots or discovering group composition. In `pollGroupIncoming`, each member polls only their unique target, never a shared one. Rationale: A same-target design enables DHT observers to correlate $N$ recipients via concurrent GETs to the same slot, breaking group destination secrecy.

### 8.3. AEAD Context Binding (Group AAD Binding)
Every group message (Type `0x02` text or Type `0x05` chunk) is encrypted with AES-256-GCM with strict AAD binding:
$$\text{AAD} = \text{Target} \ (20\text{ B}) \parallel GroupID \ (16\text{ B}) \parallel SenderMemberID \ (16\text{ B})$$
Attempting to redirect a record to another group or impersonate another member triggers an immediate AEAD tag verification error (`AEADBadTagException`).

### 8.4. Group Key Rotation: Forward Secrecy and Post-Compromise Security (PCS)
1. **Automatic Rotation Every 50 Messages:**
   When $Counter_{out} > 0$ and $Counter_{out} \equiv 0 \pmod{50}$ (`GROUP_REKEY_MESSAGE_INTERVAL = 50`), the sender generates a fresh CSPRNG key, increments epoch $groupEpoch + 1$, zeroes the counter, and transmits `GROUP_SUBTYPE_REKEY` to all active members.
2. **Mandatory Rotation on Member Departure (`GROUP_SUBTYPE_LEAVE`):**
   When any member leaves the group and broadcasts `GROUP_SUBTYPE_LEAVE`:
   * All remaining members immediately mark the departing member as inactive in the database (`isActive = false`).
   * Each active member immediately ratchets their $myChainKeyOut$ into a new epoch $groupEpoch + 1$.
   * A `GROUP_SUBTYPE_REKEY` frame is transmitted **exclusively to the remaining active members** (`if (!member.isActive || member.memberId == myMemberId) continue`).
   * This provides **Post-Compromise Security / Post-Leave Secrecy**: the departing participant has no access to the new chain state and cannot decrypt future group messages. Concurrently, KDF one-wayness protects past messages (**Forward Secrecy**).

### 8.5. Room Database Table Schemas

#### Table `groups`:
```sql
CREATE TABLE IF NOT EXISTS groups (
    groupId TEXT NOT NULL PRIMARY KEY,
    groupName TEXT NOT NULL,
    myMemberId TEXT NOT NULL,
    myChainKeyOut BLOB NOT NULL,
    myCounterOut INTEGER NOT NULL DEFAULT 0,
    groupEpoch INTEGER NOT NULL DEFAULT 1,
    createdAt INTEGER NOT NULL,
    lastActive INTEGER NOT NULL,
    isActive INTEGER NOT NULL DEFAULT 1
);
```
* `myChainKeyOut`: 64-byte outgoing ratchet state encrypted via `EncryptedBlob` with an Android Keystore key bound to `groups_${groupId}`.
* `groupEpoch`: Key epoch counter (incremented upon rekey or member departure).

#### Table `group_members`:
```sql
CREATE TABLE IF NOT EXISTS group_members (
    groupId TEXT NOT NULL,
    memberId TEXT NOT NULL,
    contactId TEXT,
    memberName TEXT NOT NULL,
    chainKeyIn BLOB NOT NULL,
    counterIn INTEGER NOT NULL DEFAULT 0,
    joinedAt INTEGER NOT NULL,
    isActive INTEGER NOT NULL DEFAULT 1,
    receivedBitmapBase INTEGER NOT NULL DEFAULT 0,
    receivedBitmap BLOB NOT NULL,
    PRIMARY KEY(groupId, memberId)
);
CREATE INDEX IF NOT EXISTS index_group_members_groupId ON group_members (groupId);
CREATE INDEX IF NOT EXISTS index_group_members_contactId ON group_members (contactId);
```
* `chainKeyIn`: 64-byte incoming ratchet state for the member, encrypted via `EncryptedBlob` bound to `group_members_${groupId}_${memberId}`.
* `isActive`: Membership status flag (`1` = active, `0` = departed / removed).
* `receivedBitmap`: Sliding bitmap for anti-replay protection preventing duplicate group frames.

---

## 9. Sequence Epochs and Lookahead Window

Due to the asynchronous nature of UDP and DHT transport, packets may arrive with latency or out of order.

1. **Lookahead Window ($n \dots n+4$):**
   * A recipient with current counter $Counter_{in} = n$ derives keys and polls the DHT for slots $Target_n, Target_{n+1}, \dots, Target_{n+4}$.
   * If message $n+2$ arrives out of order, keys for slots $n$ and $n+1$ are preserved in the secure `skipped_keys` table (encrypted via Keystore) in case those packets arrive later.
2. **Sliding Bitmap Window (Anti-Replay):**
   * A 1024-bit sliding bitmap in `ContactEntity` and `GroupMemberEntity` detects and rejects duplicates.
   * Messages with sequence number $SeqNum < Counter_{in} - 1024$ are unconditionally rejected.

---

## 10. Formal Security Verification (docs/formal/)

All fundamental protocol security guarantees have been symbolically verified using **ProVerif 2.05** under `docs/formal/` (24 lemmas across 7 models):

| Security Property | Model File | Verified Cryptographic Guarantees | ProVerif Outcome |
| :--- | :--- | :--- | :--- |
| **Unified Protocol** | `pqchat_protocol.pv` | MasterKey, tracks $A \to B$ and $B \to A$, AAD payloads, SAS transcript, and anti-replay | `RESULT: True` (8/8) |
| **Secrecy and Confirmation** | `pqchat_secrecy.pv` | Payload confidentiality and injective authentication in Hybrid KEM (ML-KEM-512 + X25519) | `RESULT: True` (5/5) |
| **Forward Secrecy (FS)** | `pqchat_forward_secrecy.pv` | Past message protection upon chain state compromise in RAM | `RESULT: True` (2/2) |
| **Self-Healing (PCS)** | `pqchat_post_compromise.pv` | Secrecy restoration after key compromise via asymmetric KEM rotation | `RESULT: True` (2/2) |
| **Anti-Replay Protection** | `pqchat_replay.pv` | Injective packet acceptance and monotonic slot invalidation via tombstones | `RESULT: True` (2/2) |
| **Unlinkability & Tombstones** | `pqchat_unlinkability.pv` | Observational equivalence of target addresses and indistinguishability of 900-byte tombstones | `RESULT: True` (1/1) |
| **Group Protocol and PCS/FS** | `pqchat_group_protocol.pv` | Sender key distribution, AAD binding, and group PCS/FS on member leave | `RESULT: True` (4/4) |

### In-Depth Summary of Verified Lemmas:

1. **Secrecy:** Proves that $MasterKey$, ratchet states $ChainKey_{A \to B}, ChainKey_{B \to A}$, and message payloads cannot be recovered by a Dolev-Yao adversary monitoring DHT queries and the public QR code (`pqchat_protocol.pv`, `pqchat_secrecy.pv`).
2. **Handshake Authentication & SAS Binding:** Proves injective correspondence (`inj-event(AliceFinished) ==> inj-event(BobFinished)`), binding the transcript, dual **Hybrid KEM (ML-KEM-512 + X25519)** protection, and SAS commitment ($Commitment$).
3. **Forward Secrecy:** Proves (`pqchat_forward_secrecy.pv`) that compromising ratchet state $ChainKey_1$ does not reveal earlier messages ($msg_0$).
4. **Post-Compromise Security (PCS):** Proves (`pqchat_post_compromise.pv`) that following a chain compromise, asymmetric hybrid KEM rotation completely restores secrecy for subsequent messages.
5. **Anti-Replay:** Proves injective packet acceptance (`pqchat_replay.pv` and `pqchat_protocol.pv`), preventing replay injection across the DHT, and verifies safe monotonic slot invalidation.
6. **Unlinkability & Tombstone Indistinguishability:** Proves observational equivalence (`diff-equivalence` in `pqchat_unlinkability.pv`) establishing that target addresses $\text{Target}_i = \text{SHA-1}(pk_i)$ reveal no identities (Metadata-Free Rendezvous), and 900-byte tombstones (CSPRNG noise) are indistinguishable from active messages or cover traffic.
7. **Group Messaging & Key Rotation (Group Protocol & PCS/FS):** Proves (`pqchat_group_protocol.pv`):
   * Secrecy of sender ratchet keys distributed in Type `0x06` frames (`TYPE_GROUP_CONTROL`) across 1-to-1 channels (ML-KEM-512 + X25519).
   * Authenticity of group messages with AAD binding ($\text{Target} \parallel GroupID \parallel SenderMemberID$).
   * Forward Secrecy of prior group messages prior to member departure.
   * Post-Compromise Security / Post-Leave Secrecy of messages in new epoch $groupEpoch + 1$ following departure (`GROUP_SUBTYPE_LEAVE`) and key rotation.

To run formal verification:
```bash
bash docs/formal/run_verification.sh
```

---

## 11. Testing Strategy

In accordance with project guidelines, tests are structured into two categories:

1. **Fast Unit Tests (Per-Commit):**
   * Executed via: `.\gradlew.bat testDebugUnitTest`
   * Completes in under two minutes, automatically skipping tests annotated with `@Tag("slow")`.
2. **Slow Integration & Statistical Tests (Nightly CI):**
   * Repository tests (`org.pqchat.dht.data.repository.*`), Monte Carlo statistical tests (`TrafficThreatModelStatisticalTest`), and loopback measurements (`LoopbackMeasurementHarnessTest`) are tagged with `@Tag("slow")`.
   * Executed in a dedicated GitHub Actions nightly workflow (`.github/workflows/nightly.yml`) at 02:00 UTC or on-demand locally:
     ```bash
     .\gradlew.bat testDebugUnitTest -DrunSlowTests=true
     # or
     .\gradlew.bat slowTest
     ```
