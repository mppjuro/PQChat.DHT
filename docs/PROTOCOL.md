# PQChat.DHT Protocol Specification (v2.0)

This document provides the complete technical specification of the **PQChat.DHT** communication protocol — a decentralized, post-quantum, asynchronous mobile messaging system for Android, leveraging the public BitTorrent Mainline DHT (BEP 44) as an ephemeral *Store-and-Forward* buffer.

---

## 1. System Architecture and Threat Model

### 1.1. Core Architectural Pillars
1. **Serverless & Zero Metadata:** Complete absence of centralized servers, push notification brokers (FCM/APNs), and static user identifiers or accounts.
2. **Client-Only Leaf Node Mode:** Mobile devices never route third-party KRPC packets and never buffer data for other nodes in RAM. They function exclusively as initiators of UDP `put` / `get` queries (BEP 44).
3. **Ephemeral DHT Buffer (Store-and-Forward):** Messages are stored as mutable BEP 44 records with a retention lifespan of 24–72 hours.
4. **Post-Quantum Cryptography (PQC):** Protection against *Harvest Now, Decrypt Later* attacks using the NIST-standardized **ML-KEM-512** algorithm (FIPS 203 / Kyber-512) paired with classical **X25519 ECDH** (RFC 7748) in a dual-defense hybrid model.
5. **Anti-Traffic Analysis:** Constant-Budget Stratified Polling and Poisson-distributed cover traffic with Weighted Fair Queueing (WFQ) to eliminate temporal and statistical correlation.

### 1.2. Cryptographic Assumptions & Security Model (Security Assumptions)

> [!IMPORTANT]
> **Assumption 1: Public Seed in QR Code ($Seed_{init}$ is Public)**
> The QR code or steganographic PNG8 image presented during out-of-band pairing (Handshake) contains:
> $$QR = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B}) \quad (\text{total } 864\text{ bytes})$$
> The protocol **does not assume confidentiality** of the QR code against physical observers (e.g., shoulder surfing or surveillance cameras).
> * $Seed_{init}$ is used exclusively for one-time deterministic derivation of the DHT rendezvous point:
>   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
>   as well as for transcript binding and collision avoidance.
> * Even if an adversary learns $pk_A$ and $Seed_{init}$, **they cannot decrypt messages or determine the shared secret**, because secrecy relies strictly on the hardness of ML-KEM-512 (Module Learning With Errors — M-LWE) and X25519 ECDH (Discrete Logarithm Problem).
> * Man-in-the-Middle attacks (tampering with DHT responses) are prevented by the **Key Confirmation Tag** and **Short Authentication String (SAS)**.

> [!WARNING]
> **Assumption 2: Ed25519 Signature in BEP 44 is Not Post-Quantum**
> The public BitTorrent DHT network (BEP 44 specification) requires each mutable record to be signed with Ed25519 public key $k$ ($32\text{ B}$) and signature ($64\text{ B}$).
> * In PQChat.DHT, the Ed25519 key is a **one-time, ephemeral transport token** derived from the current ratchet chain state ($EdSeed_i$).
> * Ed25519 **does not encrypt payloads and does not participate in shared secret negotiation**.
> * An adversary with access to a quantum computer (Shor's algorithm) could break the Ed25519 signature and overwrite the DHT record (Denial of Service or in-flight frame tampering), but **cannot break payload encryption (ML-KEM + AES-256-GCM)**. Any tampered frames are immediately discarded by the recipient due to AEAD tag verification failure.

---

## 2. Rendezvous Phase and Handshake

The pairing workflow consists of 3 steps: QR/steganographic image generation by Alice, processing and publishing by Bob, and retrieval and verification by Alice.

```
       Alice                                                  Bob
  (Displays QR/PNG8)                                     (Scans QR/PNG8)
         |                                                    |
  1. Generates (pk_A, sk_A)                                   |
     Seed_init <- CSPRNG(32)                                  |
     Target_0 = SHA-1(...)                                    |
     Presents QR / PNG8: pk_A || Seed_init                    |
         | ---------------- Scan QR / PNG8 (OOB) ------------>|
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

### 2.1. Step 1 (Alice): Initialization and QR / Steganography Presentation
1. Keypair Generation: $(pk_A, sk_A) \leftarrow \text{Hybrid-KEM.KeyGen}()$ (832 B public key: 800 B ML-KEM-512 + 32 B X25519).
2. Random Seed Generation: $Seed_{init} \leftarrow \text{CSPRNG}(32\text{ bytes})$.
3. Rendezvous Address Derivation ($Target_0$):
   $$HMAC_0 = \text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"})$$
   $$Target_0 = \text{SHA-1}(HMAC_0)$$
4. Payload Presentation (strict 864 bytes size):
   $$Payload_{raw} = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B})$$
   Presented either as a dense QR code or embedded into an innocent-looking 256-color PNG8 image via median-cut color quantization steganography.

### 2.2. Step 2 (Bob): Scanning, Encapsulation, and BEP 44 Publication
1. Unpacking: Extract $pk_A$ and $Seed_{init}$ from QR code or PNG8 stego image.
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
$$SAS = \text{format}(\text{"%04d-%04d"}, Part_1, Part_2)$$
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
  1. Generates fresh Hybrid KEM pair                          |
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
* **1-on-1 AAD (Additional Authenticated Data):**
  $$\text{AAD} = Target \ (20\text{ B}) \parallel Direction \ (\text{"AliceToBob" or "BobToAlice"})$$
* **Group AAD:**
  $$\text{AAD} = Target \ (20\text{ B}) \parallel GroupID \ (16\text{ B}) \parallel SenderMemberID \ (16\text{ B})$$
  AAD binding prevents reflection attacks, target slot swapping, and cross-group replay tampering.

### 7.3. Internal Plaintext Payload Header (13 bytes)
```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    MsgType    |            SeqNum             |    AckNum     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    (cont.)    |                                               |
+-+-+-+-+-+-+-+-+                 TimestampUTC                  |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
1. `MsgType` (1 B, UInt8): Message type identifier (`0x01`–`0x08`).
2. `SeqNum` (2 B, UInt16 Big-Endian): Sender monotonic sequence counter $Counter_{out}$.
3. `AckNum` (2 B, UInt16 Big-Endian): Last acknowledged recipient sequence number.
4. `TimestampUTC` (8 B, Int64 Big-Endian): Unix epoch transmission timestamp in milliseconds.

### 7.4. Complete Bit and Byte Specification for Types 0x01 to 0x08

Total available space after the 13-byte header is $872 - 13 = 859\text{ bytes}$.

#### Type 0x01: Handshake Online Finalize (`TYPE_HANDSHAKE_FINALIZE`)
```
+──────────────────────────┬──────────┬─────────────────┬──────────────+
|    Hybrid Ciphertext     |   Salt   | Key Confirm Tag | CSPRNG Noise |
|   800 bytes (768 + 32)   | 24 bytes |    32 bytes     |   3 bytes    |
+──────────────────────────┴──────────┴─────────────────┴──────────────+
```
* `Hybrid Ciphertext` (800 B): 768 B ML-KEM-512 ciphertext + 32 B ephemeral X25519 public key.
* `Salt` (24 B): Ephemeral salt for HKDF extraction.
* `Key Confirmation Tag` (32 B): HKDF expansion tag confirming transcript consistency.
* `CSPRNG Noise` (3 B): Random noise padding up to 859 bytes ($859 - 856 = 3\text{ B}$).

#### Type 0x02: Standard Text Message (`TYPE_TEXT_MESSAGE`)
```
+───────────────┬───────────────────────────────────────┬──────────────+
|  TextLength   |           UTF-8 Text Payload          | CSPRNG Noise |
| 2 bytes (BE)  |        L bytes (0 <= L <= 857)        | 857 - L bytes|
+───────────────┴───────────────────────────────────────┴──────────────+
```
* `TextLength` ($L$, 2 B, UInt16 Big-Endian): Length of UTF-8 encoded string ($L \le 857$).
* `UTF-8 Text Payload` ($L$ B): Message string content.
* `CSPRNG Noise` ($857 - L$ B): Pure cryptographic noise padding to exactly 859 bytes.

#### Type 0x03: PQC Rekey Offer (`TYPE_REKEY_OFFER`)
```
+───────────────┬───────────────────────────────────────┬──────────────+
|  RekeyEpoch   |          Combined Public Key          | CSPRNG Noise |
| 4 bytes (BE)  |         832 bytes (800 + 32)          |   23 bytes   |
+───────────────┴───────────────────────────────────────┴──────────────+
```
* `RekeyEpoch` (4 B, UInt32 Big-Endian): Target epoch index ($groupEpoch$ or ratchet epoch).
* `Combined Public Key` (832 B): 800 B ML-KEM-512 public key + 32 B X25519 public key.
* `CSPRNG Noise` (23 B): Padding to 859 bytes ($859 - 836 = 23\text{ B}$).

#### Type 0x04: PQC Rekey Response (`TYPE_REKEY_RESPONSE`)
```
+───────────────┬───────────────────────────────────────┬──────────────+
|  RekeyEpoch   |           Hybrid Ciphertext           | CSPRNG Noise |
| 4 bytes (BE)  |         800 bytes (768 + 32)          |   55 bytes   |
+───────────────┴───────────────────────────────────────┴──────────────+
```
* `RekeyEpoch` (4 B, UInt32 Big-Endian): Acknowledged epoch index.
* `Hybrid Ciphertext` (800 B): 768 B ML-KEM-512 encapsulation ciphertext + 32 B X25519 ephemeral public key.
* `CSPRNG Noise` (55 B): Padding to 859 bytes ($859 - 804 = 55\text{ B}$).

#### Type 0x05: Binary Chunk Transfer (`TYPE_CHUNK_TRANSFER`)
```
+──────────────┬────────────┬─────────────┬─────────────┬─────────────┬──────────────+
|  TransferID  | ChunkIndex | TotalChunks | ChunkLength | Binary Data | CSPRNG Noise |
|   16 bytes   | 2 bytes BE | 2 bytes BE  | 2 bytes BE  |   C bytes   | 837 - C bytes|
+──────────────┴────────────┴─────────────┴─────────────┴─────────────┴──────────────+
```
* `TransferID` (16 B): Unique Transfer UUID (Big-Endian).
* `ChunkIndex` (2 B, UInt16 Big-Endian): 0-based chunk sequence index.
* `TotalChunks` (2 B, UInt16 Big-Endian): Total chunk count in transfer ($TotalChunks \le 1000$).
* `ChunkLength` ($C$, 2 B, UInt16 Big-Endian): Byte size of this chunk ($C \le 837$).
* `Binary Data` ($C$ B): Raw chunk data (e.g. PNG8 image fragment).
* `CSPRNG Noise` ($837 - C$ B): Random noise padding up to 859 bytes.

#### Type 0x06: Group Control Frame (`TYPE_GROUP_CONTROL`)
```
+─────────┬──────────┬───────────┬──────────────┬──────────────────┬──────────────+
| SubType | GroupID  |GroupEpoch |SenderMemberID|SenderGroupChainKey|CurrentCounter|
| 1 byte  | 16 bytes |4 bytes BE |   16 bytes   |     64 bytes     |  4 bytes BE  |
+─────────┴──────────┴───────────┴──────────────┴──────────────────┴──────────────+
| GroupNameLen |    GroupName    | MemberCount |       Members Array ...         |
|  2 bytes BE  | N bytes (<= 64) | 2 bytes BE  | M * (16B + 1B + up to 32B UTF-8)|
+──────────────┴─────────────────┴─────────────┴─────────────────────────────────+
|                          CSPRNG Noise Padding                                  |
+────────────────────────────────────────────────────────────────────────────────+
```
* `ControlSubType` (1 B, UInt8):
  * `0x01` = `GROUP_SUBTYPE_INVITE`: Group invitation and roster.
  * `0x02` = `GROUP_SUBTYPE_REKEY`: Automatic or forced key rotation.
  * `0x03` = `GROUP_SUBTYPE_LEAVE`: Departure notice from leaving member.
* `GroupID` (16 B): Unique group UUID.
* `GroupEpoch` (4 B, UInt32 Big-Endian): Monotonic group key epoch.
* `SenderMemberID` (16 B): UUID of the sending member.
* `SenderGroupChainKey` (64 B): Current 64-byte sender ratchet chain state $myChainKeyOut$.
* `CurrentCounter` (4 B, UInt32 Big-Endian): Current transmission counter for this sender key.
* `GroupNameLength` ($N$, 2 B, UInt16 Big-Endian): Length of group name ($N \le 64$).
* `GroupName` ($N$ B): Group title in UTF-8.
* `MemberCount` ($M$, 2 B, UInt16 Big-Endian): Number of member descriptor records ($M \le 64$).
* `Members Array`: Serialized entries: `MemberID` (16 B) + `NameLen` (1 B) + `MemberName` ($K$ bytes UTF-8, $K \le 32$).
* `CSPRNG Noise Padding`: Padding to 859 bytes.

#### Type 0x07: Message Reaction (`TYPE_REACTION`)
```
+────────────────┬──────────────┬─────────────┬──────────────────┬──────────────+
| TargetSeqEpoch | TargetSeqNum | EmojiLength |   Emoji UTF-8    | CSPRNG Noise |
|   4 bytes BE   |  2 bytes BE  | 1 byte (E)  | E bytes (<= 64)  | 852 - E bytes|
+────────────────┴──────────────┴─────────────┴──────────────────┴──────────────+
```
* `TargetSeqEpoch` (4 B, UInt32 Big-Endian): Ratchet epoch of the message being reacted to.
* `TargetSeqNum` (2 B, UInt16 Big-Endian): Monotonic sequence counter $SeqNum$ of target message.
* `EmojiLength` ($E$, 1 B, UInt8): Length of UTF-8 emoji string ($1 \le E \le 64$).
* `Emoji UTF-8` ($E$ B): UTF-8 emoji characters (e.g. 👍, ❤️, 🔥).
* `CSPRNG Noise Padding` ($852 - E$ B): Random noise padding up to 859 bytes.

#### Type 0x08: Location Pin / Offline Safety Status (`TYPE_LOCATION_PIN`)
```
+──────────────┬───────────────┬──────────────┬──────────────┬──────────────┬──────────────+
|   Latitude   |   Longitude   |   Altitude   |   Accuracy   |  NoteLength  |     Note     |
| 8 bytes (D)  |  8 bytes (D)  | 8 bytes (D)  | 4 bytes (F)  |  2 bytes BE  |   P bytes    |
+──────────────┴───────────────┴──────────────┴──────────────┴──────────────┴──────────────+
| Optional Ephemeral: MAGIC_EPHEMERAL (8B) + EphemeralTtlSeconds (4B) | CSPRNG Noise   |
+─────────────────────────────────────────────────────────────────────┴────────────────+
```
* `Latitude` (8 B, Double IEEE 754 Big-Endian): Geographical latitude in decimal degrees.
* `Longitude` (8 B, Double IEEE 754 Big-Endian): Geographical longitude in decimal degrees.
* `Altitude` (8 B, Double IEEE 754 Big-Endian): Altitude in meters above WGS 84 ellipsoid.
* `Accuracy` (4 B, Float IEEE 754 Big-Endian): Horizontal accuracy radius in meters ($1\sigma$).
* `NoteLength` ($P$, 2 B, UInt16 Big-Endian): Length of text note ($P \le 829$ standard, or $P \le 817$ with ephemeral header).
* `Note` ($P$ B): Status or location annotation in UTF-8.
* `Optional Ephemeral Header` (12 bytes total, present only when $TTL > 0$):
  * `MAGIC_EPHEMERAL` (8 B, UInt64 Big-Endian): Constant `0x5051435F4550484DL` ("PQC_EPHM").
  * `EphemeralTtlSeconds` (4 B, UInt32 Big-Endian): Expiration time-to-live in seconds.
* `CSPRNG Noise Padding`: Padding to 859 bytes ($829 - P$ or $817 - P$ bytes).

---

## 8. Local Database Encryption with Row-Bound Context (`MAGIC_ROW_BOUND_V2`) and Duress PIN

### 8.1. Threat: Row/Column Swap Attacks in SQLite Databases
In standard AES-GCM database column encryption, an adversary with root access, forensic extraction tools, or physical storage dumps could extract an encrypted blob from one row/column (e.g. an admin message or key) and write it into another row/column. Because both records use the same master key, decryption would succeed without error, leading to state corruption, privilege escalation, or message spoofing.

### 8.2. Wire Format of `MAGIC_ROW_BOUND_V2`
PQChat.DHT implements V2 row-bound encryption (`MAGIC_ROW_BOUND_V2 = 0x52`, ASCII `'R'`) where the Additional Authenticated Data (AAD) cryptographically seals the database location:
$$\text{AAD} = \text{table} \parallel \text{"+"} \parallel \text{id} \parallel \text{"+"} \parallel \text{column}$$

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Magic (0x52)  |   tableLen    |          tableName ...        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    idLen (2 bytes BE)         |             rowId ...         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   columnLen   |          columnName ...                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       IV / Nonce (12 bytes)                   |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Ciphertext + AEAD Tag (16 bytes) ...         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
If an adversary moves or swaps an encrypted blob to any other row, column, or table, decryption fails immediately with `AEADBadTagException`, proven formally in ProVerif Model 8 (`pqchat_duress_wipe.pv`, Lemma 8.4).

### 8.3. Duress PIN Mechanism (`KeystoreCrypto.deleteMasterKey`) and Decoy Mode
Under physical coercion or compelled unlock:
1. The user enters a preconfigured **Duress PIN** (distinguished from the legitimate Unlock PIN).
2. The authentication engine triggers an immediate hardware key wipe:
   * Calls `KeystoreCrypto.deleteMasterKey()`, deleting the master wrapping key from the hardware-backed Android Keystore (StrongBox / TEE).
   * Irreversibly purges cached keys and session tokens in RAM (`fill(0)`).
   * Clears sensitive SharedPreferences flags.
3. The app opens `DecoyNotesScreen`, presenting a realistic, functioning personal notes notepad.
4. Because the hardware master key is permanently erased from the TEE, the SQLite database becomes mathematically unrecoverable.

---

## 9. PNG8 Handshake Steganography Algorithm (`Png8Compressor.kt`)

To circumvent visual inspection, automated QR scanner surveillance, and censorship checkpoints, PQChat.DHT provides an out-of-band pairing mechanism disguised as ordinary PNG images.

### 9.1. Steganography Envelope Structure
The 864-byte pairing payload ($pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B})$) is encapsulated into an 874-byte binary envelope:
```
+──────────────────────────┬──────────────┬──────────────────┬──────────────+
|   STEG_MAGIC ("PQST")    |  PayloadLen  |  Pairing Payload |  CRC32 Check |
|   4 bytes (0x50515354)   |  2 bytes BE  |    864 bytes     |  4 bytes BE  |
+──────────────────────────┴──────────────┴──────────────────┴──────────────+
```
* `STEG_MAGIC` (4 B): Magic prefix `0x50, 0x51, 0x53, 0x54` ("PQST").
* `PayloadLen` (2 B, UInt16 Big-Endian): Payload length (constant `864`).
* `Pairing Payload` (864 B): $pk_A \parallel Seed_{init}$.
* `CRC32 Check` (4 B, UInt32 Big-Endian): IEEE 802.3 CRC32 checksum for payload integrity verification.

### 9.2. Median Cut Color Quantization & Indexed LSB Embedding
1. **Median Cut Quantization:**
   The source image is partitioned in RGB color space along the color axis with greatest variance until 256 representative palette clusters are created (PNG8 Indexed Color mode).
2. **Payload Embedding:**
   * The 874-byte envelope bitstream is embedded into the least significant bits (LSB) of the palette color entries or indexed pixel stream.
   * Palette colors are perturbed by at most $\pm 1$ per channel, rendering visual differences invisible to human inspection and statistical image tests.
3. **Extraction & Verification:**
   * `Png8Compressor.extractPayload` reads the indexed stream, validates `STEG_MAGIC` and `CRC32`.
   * If the image has been recompressed or altered, the CRC32 check fails gracefully, allowing the app to fall back to QR code scanning.

---

## 10. Constant-Budget Stratified Polling and Weighted Fair Queueing (WFQ)

### 10.1. Constant-Budget Stratified Polling ($N_{\text{poll}} = 8$)
Variable query frequencies in DHT polling leak the number of active contacts and conversations to network observers. PQChat.DHT enforces **Constant-Budget Stratified Polling**:
* Every polling tick queries **exactly 8 target addresses** (`N_POLL_TARGETS = 8`).
* **Stratified Sampling when Targets $> 8$:**
  Active slots are partitioned into stratified priority tiers (`FOREGROUND_CHAT` contacts, lookahead window slots, background idle contacts). Target selection employs Weighted Fair Sampling based on contact activity timestamps.
* **Decoy Target Padding when Targets $< 8$:**
  If the client has fewer than 8 active targets (e.g. only 2 active contacts), the remaining $8 - K$ queries are drawn from `DecoyTargetPool`. These decoys query valid, live DHT addresses generated by Poisson dummy writes, preventing 0-PUT statistical filtering.
* **Anonymity Guarantee:** An observer monitoring the smartphone's UDP emission sees a completely invariant rate of 8 queries per interval, leaking zero information about contact count or chat activity.

### 10.2. Outbound Poisson WFQ Queue (`OutboundPoissonQueue`)
All outbound DHT packets (direct messages, group broadcasts, chunk transfers, acknowledgments, and cover noise) pass through an 8-slot cyclic Weighted Fair Queueing scheduler:
```
Slot:     [ 0 ]     [ 1 ]     [ 2 ]     [ 3 ]     [ 4 ]     [ 5 ]     [ 6 ]     [ 7 ]
Class:   DIRECT    GROUP     DIRECT    GROUP     DIRECT    IMAGE     DIRECT    COVER
Ratio:    50%       25%       50%       25%       50%      12.5%      50%      12.5%
```
* **Traffic Classes:**
  1. `DIRECT` (Priority 4): 1-on-1 text messages, handshake finalize frames, rekey packets.
  2. `GROUP` (Priority 3): Group chat messages and member control frames.
  3. `IMAGE` (Priority 2): PNG8 media chunk packets.
  4. `ACK` (Priority 1): Symmetrically encrypted cover acknowledgments.
  5. `COVER` (Priority 0): CSPRNG Poisson dummy traffic.
* **Anti-Starvation Guarantee:** Even under heavy user texting or image uploads, the `COVER` traffic slot executes every 8th cycle, maintaining continuous Poisson background traffic and preventing metadata leakage.

---

## 11. Formal Security Verification (docs/formal/)

All fundamental protocol security guarantees have been symbolically verified using **ProVerif 2.05** under `docs/formal/` (32 lemmas across 8 models):

| Security Property | Model File | Verified Cryptographic Guarantees | ProVerif Outcome |
| :--- | :--- | :--- | :--- |
| **Unified Protocol** | `pqchat_protocol.pv` | MasterKey, tracks $A \to B$ and $B \to A$, AAD payloads, SAS transcript, micro-payloads (`0x07`, `0x08`), and anti-replay | `RESULT: True` (12/12) |
| **Secrecy and Confirmation** | `pqchat_secrecy.pv` | Payload confidentiality and injective authentication in Hybrid KEM (ML-KEM-512 + X25519) | `RESULT: True` (5/5) |
| **Forward Secrecy (FS)** | `pqchat_forward_secrecy.pv` | Past message protection upon chain state compromise in RAM | `RESULT: True` (2/2) |
| **Self-Healing (PCS)** | `pqchat_post_compromise.pv` | Secrecy restoration after key compromise via asymmetric KEM rotation | `RESULT: True` (2/2) |
| **Anti-Replay Protection** | `pqchat_replay.pv` | Injective packet acceptance and monotonic slot invalidation via tombstones | `RESULT: True` (2/2) |
| **Unlinkability & Tombstones** | `pqchat_unlinkability.pv` | Observational equivalence of target addresses and indistinguishability of 900-byte tombstones | `RESULT: True` (1/1) |
| **Group Protocol and PCS/FS** | `pqchat_group_protocol.pv` | Sender key distribution, AAD binding, and group PCS/FS on member leave | `RESULT: True` (4/4) |
| **Duress Wipe & Row-Bound V2**| `pqchat_duress_wipe.pv` | Hardware master key erasure irreversibility, decoy screen activation, and SQLite row/column swap resistance (`MAGIC_ROW_BOUND_V2`) | `RESULT: True` (4/4) |

To run the automated formal verification suite:
```bash
bash docs/formal/run_verification.sh
```

---

## 12. Testing Strategy

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
