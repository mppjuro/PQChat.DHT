# AGENTS.md — Architectural and Implementation Guidelines for AI Agents

This file defines the technical specification, cryptographic model, code architecture, and implementation rules for the decentralized, post-quantum mobile messenger on Android. Every AI agent working in this repository is strictly required to adhere to the guidelines below.

---

## 1. Project Overview and Architectural Philosophy

The project is a fully decentralized (serverless), censorship-resistant, metadata-protecting mobile messenger for Android, utilizing the public **BitTorrent Mainline DHT (BEP 44)** as an ephemeral store-and-forward buffer for 24–72 hours.

### Core Pillars:
1. **Zero Centralization:** No intermediary servers, no push notification brokers (no FCM/APNs), and no static IP addresses or user accounts.
2. **Metadata Protection (Metadata-Free Rendezvous):** Network observers and DHT nodes cannot link sender to recipient, determine that a conversation is taking place, or measure message exchange frequency.
3. **Post-Quantum Cryptography (PQC):** Protection against *Harvest Now, Decrypt Later* attacks using NIST-standardized algorithms (FIPS 203).
4. **Leaf Node Mode (Client-Only / Leaf Node):** The smartphone never routes third-party traffic or stores other users' data in RAM; it acts strictly as an ephemeral UDP query initiator.

---

## 2. Technology Stack

* **Primary & Exclusive Language:** Kotlin (100% application code, DHT KRPC UDP networking, Bencode, cryptography, UI, and background services — no C++/JNI layer).
* **UI Framework:** Jetpack Compose + Material 3.
* **Database:** Room (SQLite) with sensitive fields encrypted using keys backed by Android Keystore and row-level AAD binding.
* **Concurrency:** Kotlin Coroutines (`Dispatchers.IO`, `Dispatchers.Default`) + Flow.
* **Background Work:** AndroidX WorkManager (periodic tasks) + Foreground Service (for active chat) + AlarmManager (`setAndAllowWhileIdle` for Doze mode).
* **Cryptographic Library:** Bouncy Castle Java/Kotlin PQC Provider (`org.bouncycastle:bcprov-jdk18on`) + native Android `javax.crypto` API (for AES-GCM).

---

## 3. Cryptographic Specification

| Component | Standard / Algorithm | Purpose |
| :--- | :--- | :--- |
| **KEM (Handshake & Rekey)** | Hybrid X25519 + ML-KEM-512 (FIPS 203 + RFC 7748) | Asymmetric shared secret agreement ($pk = 832\text{ B}$, $ct = 800\text{ B}$, $SS = 32\text{ B}$) |
| **Payload Encryption (AEAD)** | AES-256-GCM | Symmetric message encryption (Key: 32 B, IV: 12 B, Tag: 16 B) |
| **Key Derivation (KDF)** | HKDF-SHA512 (RFC 5869) | Derivation of ratchet chains, slot seeds, and AES keys |
| **DHT Transport Requirement** | Ed25519 (RFC 8032) | Required by BEP 44 node signature (used strictly as an **ephemeral one-time token**) |
| **Database Encryption (Row Binding)** | AES-256-GCM (`MAGIC_ROW_BOUND_V2` = `0x52`) | Hardware Keystore master key; AAD bound to `table+id+column` |
| **Handshake Steganography** | PNG8 indexed palette steganography | In-flight encoding of QR key material (`STEG_MAGIC = "PQST"`, CRC32) |

### Deterministic Dual Unidirectional Chains:
Each contact maintains two independent chains governed by separate monotonic counters:
* **Track $A \to B$:** Alice increments $Counter_{out}$, Bob increments $Counter_{in}$.
* **Track $B \to A$:** Bob increments $Counter_{out}$, Alice increments $Counter_{in}$.

Sending a message on one track **never** impacts the counter sequence or addressing of the opposite track.

### SQLite Database Encryption with `MAGIC_ROW_BOUND_V2` (`0x52`):
To protect against Row/Column Swap attacks in SQLite without native C++ libraries:
* **Magic Identifier:** `MAGIC_ROW_BOUND_V2 = 0x52` (ASCII `'R'`).
* **Wire Format:**
  `[MAGIC 1B (0x52)] + [tableLen 1B] + [table] + [idLen 2B BE] + [id] + [colLen 1B] + [col] + [IV 12B] + [Ciphertext + Tag 16B]`
* **AAD Binding:**
  `AAD = table + "+" + id + "+" + column`
* Swapping encrypted blobs between rows or between columns within the same row causes an immediate AEAD authentication tag verification failure (`AEADBadTagException`), preventing cipher tampering.

### Physical Coercion & Duress PIN Mechanism:
* **Duress PIN (`KeystoreCrypto.deleteMasterKey`):** Entering an emergency PIN triggers an irreversible purge of the hardware Android Keystore master key (Titan M / StrongBox / TEE) and wipes in-memory caches (`MasterKeyHolder.clear()`).
* **Plausible Deniability:** Database contents immediately become permanent cryptographic noise ($P_{\text{recover}} < 2^{-256}$). The UI seamlessly transitions to `DecoyNotesScreen`, displaying a plausible, benign personal notes application.

### PNG8 Handshake Steganography (`Png8Compressor.kt`):
* Handshake exchange material can be embedded into indexed 8-bit PNG images.
* **Envelope Format:**
  `[STEG_MAGIC 4B ("PQST" = 0x50 0x51 0x53 0x54)] + [PayloadLength 2B (864)] + [Payload 864B (pk || Seed_init)] + [CRC32 4B]` (total 874 bytes embedded).

---

## 4. Binary DHT Record Specification (BEP 44 Value)

Every binary payload ('v') stored on the DHT has a **rigid size of exactly 900 bytes** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES = 900`). Any unused trailing bytes are padded with cryptographically secure pseudo-random noise (`CryptoUtils.secureRandomBytes`).

### Rationale for 900 B Size and BEP 44 Compliance:
Under the BitTorrent BEP 44 specification, the total size of the value field `'v'` after Bencode encoding **must not exceed 1000 bytes**:
* Bencode encodes a byte string as `<length>:<data>`.
* For a 900-byte raw payload, the encoded string is `"900:"` (4-byte prefix) + 900 bytes of data = **exactly 904 bytes**, satisfying the rigid BEP 44 limit ($\le 1000\text{ B}$).
* **Critical Note:** If the raw payload were 1000 bytes, its Bencode-encoded representation would be `"1000:"` (5-byte prefix) + 1000 bytes of data = **1005 bytes**, which **exceeds the BEP 44 limit** and triggers immediate rejection by public BitTorrent DHT nodes!

```
+───────────────────────────────────────────────────────────────────────────────+
|                    BEP 44 VALUE RECORD (EXACTLY 900 BYTES)                    |
+────────────┬─────────────┬────────────────────────────────────────────────────+
| IV (Nonce) |  AEAD Tag   |                ENCRYPTED PAYLOAD                   |
|  12 bytes  |  16 bytes   |                    872 bytes                       |
+────────────┴─────────────┴──────────────────┬──────────────────┬──────────────+
                           |  Header (13 B)   |   Type Payload   | CSPRNG Noise |
                           +──────────────────┴──────────────────┴──────────────+
```

### Internal Plaintext Header (13 bytes):
1. `MsgType` (1 byte):
   * `0x01` – Handshake Online Finalize
   * `0x02` – Standard Text Message
   * `0x03` – PQC Rekey Offer (New public key)
   * `0x04` – PQC Rekey Response (Confirmation ciphertext)
   * `0x05` – Binary Chunk Transfer (e.g., PNG image)
   * `0x06` – Group Control (`TYPE_GROUP_CONTROL`: Invite, Rekey, Leave)
   * `0x07` – Message Reaction (`TYPE_REACTION`: emoji linked to target message)
   * `0x08` – Location Pin / Offline Safety Status (`TYPE_LOCATION_PIN`)
   * `0x09` – Push-To-Talk Micro-Voice Note (`TYPE_VOICE_NOTE`)
2. `SeqNum` (2 bytes, UInt16 Big-Endian): Sender's $Counter_{out}$.
3. `AckNum` (2 bytes, UInt16 Big-Endian): Highest received sequence number from partner.
4. `TimestampUTC` (8 bytes, Int64 Big-Endian): Unix timestamp of transmission in milliseconds.

### Dedicated Internal Formats (859-byte space after 872 - 13 header):

* **Type 0x01 (Handshake Finalize):**
  * `Hybrid Ciphertext`: 800 bytes (768 B ML-KEM-512 ct + 32 B X25519 eph pk)
  * `Salt`: 24 bytes
  * `Key Confirmation Tag`: 32 bytes
  * `CSPRNG Padding`: 3 bytes (859 - 856)
* **Type 0x02 (Text Message):**
  * `TextLength` ($L$): 2 bytes (UInt16, value $\le 857$)
  * `UTF-8 Payload`: $L$ bytes (maximum 857 text bytes)
  * `CSPRNG Padding`: $857 - L$ bytes
* **Type 0x03 (PQC Rekey Offer):**
  * `RekeyEpoch`: 4 bytes (UInt32 Big-Endian)
  * `Combined PublicKey`: 832 bytes (800 B ML-KEM-512 + 32 B X25519)
  * `CSPRNG Padding`: 23 bytes (859 - 836)
* **Type 0x04 (PQC Rekey Response):**
  * `RekeyEpoch`: 4 bytes (UInt32 Big-Endian)
  * `Hybrid Ciphertext`: 800 bytes (768 B ML-KEM-512 ct + 32 B X25519)
  * `CSPRNG Padding`: 55 bytes (859 - 804)
* **Type 0x05 (Chunk Transfer – e.g. PNG):**
  * `TransferID`: 16 bytes (Transfer UUID)
  * `ChunkIndex`: 2 bytes (UInt16)
  * `TotalChunks`: 2 bytes (UInt16)
  * `ChunkLength` ($C$): 2 bytes (UInt16, value $\le 837$)
  * `BinaryData`: $C$ bytes
  * `CSPRNG Padding`: $837 - C$ bytes
* **Type 0x06 (Group Control Frame):**
  * `ControlSubType`: 1 byte (`0x01` – `GROUP_SUBTYPE_INVITE`, `0x02` – `GROUP_SUBTYPE_REKEY`, `0x03` – `GROUP_SUBTYPE_LEAVE`)
  * `GroupID`: 16 bytes (Group UUID)
  * `GroupEpoch`: 4 bytes (UInt32 Big-Endian)
  * `SenderMemberID`: 16 bytes (Sender UUID within group)
  * `SenderGroupChainKey`: 64 bytes (Current group sender chain)
  * `CurrentCounter`: 4 bytes (UInt32 Big-Endian)
  * `GroupNameLength` ($N$): 2 bytes (UInt16, value $\le 64$)
  * `GroupName`: $N$ bytes UTF-8 (maximum 64 bytes)
  * `MemberCount` ($M$): 2 bytes (UInt16, count of participants, value $\le 64$)
  * `Members`: array of $M$ entries: `MemberID` (16 B) + `NameLen` (1 B) + `MemberName` (up to 32 B UTF-8)
  * `CSPRNG Padding`: padding to 859 bytes.
* **Type 0x07 (Reaction):**
  * `TargetSeqEpoch`: 4 bytes (UInt32 Big-Endian)
  * `TargetSeqNum`: 2 bytes (UInt16 Big-Endian)
  * `EmojiLength` ($E$): 1 byte (UInt8, value $\le 64$)
  * `Emoji`: $E$ bytes UTF-8 (maximum 64 bytes)
  * `CSPRNG Padding`: $852 - E$ bytes (padding to 859 B)
* **Type 0x08 (Location Pin / Offline Safety Status):**
  * `Latitude`: 8 bytes (Double IEEE 754 Big-Endian)
  * `Longitude`: 8 bytes (Double IEEE 754 Big-Endian)
  * `Altitude`: 8 bytes (Double IEEE 754 Big-Endian)
  * `Accuracy`: 4 bytes (Float IEEE 754 Big-Endian)
  * `NoteLength` ($P$): 2 bytes (UInt16 Big-Endian, value $\le 829$, or $\le 817$ for ephemeral messages)
  * `Note`: $P$ bytes UTF-8 (maximum 829 bytes, or $\le 817$)
  * `Optional Ephemeral Header`: `MAGIC_EPHEMERAL` (8 bytes, `0x5051435F4550484DL`) + `EphemeralTtlSeconds` (4 bytes, UInt32 Big-Endian) – present only when $TTL > 0$
  * `CSPRNG Padding`: padding to 859 B ($829 - P$ or $817 - P$ bytes)
* **Type 0x09 (Ultra-Low-Bitrate Micro-Voice Note):**
  * `VoiceClipId`: 8 bytes (Int64 Big-Endian, UUID/clip identifier)
  * `SegmentIndex`: 1 byte (UInt8, value $0..2$)
  * `TotalSegments`: 1 byte (UInt8, value $1..3$)
  * `DurationMs`: 2 bytes (UInt16 Big-Endian, segment duration in ms)
  * `CodecMode`: 1 byte (`0x01` – `CODEC_MODE_LPC10_COMPACT`, 8 kHz mono, 1280 bps / 160 B/s)
  * `EphemeralTtlSeconds`: 4 bytes (UInt32 Big-Endian)
  * `CompressedVoiceBytesLength` ($V$): 2 bytes (UInt16 Big-Endian, value $\le 840$)
  * `Compressed Voice Stream`: $V$ bytes (up to 840 bytes, ~5.25s per frame, maximum 2520 bytes across 3 frames = ~15.75s)
  * `CSPRNG Padding`: padding to 859 B ($840 - V$ bytes)

### Group Chats and Database Tables (`groups` and `group_members`):
* **Distribution and Addressing Model:** Each participant maintains their own outbound chain ($myChainKeyOut$). Group messages are transmitted to individual recipient slots:
  $$\text{Target}_{slot} = \text{RatchetChain.deriveGroupRecipientSlot}(ChainKey, Counter, GroupID, SenderMemberID, RecipientMemberID)$$
  which completely eliminates observer correlation (Group Follower Correlation).
* **AAD Binding:** AEAD AES-256-GCM encryption of group payloads strictly binds the context:
  $$\text{AAD} = \text{Target} \parallel GroupID \parallel SenderMemberID$$
  preventing any tampering with sender, group, or destination slot.
* **Automatic Sender Key Rotation:** Occurs automatically every 50 sent group messages (`GROUP_REKEY_MESSAGE_INTERVAL = 50`), generating a fresh 64-byte CSPRNG key, advancing to $groupEpoch + 1$, resetting counter to 0, and transmitting Type `0x06` frame (`GROUP_SUBTYPE_REKEY`) to all active members.
* **Forced Key Rotation on Member Leave (Forward Secrecy & PCS):** Upon receiving a `GROUP_SUBTYPE_LEAVE` frame from any member, the leaving participant is immediately marked inactive (`isActive = 0`), the local $myChainKeyOut$ is rotated to $groupEpoch + 1$, and a `GROUP_SUBTYPE_REKEY` frame is broadcast strictly to remaining active members. This isolates the departed member from all future messages (Post-Compromise Security / Post-Leave Secrecy) while protecting past conversations (Forward Secrecy).
* **`groups` Table:**
  * `groupId` (TEXT, PRIMARY KEY, UUID), `groupName` (TEXT), `myMemberId` (TEXT, UUID)
  * `myChainKeyOut` (BLOB, `EncryptedBlob` bound to row in Keystore), `myCounterOut` (INTEGER), `groupEpoch` (INTEGER)
  * `createdAt` (INTEGER), `lastActive` (INTEGER), `isActive` (INTEGER, BOOLEAN)
* **`group_members` Table:**
  * `groupId` (TEXT), `memberId` (TEXT), PRIMARY KEY (`groupId`, `memberId`)
  * `contactId` (TEXT, NULLABLE — foreign key to 1-on-1 contact), `memberName` (TEXT)
  * `chainKeyIn` (BLOB, `EncryptedBlob` bound to row in Keystore), `counterIn` (INTEGER)
  * `joinedAt` (INTEGER), `isActive` (INTEGER, BOOLEAN)
  * `receivedBitmapBase` (INTEGER), `receivedBitmap` (BLOB — sliding bitmap for replay protection)

### Additional Fixed 900 B Record Types:
* **Cover-Traffic ACK:** Symmetrically encrypted acknowledgment packet concealed in noise at $\text{Target}_{ACK}$, with rigid 900-byte size (`CoverAckProtocol`).
* **Cover Traffic Dummy:** Uncoordinated 900-byte record filled with pure CSPRNG noise (`DhtLeafNode.sendCoverTrafficDummy`).
* **Secure Tombstone (Slot Wipe Upon Receipt):** Overwrites consumed message slots with a record of rigid 900 bytes of pure CSPRNG noise at `seq = DEFAULT_MUTABLE_SEQ + 1` (`BinaryFrameCodec.createTombstonePayload`). This replaces vulnerable 0-byte tombstone variants that leaked delivery timing to DHT nodes and eavesdroppers. Because the size remains exactly 900 B (904 B in Bencode), the tombstone is completely indistinguishable from normal writes or cover traffic.

---

## 5. Workflows

### A. Handshake (QR Scan / PNG8 Stego + Online Finalize):
1. **Alice (QR/Stego):** Generates hybrid X25519 + ML-KEM-512 keypair $(pk_A, sk_A)$ and random $Seed_{init}$ (32 B). Displays QR code encoding $pk_A \parallel Seed_{init}$ (total 864 bytes) or exports a PNG8 image with steganographic embedding (`STEG_MAGIC = "PQST"`).
2. **Bob (Scan & Put):** Scans code / extracts PNG8 payload, executes $\text{Encapsulate}(pk_A) \to (SS_{init}, ct_B)$ (where $ct_B$ is 800 B: 768 B ML-KEM-512 ct + 32 B X25519 eph pk). Derives rendezvous target:
   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
   Sends Type `0x01` packet to $\text{Target}_0$ via an ephemeral BEP 44 record (900 B).
3. **Alice (Get & Derive):** Polls DHT for $\text{Target}_0$. Upon retrieval, decrypts packet, executes $\text{Decapsulate}(sk_A, ct_B)$ to recover $SS_{init}$.
4. **State Derivation:** Both parties derive:
   * $ChainKey_{A \to B} = \text{HKDF-Expand}(SS_{init}, \text{"AliceToBob"}, 64)$
   * $ChainKey_{B \to A} = \text{HKDF-Expand}(SS_{init}, \text{"BobToAlice"}, 64)$
   * Initialize counters $Counter = 0$.

### B. Address Hopping (Key Hopping):
For each message $i$:
1. $\text{Entropy}_i = \text{HKDF-Expand}(ChainKey^i, \text{"step"} \parallel i, 128)$.
2. Bytes 0–31: $MsgKey_i$ (AES-256 key).
3. Bytes 32–63: $EdSeed_i$ (seed for one-time Ed25519 keypair $pk_i, sk_i$).
4. Bytes 64–127: $ChainKey^{i+1}$.
5. Destination Address: $\text{Target}_i = \text{SHA-1}(pk_i)$.

### C. PQC Rotation (Re-keying Every 50 Messages):
* When $Counter_{out} \equiv 0 \pmod{50}$ and $Counter_{out} > 0$:
  * Sender includes a new ephemeral hybrid X25519 + ML-KEM-512 public key (832 B) in a Type `0x03` packet.
  * Recipient responds on their outbound channel with a hybrid KEM ciphertext (800 B) in a Type `0x04` packet.
  * Upon processing both sides, the new secret $SS_{rekey}$ is injected into the master chain:
    $$ChainKey \leftarrow \text{HKDF-Extract}(ChainKey, SS_{rekey})$$

---

## 6. Polling Cycles and Anti-Traffic Analysis

### Adaptive Polling Schedule:
1. **10 seconds:** Active chat window with specific contact (`FOREGROUND_CHAT` — screen on, app in foreground, conversation selected).
2. **1 minute:** App open in foreground (`APP_ACTIVE_OTHER` — screen on, contacts list, diagnostics, or settings).
3. **5 minutes:** Device in use (`BACKGROUND_IDLE` — screen on, but app in background / minimized).
4. **15 minutes:** Device locked / sleeping (`DOZE_SLEEP` — screen off; handled by `WorkManager` and `AlarmManager.setAndAllowWhileIdle`).

Detailed state machine model, Android 12+ Cached App Freezer (CAF) handling, Android 15 `dataSync` FGS limits (targetSdk 35), and `BOOT_COMPLETED` flow are documented in [docs/android_lifecycle_background_execution.md](docs/android_lifecycle_background_execution.md).

### Consistent Lifecycle Transitions (PollingLifecycleCoordinator):
Transitions between the 4 polling states are centrally managed by `PollingLifecycleCoordinator`:
* Utilizes `ProcessLifecycleOwner` (tracking foreground/background status independent of activity recreation or rotation).
* Detects physical screen state via dynamic `ScreenStateReceiver` (`ACTION_SCREEN_ON`, `ACTION_SCREEN_OFF`) and `PowerManager.isInteractive`.
* Activity `ON_STOP` **is never treated as screen off**; minimizing the app while screen is active leads to `BACKGROUND_IDLE` (5 min), not `DOZE_SLEEP`.

### Constant-Budget Stratified Polling ($N_{\text{poll}} = 8$):
* To prevent eavesdroppers from deducing the number of contacts or active conversations from query volume, every polling cycle queries a fixed budget:
  $$N_{\text{poll}} = \text{N\_POLL\_TARGETS} = 8$$
* **Stratified Sampling:** When active tracks exceed 8, targets are selected via Weighted Fair Stratified Sampling prioritizing currently active conversations.
* **Decoy Padding:** When active tracks are fewer than 8, remaining slots are padded with realistic decoy addresses from `DecoyTargetPool`.

### Weighted Fair Queuing (WFQ) Outbound Poisson Traffic (`OutboundPoissonQueue`):
* Poisson cover traffic and outbound frames are shaped using a 5-class Weighted Fair Queue (`OutboundPoissonQueue`):
  1. `DIRECT_TEXT` (Priority 1)
  2. `DIRECT_ACK` (Priority 2)
  3. `GROUP_TEXT` (Priority 3)
  4. `IMAGE_CHUNK` (Priority 4)
  5. `COVER_DUMMY` (Priority 5)
* **Scheduling Frame (8 Slots):**
  `[DIRECT, GROUP, DIRECT, GROUP, DIRECT, IMAGE, DIRECT, COVER]`
  guaranteeing 50% bandwidth for direct messages, 25% for group messages, 12.5% for image transfers, and 12.5% for continuous background cover traffic.
* **Poisson Intervals:** Delay to next write follows exponential distribution:
  $$\Delta t = -\frac{1}{\lambda} \ln(U), \quad U \sim \mathcal{U}(0, 1)$$

---

## 7. Project Module Structure

The project code is organized 100% in Kotlin:

```
app/src/main/java/org/pqchat/dht/
├── crypto/              # PqcEngine, MLKemEngine, AesGcmEngine, BinaryFrameCodec, Ed25519Engine, RatchetChain
├── data/
│   ├── db/              # Room Database (AppDatabase, DAOs, Encrypted Entities)
│   ├── repository/      # ChatRepository, MessageChunker
│   └── settings/        # AppSettingsManager (SharedPreferences & DataStore)
├── dht/
│   ├── bencode/         # Efficient Kotlin Bencode decoder/encoder
│   ├── krpc/            # KRPC DHT UDP socket management
│   └── leaf/            # DhtLeafNode (Leaf-mode BEP 44 put/get client)
├── media/               # Png8Compressor, image transfer optimization
├── network/
│   └── tor/             # Embedded Tor and SOCKS5 proxy support
├── protocol/            # ProtocolEngine, CoverAckProtocol (acknowledgments in noise)
├── research/            # ResearchTelemetryManager, FirebaseResearchSync, HistoricalTtlSampler
├── service/             # PollingScheduler, PollingLifecycleCoordinator, ScreenStateReceiver, BootReceiver, DhtAlarmReceiver, ChatHeadService
├── traffic/             # AdaptivePollingManager, PoissonTrafficGenerator, OutboundPoissonQueue, DecoyTargetPool, PollingWorker
└── ui/
    ├── screens/         # ChatScreen, ContactsScreen, DiagnosticsScreen, SettingsScreen, DecoyNotesScreen
    ├── components/      # Reusable Compose UI components
    └── theme/           # Material 3 Design Tokens, Color Scheme, Typography
```

---

## 8. Implementation Guidelines and Constraints for AI Agents

1. **Memory Safety and Key Zeroization:**
   * After completing cryptographic operations on ephemeral keys, `ByteArray` instances must be immediately zeroed (`array.fill(0)`).
   * Plaintext data, private keys, seeds, and decrypted payloads must never be logged (`Log.d`, `println`).
   * Before every commit, verify that no credentials or private API keys are committed.
2. **Network Error Handling:**
   * DHT `get` operations are asynchronous and can time out. A timeout is not a fatal error — it simply indicates no new message or a need to retry in the next polling window.
3. **Replay and Collision Resistance:**
   * Messages with sequence numbers lower than the current $Counter_{in}$ state must be immediately dropped.
   * Any record with an invalid AEAD tag (`AEADBadTagException`) or mismatched Ed25519 signature is strictly dropped and purged.
4. **Clean Code:**
   * Prefer immutable data structures (`data class`).
   * Maintain full unit test coverage for cryptographic modules (`KdfChainTest`, `PqcEngineTest`, `ChunkingTest`, `CryptoEngineTest`).
5. **Testing Strategy and Repository Workflow:**
   * **Fast Unit Tests (Per Commit):** Before every commit, execute fast unit tests: `.\gradlew.bat testDebugUnitTest`. These skip long-running scenarios (`@Tag("slow")`) and finish in under 2 minutes. If tests exceed 5 minutes, inspect logs and decide whether the implementation has an issue or the test should be categorized as `@Tag("slow")` for nightly CI. Never wait more than 10 minutes without acting. Fast unit tests must pass before pushing commits.
   * **Slow Tests:** Repository integration tests (`org.pqchat.dht.data.repository.*`), Monte Carlo statistical tests, and loopback simulations are annotated with `@Tag("slow")`. They run automatically in nightly GitHub Workflows (`.github/workflows/nightly.yml`) and locally on demand via `.\gradlew.bat testDebugUnitTest -DrunSlowTests=true` or `.\gradlew.bat slowTest`.
   * **Formal Verification Models:** ProVerif formal models in `docs/formal/` are verified using `bash docs/formal/run_verification.sh`. They comprise 8 models (.pv) verifying 32 security lemmas (including secrecy of session keys and payloads, anti-grinding SAS authentication and transcript binding, hybrid ML-KEM-512 + X25519 KEM, Forward Secrecy, Post-Compromise Security, replay protection, indistinguishability of 900-byte tombstones and cover traffic, secrecy of group key distribution in 0x06 frames, AAD binding authenticity, group PCS/FS on member leave, and irreversibility of master key erasure upon duress wipe with SQLite row/column swap resistance).
   * **Markdown Math Formatting:** In README and other `.md` files, mathematical expressions must use `$expression$` formatting (which renders robustly across GitHub and markdown previewers).
   * **Emulator Verification:** Test major UI or chat logic changes in an Android emulator (e.g. install via `.\gradlew.bat installDebug`, launch activity, capture screenshot for inspection).
   * **Commit & Push:** After tests pass, commit with a clear Conventional Commits message and push to remote.
