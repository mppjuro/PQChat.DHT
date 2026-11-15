# AGENTS.md — AI Agent Routing Index & Architectural Invariants

This document serves as the authoritative architectural index, security invariant specification, and subsystem routing map for AI agents working in the `PQChat.DHT` repository.

---

## 1. Core Architecture & Invariants

1. **Zero Centralization & Leaf-Only Operation:** Fully serverless Android messenger (100% Kotlin, Jetpack Compose, Room, Coroutines) using the public BitTorrent Mainline Kademlia DHT (BEP-44) as an ephemeral 24–72h store-and-forward buffer. No push brokers (no FCM/APNs), no user accounts, and strict leaf-node mode (never routes third-party traffic or stores external DHT records).
2. **Fail-Closed Tor Transport:** When Tor routing is enabled, all DHT KRPC traffic is tunneled through an embedded Tor SOCKS5/TCP-tunnel circuit (`EmbeddedTorManager` $\rightarrow$ `TorSocketFactory`). Direct UDP fallback is strictly forbidden (fail-closed on circuit or proxy failure).
3. **Post-Quantum & Hybrid Cryptography:** Handshake and periodic rekeying (every 50 messages) use hybrid `X25519 + ML-KEM-512` (FIPS 203, $pk = 832\text{ B}$, $ct = 800\text{ B}$, $SS = 32\text{ B}$). Symmetric payloads use `AES-256-GCM` with `HKDF-SHA512` dual unidirectional ratchet chains ($A \to B$ and $B \to A$) and one-time ephemeral `Ed25519` keys per DHT slot ($\text{Target}_i = \text{SHA-1}(pk_i)$).
4. **Rigid 900-Byte Frame Invariant:** Every BEP-44 value (`v`) written to the DHT—including messages (`0x01`–`0x0B`), cover-traffic ACKs, dummy cover packets, and post-receipt secure tombstones (`seq = DEFAULT_MUTABLE_SEQ + 1`)—must be padded with CSPRNG noise to **exactly 900 bytes** (904 bytes Bencode-encoded, $\le 1000\text{ B}$ BEP-44 limit).
5. **Poisson Cover Traffic & Stratified Polling:** Outbound writes follow a memoryless Poisson process ($\Delta t = -\ln(U)/\lambda$) scheduled across a 5-class Weighted Fair Queue (`OutboundPoissonQueue`). Inbound polling uses a constant budget ($N_{\text{poll}} = 8$ targets per cycle) padded with `DecoyTargetPool` addresses across 4 lifecycle states (`FOREGROUND_CHAT` 10s, `APP_ACTIVE_OTHER` 1m, `BACKGROUND_IDLE` 5m, `DOZE_SLEEP` 15m).
6. **Row-Bound Storage & Duress Wipe:** SQLite sensitive columns are encrypted via Android Keystore `AES-256-GCM` (`MAGIC_ROW_BOUND_V2 = 0x52`) with AAD bound to `table+id+column`. Group frames bind $\text{AAD} = \text{Target} \parallel \text{GroupID} \parallel \text{SenderMemberID}$ and rotate sender keys every 50 messages or upon member leave. Entering the Duress PIN deletes the hardware master key (`KeystoreCrypto.deleteMasterKey`), zeroes RAM caches, and transitions to `DecoyNotesScreen`.
7. **Zero Metadata / Key Leakage & Memory Hygiene:** Ephemeral key `ByteArray` buffers must be zeroed (`fill(0)`) immediately after use. Never log plaintext messages, cryptographic keys, seeds, nonces, or raw contact identifiers via `Log.*` or `println`. All repository code, comments, and documentation must remain 100% in English (`scripts/check_language_unification.py`).

---

## 2. Agent Execution Protocol

1. **Respect Context Ignore Rules:** Always honor `.aiignore` and `.geminiignore`. Do not load or scan excluded non-code artifacts (`app/schemas/**`, `docs/measurements/**`, `docs/*.csv`, `tools/**/*.csv`, `docs/formal/report.txt`, `docs/*.png`, `gradle/**`, `build/**`) unless explicitly instructed by the user.
2. **Read-Only Diagnosis First:** For multi-file bugs, concurrency/ratchet desynchronizations, or logcat analyses, always execute a **read-only diagnosis phase** first. Identify the root cause, verify state transitions across the data flow, and list the exact files and functions to be modified before performing any file edits.
3. **Targeted JVM Unit Tests Before E2E:** After any code change, run the targeted JVM unit test command (`./gradlew testDebugUnitTest --tests "..."`) mapped to the affected subsystem below. Fast unit tests must pass completely before invoking heavy multi-emulator E2E orchestration (`tools/e2e_emulator_orchestrator.py`) or slow integration suites (`-DrunSlowTests=true`).
4. **Protocol & Schema Integrity:** Never alter the 900-byte binary frame size, the 13-byte plaintext header layout, or `MAGIC_ROW_BOUND_V2` AAD format without updating the corresponding unit tests and ProVerif models (`docs/formal/`). Use `$expression$` for inline math in Markdown files.

---

## 3. Subsystem Routing Map & Targeted Unit Tests

Use the routing table and detailed subsystem flows below to navigate directly to the relevant source files (listed in order of data flow) and execute only the associated JVM unit tests.

| # | Subsystem | Primary Package Roots | Quick Verification Scope |
| :- | :--- | :--- | :--- |
| **3.1** | **1-on-1 Handshake & SAS Verification** | `ui/screens`, `ui/viewmodel`, `protocol`, `data/repository` | QR/Stego payload, KEM encapsulation, SAS transcript binding |
| **3.2** | **Group Chat, Invites & Multi-Node Sync** | `crypto`, `data/repository`, `data/db`, `ui/viewmodel` | `0x06`/`0x0A` frames, per-member slot derivation, epoch rekey |
| **3.3** | **PQ Cryptography, Double Ratchet & Rekeying** | `crypto`, `protocol` | Hybrid `X25519 + ML-KEM-512`, HKDF chains, Keystore AAD, Duress wipe |
| **3.4** | **Kademlia DHT (BEP-44), Leaf Node & Bencode** | `dht/bencode`, `dht/krpc`, `dht/leaf` | Bencode codec, KRPC UDP messages, iterative `get`/`put`, Sybil defense |
| **3.5** | **Tor Transport & Fail-Closed Tunneling** | `network/tor` | Embedded Tor lifecycle, SOCKS5 handshake, TCP tunnel, fail-closed policy |
| **3.6** | **Poisson Cover Traffic, Adaptive Polling & Republish** | `traffic`, `protocol` | WFQ scheduling, cover ACKs, 4-state polling, blind republish |
| **3.7** | **Chunking, Media & Steganography** | `protocol`, `media`, `media/voice` | Sliding-window chunk transfer, PNG8 quantization/stego, LPC-10 voice |
| **3.8** | **Background Services & Android Lifecycle** | `service`, `traffic` | `ProcessLifecycleOwner`, screen state, WorkManager/AlarmManager, FGS |
| **3.9** | **Multi-Emulator E2E Harness** | `tools/`, `app/src/androidTest`, `app/src/test/.../e2e` | Full two-emulator UI Automator & loopback E2E verification |

---

### 3.1. 1-on-1 Handshake & SAS Verification

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/ui/screens/HandshakeScreen.kt`
  2. `app/src/main/java/org/pqchat/dht/ui/viewmodel/ChatViewModel.kt`
  3. `app/src/main/java/org/pqchat/dht/ui/viewmodel/BobHandshakeStatus.kt`
  4. `app/src/main/java/org/pqchat/dht/protocol/HandshakeManager.kt`
  5. `app/src/main/java/org/pqchat/dht/data/repository/ChatRepository.kt`
* **Key Responsibilities:** Alice QR/PNG8 generation ($pk_A \parallel Seed_{init}$), Bob hybrid encapsulation and `0x01` frame transmission to $\text{Target}_0$, Alice polling and decapsulation, anti-grinding SAS verification, and initial ratchet chain derivation.
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.ui.HandshakeVerificationTest" --tests "org.pqchat.dht.ui.BobHandshakeStatusTest" --tests "org.pqchat.dht.ui.HandshakeScreenStateTest"
  ```

### 3.2. Group Chat, Invites & Multi-Node Sync

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/crypto/BinaryFrameCodec.kt`
  2. `app/src/main/java/org/pqchat/dht/data/repository/ChatRepository.kt`
  3. `app/src/main/java/org/pqchat/dht/data/db/EntitiesAndDaos.kt`
  4. `app/src/main/java/org/pqchat/dht/ui/viewmodel/ChatViewModel.kt`
* **Key Responsibilities:** Encoding/decoding `0x06` (`GROUP_SUBTYPE_INVITE`, `GROUP_SUBTYPE_REKEY`, `GROUP_SUBTYPE_LEAVE`) and `0x0A` (`TYPE_GROUP_POLL`) frames, per-recipient slot derivation (`deriveGroupRecipientSlot`), Group AAD binding ($\text{Target} \parallel \text{GroupID} \parallel \text{SenderMemberID}$), automatic rekeying every 50 messages, and forward/post-compromise secrecy on member leave.
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.data.repository.ThreeNodeGroupTest" --tests "org.pqchat.dht.data.repository.GroupChatRepositoryTest" --tests "org.pqchat.dht.crypto.GroupChatCryptoTest"
  ```

### 3.3. PQ Cryptography, Double Ratchet & Rekeying

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/crypto/MLKemEngine.kt` / `app/src/main/java/org/pqchat/dht/crypto/HybridKemEngine.kt`
  2. `app/src/main/java/org/pqchat/dht/protocol/RatchetChain.kt`
  3. `app/src/main/java/org/pqchat/dht/protocol/RekeyCoordinator.kt`
  4. `app/src/main/java/org/pqchat/dht/crypto/KeystoreCrypto.kt`
* **Key Responsibilities:** FIPS 203 ML-KEM-512 + X25519 hybrid key encapsulation, HKDF-SHA512 step derivation ($MsgKey_i$, $EdSeed_i$, $ChainKey^{i+1}$), periodic 50-message PQC rekey (`0x03` Offer / `0x04` Response), SQLite `MAGIC_ROW_BOUND_V2` (`0x52`) row/column AAD encryption, and Duress PIN hardware master key destruction.
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.crypto.CryptoEngineTest" --tests "org.pqchat.dht.crypto.MlKemKatAndUniquenessTest" --tests "org.pqchat.dht.data.repository.ChatRepositoryRekeyIntegrationTest" --tests "org.pqchat.dht.crypto.DuressPinKeystoreTest"
  ```

### 3.4. Kademlia DHT (BEP-44), Leaf Node & Bencode

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/dht/bencode/Bencode.kt`
  2. `app/src/main/java/org/pqchat/dht/dht/krpc/KrpcMessage.kt`
  3. `app/src/main/java/org/pqchat/dht/dht/leaf/DhtClient.kt`
  4. `app/src/main/java/org/pqchat/dht/dht/leaf/DhtLeafNode.kt`
* **Key Responsibilities:** Zero-allocation/bounded Bencode parsing, KRPC `find_node` / `get_peers` / BEP-44 `get` & `put` message serialization, Ed25519 mutable item signing, iterative Kademlia closest-node lookup, Sybil/eclipse mitigation, and 900-byte tombstone overwrites (`seq = DEFAULT_MUTABLE_SEQ + 1`).
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.dht.DhtEngineTest" --tests "org.pqchat.dht.dht.DhtLeafNodePutLookupTest" --tests "org.pqchat.dht.dht.AdversarialDhtSecurityTest" --tests "org.pqchat.dht.dht.bencode.BencodeSecurityTest"
  ```

### 3.5. Tor Transport & Fail-Closed Tunneling

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/network/tor/EmbeddedTorManager.kt`
  2. `app/src/main/java/org/pqchat/dht/network/tor/DefaultTorProcessRunner.kt`
  3. `app/src/main/java/org/pqchat/dht/network/tor/Socks5Client.kt`
  4. `app/src/main/java/org/pqchat/dht/network/tor/TorTcpTunnelClient.kt`
  5. `app/src/main/java/org/pqchat/dht/network/tor/TorSocketFactory.kt`
* **Key Responsibilities:** Embedded Tor daemon bootstrap and health monitoring, SOCKS5 proxy authentication and circuit isolation, TCP-over-Tor relay tunneling for DHT queries, and strict fail-closed enforcement (blocking clearnet UDP leaks when Tor is active or degraded).
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.network.tor.EmbeddedTorManagerTest" --tests "org.pqchat.dht.network.tor.TorFailClosedTest" --tests "org.pqchat.dht.network.tor.DhtClientTorIntegrationTest"
  ```

### 3.6. Poisson Cover Traffic, Adaptive Polling & Republish

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/traffic/PoissonTrafficGenerator.kt`
  2. `app/src/main/java/org/pqchat/dht/traffic/OutboundPoissonQueue.kt`
  3. `app/src/main/java/org/pqchat/dht/protocol/CoverAckProtocol.kt`
  4. `app/src/main/java/org/pqchat/dht/traffic/AdaptivePollingManager.kt`
  5. `app/src/main/java/org/pqchat/dht/traffic/RepublishPolicy.kt`
  6. `app/src/main/java/org/pqchat/dht/traffic/BlindRepublishPool.kt`
* **Key Responsibilities:** Exponential inter-arrival shaping ($\Delta t = -\ln(U)/\lambda$), 8-slot WFQ scheduling (`[DIRECT, GROUP, DIRECT, GROUP, DIRECT, IMAGE, DIRECT, COVER]`), covert `0x0B` Safety Canary injection into dummy slots, noise-indistinguishable `CoverAckProtocol` ACKs, $N_{\text{poll}} = 8$ stratified polling with decoy padding, and TTL-aware blind republishing.
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.traffic.StrictPoissonTrafficShapingTest" --tests "org.pqchat.dht.traffic.CoverTrafficAckTest" --tests "org.pqchat.dht.traffic.AdaptivePollingStateMachineTest" --tests "org.pqchat.dht.traffic.RepublishAndKeepaliveTest"
  ```

### 3.7. Chunking, Media & Steganography

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/protocol/ChunkingEngine.kt`
  2. `app/src/main/java/org/pqchat/dht/protocol/SlidingWindowBitmap.kt`
  3. `app/src/main/java/org/pqchat/dht/media/Png8Compressor.kt`
  4. `app/src/main/java/org/pqchat/dht/media/voice/VoiceCodec.kt` / `app/src/main/java/org/pqchat/dht/media/voice/VoiceSegmentAssembler.kt`
* **Key Responsibilities:** Multi-chunk binary transfer (`0x05`, $\le 837\text{ B}$ per chunk) with sliding-window replay bitmap and resumption, indexed 8-bit PNG compression and `PQST` handshake steganography (874-byte envelope with CRC32), and ultra-low-bitrate LPC-10 micro-voice notes (`0x09`, 1280 bps across 1–3 frames).
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.protocol.ChunkTransferResumptionTest" --tests "org.pqchat.dht.media.Png8CompressorTest" --tests "org.pqchat.dht.media.PngSteganographyTest" --tests "org.pqchat.dht.media.VoiceSegmentAssemblerTest"
  ```

### 3.8. Background Services & Android Lifecycle

* **Data Flow (Source Files):**
  1. `app/src/main/java/org/pqchat/dht/service/PollingLifecycleCoordinator.kt`
  2. `app/src/main/java/org/pqchat/dht/service/PollingScheduler.kt`
  3. `app/src/main/java/org/pqchat/dht/service/DhtWorker.kt` / `app/src/main/java/org/pqchat/dht/traffic/PollingWorker.kt` / `app/src/main/java/org/pqchat/dht/traffic/RepublishWorker.kt`
  4. `app/src/main/java/org/pqchat/dht/service/ChatHeadService.kt`
* **Key Responsibilities:** Central lifecycle coordination via `ProcessLifecycleOwner` and `ScreenStateReceiver` (`ON_STOP` with screen interactive transitions to `BACKGROUND_IDLE`, never `DOZE_SLEEP`), `WorkManager` periodic jobs, Doze-aware `AlarmManager.setAndAllowWhileIdle` scheduling, and Android 15 (`targetSdk 35`) `dataSync` Foreground Service timeout compliance.
* **Targeted JVM Unit Tests:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.service.PollingLifecycleCoordinatorTest" --tests "org.pqchat.dht.service.PollingSchedulerTest" --tests "org.pqchat.dht.service.WorkManagerRepublishScheduleTest"
  ```

### 3.9. Multi-Emulator E2E Harness (Run Only After JVM Unit Tests Pass)

* **Data Flow & Test Files:**
  1. `tools/e2e_emulator_orchestrator.py`
  2. `app/src/androidTest/java/org/pqchat/dht/PqChatUiAutomatorTest.kt`
  3. `app/src/test/java/org/pqchat/dht/e2e/TwoDevicesE2EIntegrationTest.kt`
* **Execution Commands:**
  ```bash
  ./gradlew testDebugUnitTest --tests "org.pqchat.dht.e2e.TwoDevicesE2EIntegrationTest"
  python tools/e2e_emulator_orchestrator.py
  ```
