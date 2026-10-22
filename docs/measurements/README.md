# BitTorrent Mainline DHT (BEP 44) Telemetry Measurement Methodology and Conditions

This directory contains raw telemetry data in CSV format and documentation of measurement methodology for record latency and retention across the public BitTorrent Mainline DHT, collected via the `LoopbackMeasurementHarness` module and the `RealDhtLoopbackMeasurementTest` integration suite.

---

## 1. Testbed Conditions (Testbed Context)

* **Measurement Date and Time:** October 2026, UTC / CEST (Central European Summer Time).
* **Geographical Region:** Central Europe, residential endpoint on a high-stability FTTH broadband connection.
* **BitTorrent Mainline DHT Public Bootstrap Nodes:**
  - `router.bittorrent.com:6881`
  - `dht.transmissionbt.com:6881`
  - `router.utorrent.com:6881`
  - `dht.aelitis.com:6881`
  - `dht.libtorrent.org:25401`
* **Active DHT Swarm:** The leaf client node (`DhtLeafNode`) maintains active communication with over 140–180 public Kademlia nodes across the 160-bit SHA-1 identifier space.

---

## 2. Evaluated Network Environment Profiles

Measurements were executed across three representative network profiles:

1. **WIFI (`Wi-Fi (Stable)`):**
   - Stationary FTTH connection over Wi-Fi 6 (802.11ax).
   - Low jitter (±12 ms), minimal packet loss (<0.8%), unconstrained NAT state mapping lifetime (timeout > 300 s).
2. **LTE (`Mobile LTE`):**
   - Emulation of cellular 4G/5G mobile interface characteristics.
   - Radio modem state transitions (RRC - Radio Resource Control), variable RTT (±35 ms jitter), and elevated UDP packet loss rate.
3. **RESTRICTIVE_NAT (`Restrictive NAT/CGNAT`):**
   - Emulation of carrier-grade NAT (CGNAT) or symmetric enterprise NAT.
   - Short UDP port binding timeouts (30 s), increased jitter (±65 ms), and required KRPC query retransmissions.

---

## 3. Measurement Methodology

### 3.1. Self-Notes Loopback Architecture
Each `runLoopbackIteration`:
1. Generates a one-time ephemeral seed (32 bytes CSPRNG) and Ed25519 keypair $`(pk_i, sk_i)`$.
2. Computes the rendezvous address in DHT space: $`	ext{Target}_i = 	ext{SHA-1}(pk_i)`$.
3. Prepares a test payload of **rigid size of exactly 900 bytes** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES`).
   - In Bencode encoding, the payload encodes as `"900:"` + 900 B = **904 bytes**, satisfying the rigid BEP 44 limit ($`\le 1000`$ B).
4. Executes `putMutable` with flag **`skipLocalStore = true`**, bypassing local RAM cache and forcing live KRPC transmission to public DHT nodes.
5. Queries the record with `getMutable` (`skipLocalStore = true`), verifies the Ed25519 signature and bitwise payload integrity.
6. Records $`	ext{RTT}_{	ext{PUT}}`$, $`	ext{RTT}_{	ext{GET}}`$, $`	ext{RTT}_{	ext{TOTAL}}`$ and validates responding node quorum.

### 3.2. Data Retention Evaluation (Retention Scenarios)
Retention evaluation in `evaluateRetentionScenarios`:
* Time horizons: **1h, 2h, 6h, 24h**.
* Modes:
  - **Without republishing (`republish = false`):** Storing record at `seq = DEFAULT_MUTABLE_SEQ` and checking availability over elapsed time.
  - **With active republishing (`republish = true`):** Simulating `RepublishPolicy` with refresh write at `seq = DEFAULT_MUTABLE_SEQ + 1` prior to native BEP 44 TTL expiry (2 h).

---

## 4. Privacy and Anonymization Guarantees (Zero-Crypto Guarantee)

All CSV files in this directory strictly comply with data protection rules:
* **Zero Plaintext:** No user message content or text length is ever recorded.
* **Zero Cryptographic Keys:** No private keys, public keys, or Ed25519/KEM seeds are stored in logs or CSV outputs.
* **Pure Network Telemetry:** Strictly packet timing statistics, transport error codes, and delivery success booleans are stored.

---

## 5. Telemetry File Structure

* `loopback_wifi.csv` — Raw measurements for Wi-Fi environment (100 iterations).
* `loopback_lte.csv` — Raw measurements for LTE environment (100 iterations).
* `loopback_restrictive_nat.csv` — Raw measurements for Restrictive NAT environment (100 iterations).
* `loopback_all.csv` — Consolidated dataset across all environments (300 iterations).
* `retention_measured.csv` — Empirical retention trials for 1h, 2h, 6h, and 24h horizons.

RFC 4180 CSV Header Format:
```csv
measurement_id,timestamp_epoch_ms,data_source,network_environment,operation,rtt_put_ms,rtt_get_ms,rtt_total_ms,delivery_success,retransmissions,retention_hours,republish_enabled,nodes_queried,nodes_responded,error_code
```
