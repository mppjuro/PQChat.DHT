# 📜 Changelog

Wszystkie istotne zmiany w projekcie **PQChat.DHT** są rejestrowane w tym dokumencie.
Format jest oparty na specyfikacji [Conventional Commits](https://www.conventionalcommits.org/).

---

## 🚀 Nowe Funkcjonalności (Features)

- [`79d1fdb`](https://github.com/mppjuro/PQChat.DHT/commit/79d1fdb207bb51938310b62b88d9d7f31d733a81) (2026-10-18) — **research**: implement Local-First Batch Archiving, scrub secrets, and harden CI
- [`fbd8cef`](https://github.com/mppjuro/PQChat.DHT/commit/fbd8cef18d92dc736dcc952c05dc60fbaca10b41) (2026-10-18) — **research**: add anonymous Firebase telemetry and republish retention metrics for master thesis
- [`b237b23`](https://github.com/mppjuro/PQChat.DHT/commit/b237b233910bd56f06b0f5a6bd065c1ea2168a36) (2026-10-17) — **dht**: expand RealBep44RemoteIntegrationTest to 500-sample percentiles and dual MEASURED vs SIMULATED telemetry
- [`165c713`](https://github.com/mppjuro/PQChat.DHT/commit/165c71324e181d910e9318533e6b847e87da8e01) (2026-10-17) — **test**: add two-device end-to-end integration test with PQC rekey and DHT support to nightly CI
- [`1905c58`](https://github.com/mppjuro/PQChat.DHT/commit/1905c5805044f01e7220851ab96cc27bf622c3fe) (2026-10-15) — **dht**: add RealDhtLoopbackMeasurementTest, nightly integration CI, and telemetry report
- [`097b282`](https://github.com/mppjuro/PQChat.DHT/commit/097b2821c8adcd67bf4e99e55098447eb8134b97) (2026-10-15) — **formal**: unify ProVerif models in docs/formal, update Hybrid KEM & 900B tombstones, add CI workflow
- [`004b1fd`](https://github.com/mppjuro/PQChat.DHT/commit/004b1fd0daf4a98f650f7e915b80de617b9eda3c) (2026-10-14) — **qr**: add animated multipart QR codes with out-of-order reassembly and live progress
- [`475fc70`](https://github.com/mppjuro/PQChat.DHT/commit/475fc709bfe88b9e7c6dd48bf52ff24178e404dc) (2026-10-14) — **telemetry**: add empirical Android resource profiler and CSV export for research evaluation
- [`7c7f8ea`](https://github.com/mppjuro/PQChat.DHT/commit/7c7f8ea25adc91519516244591e16d17597d9887) (2026-10-14) — **media**: eliminate chunk 0 key reuse, enable deterministic subTarget derivation and partial transfer resuming
- [`ac3d493`](https://github.com/mppjuro/PQChat.DHT/commit/ac3d493acb5e90291ab55a6fbf35c641dab76394) (2026-10-14) — **crypto**: integrate hybrid X25519 + ML-KEM-512 into handshake, rekey, and BEP 44 frames
- [`0893db3`](https://github.com/mppjuro/PQChat.DHT/commit/0893db30a7464365710e78b7a03ff5c7c8516725) (2026-10-14) — **rekey**: integrate ML-KEM rekey cycle with ChatViewModel, UI banner and nightly integration tests
- [`c10fef9`](https://github.com/mppjuro/PQChat.DHT/commit/c10fef9f7de341e8df31b959f17f18cbc3e57b00) (2026-10-13) — **retention**: implement live Mainline DHT retention measurement harness with state relay workflow
- [`9d99af1`](https://github.com/mppjuro/PQChat.DHT/commit/9d99af1affd6dbf1139e6e836c7be4be0611588f) (2026-10-13) — **testbed**: add isolated BEP 5/44 traffic correlation testbed and nightly workflow
- [`2ce8f72`](https://github.com/mppjuro/PQChat.DHT/commit/2ce8f7274645734e116856360ac2dd08f309a8d4) (2026-10-12) — **security**: implement security hardening, keystore strongbox, bep43 ro=1, flag_secure and minify
- [`dd703e5`](https://github.com/mppjuro/PQChat.DHT/commit/dd703e5dc5512cd8814bca8a52f642054502325f) (2026-10-12) — GNU General Public License v3
- [`665360f`](https://github.com/mppjuro/PQChat.DHT/commit/665360f69ee49c1a088acf51c1ecba94d47d05cb) (2026-10-11) — **tor**: add embedded Tor engine with SOCKS5 KRPC routing and UI integration
- [`01bcf5a`](https://github.com/mppjuro/PQChat.DHT/commit/01bcf5a70cdc3871b18ab0ae064a950559fcdf3a) (2026-10-11) — **ui**: dodaj pelnoekranowy podglad zdjec z zapisem do galerii, jednoliniowy SAS i edycje nazwy kontaktu
- [`18c1a14`](https://github.com/mppjuro/PQChat.DHT/commit/18c1a143f03a16c3016677a37f24eb250cdbe0f2) (2026-10-11) — **traffic**: zaimplementuj Blind Cooperative Republishing w DHT jako zamiennik syntetycznego decoy traffic
- [`049f2f1`](https://github.com/mppjuro/PQChat.DHT/commit/049f2f14021265ba18d276ef81eed51804e0339a) (2026-10-11) — **media**: dodanie kompresji PNG8 z kwantyzacja barw i gallery pickera
- [`07b49de`](https://github.com/mppjuro/PQChat.DHT/commit/07b49debc3495a015af9ac28f1be20cb5f057ce2) (2026-10-11) — **handshake**: add ability to load and decode handshake QR from gallery
- [`f360784`](https://github.com/mppjuro/PQChat.DHT/commit/f3607845ee4e53a690e00aaf78f35fba0784b1c3) (2026-10-10) — **protocol**: add PROTOCOL.md, ProVerif models in docs/formal, anti-grinding SAS, verified contacts, and nightly slow tests workflow
- [`e8968f3`](https://github.com/mppjuro/PQChat.DHT/commit/e8968f335376b65fcb8444a9bd67d6944e30d984) (2026-10-10) — **security**: harden data at rest with fail-closed Keystore, row-bound AAD, and Room migration v7
- [`639e086`](https://github.com/mppjuro/PQChat.DHT/commit/639e086bf568e0da833c12e282680e8e20599274) (2026-10-10) — **crypto**: strict AAD binding, FIPS 203 ML-KEM upgrade, KAT tests and hybrid X25519 mode
- [`d72df3f`](https://github.com/mppjuro/PQChat.DHT/commit/d72df3f09fe67141489804811c2f8477bcc3808b) (2026-10-09) — **traffic**: implement threat model defense mechanisms (jitter, decoy GETs, delayed PUT, decoy slots, Poisson actual target) and statistical tests
- [`7da4706`](https://github.com/mppjuro/PQChat.DHT/commit/7da47065b91c7e6a99c3bf96c8eea9297f6d8f23) (2026-10-09) — **traffic**: add exponential backoff republishing policy and TTL limit for DHT messages
- [`cbcb5a3`](https://github.com/mppjuro/PQChat.DHT/commit/cbcb5a312a1136d801ff03c2b0d8388e7c7a3ed1) (2026-10-08) — **traffic**: implement Cover-Traffic ACK and Piggybacked ACK protocols
- [`664faec`](https://github.com/mppjuro/PQChat.DHT/commit/664faec7bf6aecf04a9227b1074ac98f644cdb1b) (2026-10-08) — **threat**: strengthen threat model and simulator with lookahead, 0-put decoy filtering, intersection attacks, and Sybil modeling
- [`a1788b9`](https://github.com/mppjuro/PQChat.DHT/commit/a1788b9f84b8c903fbd802af0137f1afce4b94ac) (2026-10-08) — **dht**: separate MEASURED vs SIMULATED retention metrics, fix 900B payload, remove artificial floors, and expand remote integration tests
- [`874f621`](https://github.com/mppjuro/PQChat.DHT/commit/874f62173d08a03da73783a673539e2d855eb236) (2026-10-08) — **formal**: add ProVerif formal verification models and test harness
- [`9259379`](https://github.com/mppjuro/PQChat.DHT/commit/9259379eb120c7e4ed36980bb94957bfbefa3b9d) (2026-10-08) — **service**: complete background polling architecture, WorkManager, ForegroundService, and Doze handling
- [`eb972da`](https://github.com/mppjuro/PQChat.DHT/commit/eb972da78d101a2d79d564ef45eea890fcc7ca65) (2026-10-08) — add automated DHT loopback measurement harness and retention report
- [`ecf7b43`](https://github.com/mppjuro/PQChat.DHT/commit/ecf7b43c2f4df9b3ec5c2bf7ea1ba9c927152fa4) (2026-10-08) — ML-KEM key confirmation, transcript binding, AES-GCM AAD, SAS and handshake republishing
- [`bc73de0`](https://github.com/mppjuro/PQChat.DHT/commit/bc73de02b3b9cc423084f6fba16ca9702b58c0cd) (2026-10-07) — seq numbering epochs, intermediate skipped key retention with TTL, sliding window bitmap, and property-based tests
- [`5b2e9c9`](https://github.com/mppjuro/PQChat.DHT/commit/5b2e9c920d8a298ef201730ba96d67ef1a4ebdcc) (2026-10-07) — per-contact Mutex, Room outbox with backoff, and concurrency tests
- [`0c4315f`](https://github.com/mppjuro/PQChat.DHT/commit/0c4315fe4964301197cf3a8247289b423481f737) (2026-10-07) — **dht**: implement target pre-warming route cache and lookahead routing
- [`983af9f`](https://github.com/mppjuro/PQChat.DHT/commit/983af9fc4e065b7470bd482350f4b4d53150fc4c) (2026-10-07) — **dht**: implement persistent peer cache and UDP socket reuse in DhtLeafNode
- [`bf0c011`](https://github.com/mppjuro/PQChat.DHT/commit/bf0c011add28427ead15e244cdcf2da05e1da45b) (2026-10-06) — Add adaptive app launcher icon and message debug logging
- [`38cdc0b`](https://github.com/mppjuro/PQChat.DHT/commit/38cdc0ba480c304ca75999d6026cdf71a0e6070d) (2026-10-06) — Add DHT sync timer with instant poll in TopAppBar
- [`2d8ca10`](https://github.com/mppjuro/PQChat.DHT/commit/2d8ca10661b91475a18ce4706ceea7e7bdb38cd8) (2026-10-05) — Settings screen with Theme Switcher, Polling Interval dropdowns, and Self-Conversation Notes

## 🔒 Bezpieczeństwo i Kryptografia (Security)

- [`d073c44`](https://github.com/mppjuro/PQChat.DHT/commit/d073c4454b531a032f250c989b6ac3ac37f15243) (2026-10-08) — Bencode and KRPC parsing against untrusted UDP inputs and add Jazzer fuzzing
- [`1a250a7`](https://github.com/mppjuro/PQChat.DHT/commit/1a250a7cac2fb6815a7a2efe19094a4b35e44ff1) (2026-10-07) — logging behind DEBUG, remove ChainKey hex from diagnostics, add Room migrations, and encrypt sensitive DB fields with Android Keystore

## 🐛 Poprawki Błędów (Bug Fixes)

- [`0c039d3`](https://github.com/mppjuro/PQChat.DHT/commit/0c039d36d9fdedd43c19504332ea8a316ddc0846) (2026-10-18) — **dht**: resolve BEP 44 candidate routing poisoning and enhance remote put/get reliability
- [`31ca34c`](https://github.com/mppjuro/PQChat.DHT/commit/31ca34c1e2b1bff26e75eeb833bf69cb433922d1) (2026-10-18) — **ci**: gate 500-sample DHT benchmark behind measuredIterations property to prevent timeout in RealBep44RemoteIntegrationTest
- [`590a318`](https://github.com/mppjuro/PQChat.DHT/commit/590a3181bd35dc5585279099bc93d74fc3b06e7f) (2026-10-16) — **dht**: resolve BEP 44 remote integration and loopback measurement failures
- [`c102bb7`](https://github.com/mppjuro/PQChat.DHT/commit/c102bb77e95736f14fc8bc9e279331fadd4082cf) (2026-10-15) — **guide**: Update AGENTS.md with math inline Github formatting guidelines
- [`c173c1c`](https://github.com/mppjuro/PQChat.DHT/commit/c173c1c09ceb184ec37e5ad083d470cf4d4a7bb7) (2026-10-15) — **docs**: formatting of Anti-Grinding & SAS section in README
- [`b8c665d`](https://github.com/mppjuro/PQChat.DHT/commit/b8c665d7d274b5e7dd76518b4cef75cfe6870ced) (2026-10-15) — **release**: fixed release description, deleted misused @ char
- [`5f85f00`](https://github.com/mppjuro/PQChat.DHT/commit/5f85f00ba71153b14fba7d465f2190b68176068b) (2026-10-15) — **service**: prevent unstarted PollingScheduler race condition and isolate WorkManagerRepublishScheduleTest
- [`7268b03`](https://github.com/mppjuro/PQChat.DHT/commit/7268b03f9d2d3da0d05de4d08456532ed25fbc0e) (2026-10-14) — **profiler**: eliminate race condition between background sampler and manual snapshots in tests
- [`4eea801`](https://github.com/mppjuro/PQChat.DHT/commit/4eea801b8f43e454cedfe8ea01b6de5abdd4cb02) (2026-10-14) — **ui**: resolve Compose deprecations for LocalLifecycleOwner, TabRow, and menuAnchor
- [`13e80eb`](https://github.com/mppjuro/PQChat.DHT/commit/13e80eb5212283e46f3a850560bbc24cb2bb2ead) (2026-10-14) — **dht**: avoid public bootstrap calls and loosen timing assertion in FastTerminationTest
- [`669b45a`](https://github.com/mppjuro/PQChat.DHT/commit/669b45a8d7659e9169368b57e13b0743f97c9fa4) (2026-10-14) — **tor**: enforce fail-closed transport, block silent simulation on Android, and add SOCKS5 TCP tunnel fallback for BEP 44
- [`e9330d2`](https://github.com/mppjuro/PQChat.DHT/commit/e9330d2100348d1421fe79d78c1fe71169f418f8) (2026-10-13) — **lifecycle**: centralize polling lifecycle with unified 4-state coordinator and true screen detection
- [`022d8ee`](https://github.com/mppjuro/PQChat.DHT/commit/022d8eeb336d8a602762734586cfe514084cec03) (2026-10-13) — **test**: fix instrumented tests execution, resolve toolchain provisioning and fragment request code limitation
- [`1f86595`](https://github.com/mppjuro/PQChat.DHT/commit/1f865955963be49a930f5ed482def2600877fe07) (2026-10-12) — **service**: fix background state machine, add boot receiver, fgs timeout, and battery optimization prompt
- [`fd30f05`](https://github.com/mppjuro/PQChat.DHT/commit/fd30f05ed0f4ecdfe64bc48dd6922be8a4b82df1) (2026-10-12) — **crypto**: update ML-KEM KAT test for Bouncy Castle 1.86 and set compileSdk to 37
- [`751b1eb`](https://github.com/mppjuro/PQChat.DHT/commit/751b1eb72d23c091cc81e37097aa4eb4b13dbaaa) (2026-10-12) — **test**: isolate PollingWorker state and refresh FakeDht in WorkManagerRepublishScheduleTest
- [`4156dd8`](https://github.com/mppjuro/PQChat.DHT/commit/4156dd8c2f475e1449c9c85ce289e78e8ec765d2) (2026-10-12) — **spec**: Unify record payload to 900B, implement uniform tombstone, and align documentation
- [`1cabd71`](https://github.com/mppjuro/PQChat.DHT/commit/1cabd71a112e190b53c5f21b4613e9d22fc3495f) (2026-10-12) — eliminate unused variable compiler warnings and bump GitHub Actions
- [`90d5b0b`](https://github.com/mppjuro/PQChat.DHT/commit/90d5b0baa968b2b619c67a6a1542e059fe43bf7e) (2026-10-11) — **test**: fixed RealBep44RemoteIntegrationTest: workflow imprevements - Java version updated
- [`b8c2d53`](https://github.com/mppjuro/PQChat.DHT/commit/b8c2d53f539eb683d50bbd8a4ec6c0c557f3ed71) (2026-10-11) — **test**: fixed RealBep44RemoteIntegrationTest: retry loop + DHT connection extended timeout
- [`7a56fc6`](https://github.com/mppjuro/PQChat.DHT/commit/7a56fc6628504e9bed58076845e4ccf51c335ead) (2026-10-11) — **test**: fixed CoverTrafficAckTest and TrafficThreatModelStatisticalTest
- [`6675da5`](https://github.com/mppjuro/PQChat.DHT/commit/6675da5abbbc4bcdc23546b5bd170c1f89e5114d) (2026-10-11) — **ui**: przeniesienie ustawien kompresji PNG8 na poczatek i usuniecie przycisku z gornej belki czatu
- [`39a19b5`](https://github.com/mppjuro/PQChat.DHT/commit/39a19b5093b6081771b120d3d3e6765251654756) (2026-10-11) — **ui/crypto**: naprawa weryfikacji SAS i dodawania wielu rozmowcow
- [`b8762f3`](https://github.com/mppjuro/PQChat.DHT/commit/b8762f3a890ae3d07eebbc9de49ae328e1afeac2) (2026-10-08) — BEP 44 seq metadata leak with constant seq and unify frame buffer constants
- [`bf885e2`](https://github.com/mppjuro/PQChat.DHT/commit/bf885e26606652975d923667954c6676f0cef369) (2026-10-07) — PQC rekey protocol state machine and add 200-message bidirectional integration test
- [`1cf4d8d`](https://github.com/mppjuro/PQChat.DHT/commit/1cf4d8d7fd33dfbcad41121734fbf431ab884449) (2026-10-07) — **sync**: Show sync animation immediately on app launch and prevent timer freeze during initial DHT poll
- [`0be7d8c`](https://github.com/mppjuro/PQChat.DHT/commit/0be7d8c5cb30a1472096355490e35d1de27e7a78) (2026-10-06) — **sync**: Keep sync animation active for entire DHT poll duration and transition directly to countdown
- [`c631808`](https://github.com/mppjuro/PQChat.DHT/commit/c631808ebef23f04c1bcdc8d3c5af3597025d1a6) (2026-10-06) — **ui**: Redesign DHT sync countdown timer chip into wider rectangular badge
- [`faa880a`](https://github.com/mppjuro/PQChat.DHT/commit/faa880a8b4ebf57f52ff3d0d5aa5e87c3a0c2d19) (2026-10-05) — DHT BEP 44 v field size limit to 900B, bypass local store for self-notes, and align confirmed loopback messages to left
- [`97294cc`](https://github.com/mppjuro/PQChat.DHT/commit/97294cc308e0790ebd843aa1168b532d7c5e976d) (2026-10-05) — BEP 44 mutable storage, chunk retrieval and loopback DHT delivery confirmation

## ⚡ Wydajność i Optymalizacje (Performance)

- [`0cbec4a`](https://github.com/mppjuro/PQChat.DHT/commit/0cbec4a64423dd1192b6e35122d9a2ab9ca04094) (2026-10-07) — screen change polling recalculation and resolve compiler and lint warnings
- [`e4d3094`](https://github.com/mppjuro/PQChat.DHT/commit/e4d3094a1a1aa8a2ad988f1ba22ce112ab503362) (2026-10-07) — DHT message polling with Fast Termination and asynchronous lookahead window

## 📦 Budowanie i Zależności (Build & CI)

- [`5909593`](https://github.com/mppjuro/PQChat.DHT/commit/590959339c8774483b78c65225f317b3df13967f) (2026-10-17) — **nightly**: split slow tests into parallel jobs, add timeouts, advance schedule 8h, and optimize loopback leaf node
- [`cb57ef9`](https://github.com/mppjuro/PQChat.DHT/commit/cb57ef9f091605d792d894678d9e94ce2ebe22f3) (2026-10-14) — consolidate workflows into commit fast tests, nightly tests with release, and manual release
- [`6f52b71`](https://github.com/mppjuro/PQChat.DHT/commit/6f52b712fb0b428342413077a86fc719a7e69b24) (2026-10-14) — **deps**: bump org.junit.jupiter:junit-jupiter from 5.10.2 to 6.1.3
- [`4d30697`](https://github.com/mppjuro/PQChat.DHT/commit/4d30697426e01a08418bb892b83e63a57c3aab66) (2026-10-14) — **deps**: bump org.robolectric:robolectric from 4.14.1 to 4.17
- [`abd61bf`](https://github.com/mppjuro/PQChat.DHT/commit/abd61bfbace24185d9585288a16ae94a81c4f1ae) (2026-10-14) — **deps**: bump the androidx-and-compose group with 2 updates
- [`506dd06`](https://github.com/mppjuro/PQChat.DHT/commit/506dd064cdf065fa76ef4ec970c6ab7386c6c5a3) (2026-10-14) — **deps**: bump softprops/action-gh-release from 2 to 3
- [`8effc75`](https://github.com/mppjuro/PQChat.DHT/commit/8effc7594ff5373e56a12211f48780c7fd19ef67) (2026-10-14) — **deps**: update numpy requirement in /tools/threat_sim
- [`9435074`](https://github.com/mppjuro/PQChat.DHT/commit/943507403309dfb5ff37e63f63e89adbedff9084) (2026-10-14) — **deps**: bump actions/setup-python from 5 to 7
- [`b37de1c`](https://github.com/mppjuro/PQChat.DHT/commit/b37de1c7549ee707d8f29e5d0281922612f371d2) (2026-10-12) — add issue and PR templates, nightly build and release workflows, and changelog automation
- [`f59c21c`](https://github.com/mppjuro/PQChat.DHT/commit/f59c21cccc38cfb44bcec54bce7b6891df601c7c) (2026-10-12) — **dependencies**: updated dependencies in build.gradle.kts to last version
- [`2cd09c8`](https://github.com/mppjuro/PQChat.DHT/commit/2cd09c87041220e27b52df471740bbf512323f9f) (2026-10-12) — **deps**: bump org.jetbrains.kotlinx:kotlinx-coroutines-android
- [`7db7059`](https://github.com/mppjuro/PQChat.DHT/commit/7db7059a72c222c7aa61bee6697897ee8b9b1e4f) (2026-10-12) — **deps**: bump org.jetbrains.kotlinx:kotlinx-coroutines-test
- [`299d8fe`](https://github.com/mppjuro/PQChat.DHT/commit/299d8fe71d970e81a0cdfc9b1e85de9ee4e047d8) (2026-10-12) — **deps**: bump org.junit.vintage:junit-vintage-engine
- [`eb1eb8f`](https://github.com/mppjuro/PQChat.DHT/commit/eb1eb8f37d6dcea266b1640b47e0fbc719db3f5d) (2026-10-12) — migrate to AGP 9.4.1 built-in Kotlin, KSP 2.3.12 and Compose compiler plugin
- [`9337c84`](https://github.com/mppjuro/PQChat.DHT/commit/9337c84cf6b031eabf7d4bc181f262d7dc24a7d1) (2026-10-12) — **gradle**: upgrade to Gradle 9.8.1 and enforce Java 17 daemon toolchain
- [`b8dc15c`](https://github.com/mppjuro/PQChat.DHT/commit/b8dc15c90ab803493e274279f0751e9538e80bec) (2026-10-12) — **deps**: update matplotlib requirement in /tools/threat_sim
- [`35a281a`](https://github.com/mppjuro/PQChat.DHT/commit/35a281ae7d47a7f960ac2a0198c33bebb6d1b9d6) (2026-10-12) — **deps**: bump com.google.zxing:core from 3.5.3 to 3.5.4
- [`7b3cc7a`](https://github.com/mppjuro/PQChat.DHT/commit/7b3cc7a37b6b43b31cafd928e9519f815e16e2d1) (2026-10-12) — **deps**: bump com.code-intelligence:jazzer-api from 0.23.0 to 0.30.0
- [`978bf67`](https://github.com/mppjuro/PQChat.DHT/commit/978bf67bc1bc91fb0b6b396be02d11ab64fa8f68) (2026-10-12) — **deps**: bump gradle-wrapper from 8.7 to 9.8.1
- [`b411e78`](https://github.com/mppjuro/PQChat.DHT/commit/b411e7869d5442cb5bd4fb0024e5552ff28880d7) (2026-10-12) — **deps**: update scipy requirement in /tools/threat_sim
- [`0e28665`](https://github.com/mppjuro/PQChat.DHT/commit/0e286658af64622d35b1c4a3c4e9cbdd7d6d383e) (2026-10-12) — **deps**: update numpy requirement in /tools/threat_sim
- [`779df60`](https://github.com/mppjuro/PQChat.DHT/commit/779df60e8b8c7a347059065e4faff7f9ea834db2) (2026-10-12) — **deps**: bump actions/upload-artifact from 6 to 7
- [`1164f08`](https://github.com/mppjuro/PQChat.DHT/commit/1164f08978f16df506dcc05fe522782dce8f5f1b) (2026-10-12) — **deps**: bump actions/setup-java from 5 to 6
- [`dea6985`](https://github.com/mppjuro/PQChat.DHT/commit/dea6985d105ebd1b8a5256c4d0b88672b02a73a4) (2026-10-12) — **deps**: bump actions/checkout from 5 to 7
- [`643e64a`](https://github.com/mppjuro/PQChat.DHT/commit/643e64a4811bc7cb79b72236f3eb178eb39c5687) (2026-10-12) — add dependabot configuration for gradle, github-actions and pip
- [`0232705`](https://github.com/mppjuro/PQChat.DHT/commit/0232705c8cd0bd52527d6c1606003d0ae12734c4) (2026-10-07) — update - emulator OS updated to ubuntu-latest
- [`8b34ef6`](https://github.com/mppjuro/PQChat.DHT/commit/8b34ef64034ab82f79dbc237183a8672af482df7) (2026-10-07) — gradle-wrapper.jar and set as exclusion in .gitignore

## 🧪 Testy (Tests)

- [`04b6293`](https://github.com/mppjuro/PQChat.DHT/commit/04b62930a9f063e82c1f20cf14098190f9c8415c) (2026-10-08) — fix recovery round budget and initiator roles in testRandomizedLossAndReorderingProperty

## 📚 Dokumentacja (Documentation)

- [`644e049`](https://github.com/mppjuro/PQChat.DHT/commit/644e049700a53f9f463b350d070534a82e060549) (2026-10-18) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`fc1bea0`](https://github.com/mppjuro/PQChat.DHT/commit/fc1bea050d064067ecf8a360066141efa372c5d5) (2026-10-18) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`3ffc4d1`](https://github.com/mppjuro/PQChat.DHT/commit/3ffc4d1307354f01294991e4e35f86de42486b22) (2026-10-18) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`5b97173`](https://github.com/mppjuro/PQChat.DHT/commit/5b9717306ff815aa6abb6760efdb654fd63d54cf) (2026-10-17) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`4ec96de`](https://github.com/mppjuro/PQChat.DHT/commit/4ec96debdac65f1ab60edbe4a53b4c34e273ca60) (2026-10-17) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`c524a4e`](https://github.com/mppjuro/PQChat.DHT/commit/c524a4eebda746834af9add54aa887a944efc86a) (2026-10-17) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9413149`](https://github.com/mppjuro/PQChat.DHT/commit/9413149cdef10b97dd9767a126bad5e4f7d1e5c7) (2026-10-16) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`5d8f0ce`](https://github.com/mppjuro/PQChat.DHT/commit/5d8f0ce2e2b66fe36f4027fd83281e37dc65b73d) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`8c62f1a`](https://github.com/mppjuro/PQChat.DHT/commit/8c62f1acddb02da1331af5280fd034e825a68944) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9571b12`](https://github.com/mppjuro/PQChat.DHT/commit/9571b12f33bb84d03962b0771eee1e49cd7cc1dc) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`6966ccf`](https://github.com/mppjuro/PQChat.DHT/commit/6966ccfe21c87f104b3fb391b9dac527ae8fe453) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9fe3710`](https://github.com/mppjuro/PQChat.DHT/commit/9fe37108570f66770fba8b3938077b075d3bc037) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`3c01cf7`](https://github.com/mppjuro/PQChat.DHT/commit/3c01cf715ceccda469cbac5e988324a9239a5ff7) (2026-10-15) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`0b8d0cd`](https://github.com/mppjuro/PQChat.DHT/commit/0b8d0cd629f1040bda727ccab82d01f96b2ca950) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`445319d`](https://github.com/mppjuro/PQChat.DHT/commit/445319da9253b46a91d579b578d00139d5244754) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`c37dfc3`](https://github.com/mppjuro/PQChat.DHT/commit/c37dfc37f1f7e78edba51695f2410b540e5e2266) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`567b5b2`](https://github.com/mppjuro/PQChat.DHT/commit/567b5b230f1d418fb2958802ca0ce474a5f1f7aa) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`02d216f`](https://github.com/mppjuro/PQChat.DHT/commit/02d216f1a70732f1bb96d6812c0b04125a46a9b2) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`e3aed4e`](https://github.com/mppjuro/PQChat.DHT/commit/e3aed4eb6ba6ce412760c64072e8e5d273dbec89) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`361b0c0`](https://github.com/mppjuro/PQChat.DHT/commit/361b0c0d81c75cb3c5ab88a4ba21d0a62d6ba67f) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`40e750f`](https://github.com/mppjuro/PQChat.DHT/commit/40e750f063c3d052a518b7b84b640d05e2a8d0c7) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`59d03a3`](https://github.com/mppjuro/PQChat.DHT/commit/59d03a34c8124a47e747a3f5c83327ae920495c3) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`e4feb44`](https://github.com/mppjuro/PQChat.DHT/commit/e4feb44dadfe18ecbe8b49d2e3a0393142d5fafc) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9c02d15`](https://github.com/mppjuro/PQChat.DHT/commit/9c02d1500a391532691e06f07f51dad16399989b) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9269f18`](https://github.com/mppjuro/PQChat.DHT/commit/9269f18cadf6a78478f157598b40b8cdb1959c6e) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`e856141`](https://github.com/mppjuro/PQChat.DHT/commit/e856141ec614e27b03c0815e52003675c0f69b7b) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9f785eb`](https://github.com/mppjuro/PQChat.DHT/commit/9f785eb32977c1a09624a9d1f6fd257e93546f3c) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`43c5fdd`](https://github.com/mppjuro/PQChat.DHT/commit/43c5fdd30192d8c9061c0eedecab978e99278aa3) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`59a8c57`](https://github.com/mppjuro/PQChat.DHT/commit/59a8c579267469141f761fd45e28de9837cac1c3) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`23fb33b`](https://github.com/mppjuro/PQChat.DHT/commit/23fb33b24a1c2fdea158eaf56bbaaff236988166) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`aa6b061`](https://github.com/mppjuro/PQChat.DHT/commit/aa6b0619d1d68dcf6d27d450c8971b56ea8dd3fa) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`ab19f01`](https://github.com/mppjuro/PQChat.DHT/commit/ab19f01ceb5a96c58be8a17054079f31ca63255a) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`2ae0b22`](https://github.com/mppjuro/PQChat.DHT/commit/2ae0b229e21948f87c1496838f847259574d770c) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`a53ec44`](https://github.com/mppjuro/PQChat.DHT/commit/a53ec44ccf1fc89dfcf6e277cfc0f639097e1a86) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`7ba7545`](https://github.com/mppjuro/PQChat.DHT/commit/7ba7545752d4e0d67c02a9332feb492e1cede54d) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`c093b39`](https://github.com/mppjuro/PQChat.DHT/commit/c093b39f16686d71986e27bf095b8c94a1d53acf) (2026-10-12) — README with project details and instructions
- [`3c8c26e`](https://github.com/mppjuro/PQChat.DHT/commit/3c8c26e6badbecc4fda6afba53595987e78c0c68) (2026-10-08) — add threat model, DHT correlation simulator, and upgrade CI actions to Node 24

## 🛠️ Pozostałe Zmiany (Other Changes)

- [`3dcf409`](https://github.com/mppjuro/PQChat.DHT/commit/3dcf409e14239001cd0afbb5cba01242887a9283) (2026-10-18) — decoupled 60-90m republish, ACK tombstones, resend expired messages, adaptive K (16 on LTE/CGNAT), and active chat keepalive (20-25s)
- [`121515d`](https://github.com/mppjuro/PQChat.DHT/commit/121515d9e077782f83f18679e03d96d150a62f12) (2026-10-07) — DhtClient interface, implement FakeDht, isolate integration tests, and add GitHub Actions CI
- [`cd50430`](https://github.com/mppjuro/PQChat.DHT/commit/cd50430176153aaae86435296effcd5d279eb09e) (2026-10-05) — commit
