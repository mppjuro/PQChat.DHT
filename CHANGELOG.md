# 📜 Changelog

Wszystkie istotne zmiany w projekcie **PQChat.DHT** są rejestrowane w tym dokumencie.
Format jest oparty na specyfikacji [Conventional Commits](https://www.conventionalcommits.org/).

---

## 🚀 Nowe Funkcjonalności (Features)

- [`7be993b`](https://github.com/mppjuro/PQChat.DHT/commit/7be993bdff87213be0276b65aaca912fc03ff140) (2026-10-14) — **crypto**: integrate hybrid X25519 + ML-KEM-512 into handshake, rekey, and BEP 44 frames
- [`9bd1321`](https://github.com/mppjuro/PQChat.DHT/commit/9bd132145f4c743b358fe1cdac72c637617a71dd) (2026-10-14) — **rekey**: integrate ML-KEM rekey cycle with ChatViewModel, UI banner and nightly integration tests
- [`33e111d`](https://github.com/mppjuro/PQChat.DHT/commit/33e111db9e430f2658c63d0f9e2ef10addf0865f) (2026-10-13) — **retention**: implement live Mainline DHT retention measurement harness with state relay workflow
- [`51df96f`](https://github.com/mppjuro/PQChat.DHT/commit/51df96f431f825c20a1ffdcae612c2cb8b9d93ce) (2026-10-13) — **testbed**: add isolated BEP 5/44 traffic correlation testbed and nightly workflow
- [`4631477`](https://github.com/mppjuro/PQChat.DHT/commit/4631477c2089cb020cdf46a497d84ee243885727) (2026-10-12) — **security**: implement security hardening, keystore strongbox, bep43 ro=1, flag_secure and minify
- [`4d7b841`](https://github.com/mppjuro/PQChat.DHT/commit/4d7b841da32b973c734780eeaa09ab08833d8b5b) (2026-10-12) — GNU General Public License v3
- [`2e4d976`](https://github.com/mppjuro/PQChat.DHT/commit/2e4d97631bc296780a21c2b36f6df27044a04598) (2026-10-11) — **tor**: add embedded Tor engine with SOCKS5 KRPC routing and UI integration
- [`ab8bf15`](https://github.com/mppjuro/PQChat.DHT/commit/ab8bf1530a53700f424f3ced676375293c217268) (2026-10-11) — **ui**: dodaj pelnoekranowy podglad zdjec z zapisem do galerii, jednoliniowy SAS i edycje nazwy kontaktu
- [`447a1ca`](https://github.com/mppjuro/PQChat.DHT/commit/447a1ca9e76bac5166beec30731a7e4152cca455) (2026-10-11) — **traffic**: zaimplementuj Blind Cooperative Republishing w DHT jako zamiennik syntetycznego decoy traffic
- [`7165939`](https://github.com/mppjuro/PQChat.DHT/commit/7165939694dc10801c3321b3251a2c2a9d317c9a) (2026-10-11) — **media**: dodanie kompresji PNG8 z kwantyzacja barw i gallery pickera
- [`f4f666e`](https://github.com/mppjuro/PQChat.DHT/commit/f4f666ebbbbf564a42552815ad344724a63ca19d) (2026-10-11) — **handshake**: add ability to load and decode handshake QR from gallery
- [`753833b`](https://github.com/mppjuro/PQChat.DHT/commit/753833b1f877e656c003f984cb82b5b799511160) (2026-10-10) — **protocol**: add PROTOCOL.md, ProVerif models in docs/formal, anti-grinding SAS, verified contacts, and nightly slow tests workflow
- [`8057588`](https://github.com/mppjuro/PQChat.DHT/commit/8057588d42ea09bf7bd4c4aeb94da92ed4ecfacb) (2026-10-10) — **security**: harden data at rest with fail-closed Keystore, row-bound AAD, and Room migration v7
- [`d0ae258`](https://github.com/mppjuro/PQChat.DHT/commit/d0ae258ac6578eaac0e60445e96f5681fda0262d) (2026-10-10) — **crypto**: strict AAD binding, FIPS 203 ML-KEM upgrade, KAT tests and hybrid X25519 mode
- [`a0e2d76`](https://github.com/mppjuro/PQChat.DHT/commit/a0e2d7667866f4dee588551026ee92a79d3bd052) (2026-10-09) — **traffic**: implement threat model defense mechanisms (jitter, decoy GETs, delayed PUT, decoy slots, Poisson actual target) and statistical tests
- [`f0ee6d5`](https://github.com/mppjuro/PQChat.DHT/commit/f0ee6d533af884ba5ee44b329e5befbefe593af6) (2026-10-09) — **traffic**: add exponential backoff republishing policy and TTL limit for DHT messages
- [`80730f6`](https://github.com/mppjuro/PQChat.DHT/commit/80730f641d318012107e2c2f38a37814ce51376b) (2026-10-08) — **traffic**: implement Cover-Traffic ACK and Piggybacked ACK protocols
- [`daefaa0`](https://github.com/mppjuro/PQChat.DHT/commit/daefaa0dbab2784d51dddabf52bd604fe2a9f462) (2026-10-08) — **threat**: strengthen threat model and simulator with lookahead, 0-put decoy filtering, intersection attacks, and Sybil modeling
- [`fce2c41`](https://github.com/mppjuro/PQChat.DHT/commit/fce2c41ad142871943c5d3cb592acff122cf5b0c) (2026-10-08) — **dht**: separate MEASURED vs SIMULATED retention metrics, fix 900B payload, remove artificial floors, and expand remote integration tests
- [`7fbbb02`](https://github.com/mppjuro/PQChat.DHT/commit/7fbbb028db59d1b5679762e73fd3a143a3d04f33) (2026-10-08) — **formal**: add ProVerif formal verification models and test harness
- [`9ab67f5`](https://github.com/mppjuro/PQChat.DHT/commit/9ab67f58d97d454043bedd80d31975d094862086) (2026-10-08) — **service**: complete background polling architecture, WorkManager, ForegroundService, and Doze handling
- [`c2c4d4f`](https://github.com/mppjuro/PQChat.DHT/commit/c2c4d4f3e1a422222953d4beb9e60c3f2d105611) (2026-10-08) — add automated DHT loopback measurement harness and retention report
- [`dd713ff`](https://github.com/mppjuro/PQChat.DHT/commit/dd713ff3de9f6e33e27f3be35eac1c74cd214ae1) (2026-10-08) — ML-KEM key confirmation, transcript binding, AES-GCM AAD, SAS and handshake republishing
- [`879f23a`](https://github.com/mppjuro/PQChat.DHT/commit/879f23a91efe5c6e178bdb467550c750d7f24645) (2026-10-07) — seq numbering epochs, intermediate skipped key retention with TTL, sliding window bitmap, and property-based tests
- [`8b84a97`](https://github.com/mppjuro/PQChat.DHT/commit/8b84a97d04258c96acfb947cba0e854a1e9ca6b6) (2026-10-07) — per-contact Mutex, Room outbox with backoff, and concurrency tests
- [`9e464ce`](https://github.com/mppjuro/PQChat.DHT/commit/9e464cef349ebdda66ff975e3fc372d7fe4e1156) (2026-10-07) — **dht**: implement target pre-warming route cache and lookahead routing
- [`822c698`](https://github.com/mppjuro/PQChat.DHT/commit/822c698674c809114289b7e815080fba475ccfd1) (2026-10-07) — **dht**: implement persistent peer cache and UDP socket reuse in DhtLeafNode
- [`1326193`](https://github.com/mppjuro/PQChat.DHT/commit/1326193c3718b9443c10a2b1ad72159e976db456) (2026-10-06) — Add adaptive app launcher icon and message debug logging
- [`5e67688`](https://github.com/mppjuro/PQChat.DHT/commit/5e6768873a30f39ee60d12dbef98bed633cc4d5d) (2026-10-06) — Add DHT sync timer with instant poll in TopAppBar
- [`b2d2ae3`](https://github.com/mppjuro/PQChat.DHT/commit/b2d2ae3c3f5bd69790d1ccf775f68c2c72908768) (2026-10-05) — Settings screen with Theme Switcher, Polling Interval dropdowns, and Self-Conversation Notes

## 🔒 Bezpieczeństwo i Kryptografia (Security)

- [`554973b`](https://github.com/mppjuro/PQChat.DHT/commit/554973b57396edf99d967d9df3fb08afecd1f16f) (2026-10-08) — Bencode and KRPC parsing against untrusted UDP inputs and add Jazzer fuzzing
- [`d3ac2aa`](https://github.com/mppjuro/PQChat.DHT/commit/d3ac2aab07553645a8c7a9a2e5ad1730b728c166) (2026-10-07) — logging behind DEBUG, remove ChainKey hex from diagnostics, add Room migrations, and encrypt sensitive DB fields with Android Keystore

## 🐛 Poprawki Błędów (Bug Fixes)

- [`5c8011e`](https://github.com/mppjuro/PQChat.DHT/commit/5c8011e99ca96cadee9091e554d2dc35122335ab) (2026-10-14) — **tor**: enforce fail-closed transport, block silent simulation on Android, and add SOCKS5 TCP tunnel fallback for BEP 44
- [`f95251f`](https://github.com/mppjuro/PQChat.DHT/commit/f95251f6f0175f5f0bc0d395ec67379fca733274) (2026-10-13) — **lifecycle**: centralize polling lifecycle with unified 4-state coordinator and true screen detection
- [`1dc376c`](https://github.com/mppjuro/PQChat.DHT/commit/1dc376c94e232eda2cedde8a70ad678851175026) (2026-10-13) — **test**: fix instrumented tests execution, resolve toolchain provisioning and fragment request code limitation
- [`09869d7`](https://github.com/mppjuro/PQChat.DHT/commit/09869d7a390ce3106c7e1c0ab743e4dfde6ce968) (2026-10-12) — **service**: fix background state machine, add boot receiver, fgs timeout, and battery optimization prompt
- [`05146be`](https://github.com/mppjuro/PQChat.DHT/commit/05146be9cb058d10ebc5c80e8ddd45f2bc23bc59) (2026-10-12) — **crypto**: update ML-KEM KAT test for Bouncy Castle 1.86 and set compileSdk to 37
- [`96552fd`](https://github.com/mppjuro/PQChat.DHT/commit/96552fd349bb622ba2878c9a0ebb0c9972772ed2) (2026-10-12) — **test**: isolate PollingWorker state and refresh FakeDht in WorkManagerRepublishScheduleTest
- [`289eebe`](https://github.com/mppjuro/PQChat.DHT/commit/289eebe6b2c3478d0e8c9de4f66a6800a8349424) (2026-10-12) — **spec**: Unify record payload to 900B, implement uniform tombstone, and align documentation
- [`f91fd71`](https://github.com/mppjuro/PQChat.DHT/commit/f91fd719079d58fd5667e1429b3ffae12b1c304b) (2026-10-12) — eliminate unused variable compiler warnings and bump GitHub Actions
- [`6652b69`](https://github.com/mppjuro/PQChat.DHT/commit/6652b6970cf1c04a59ed2e69aa69c8a09be16c6e) (2026-10-11) — **test**: fixed RealBep44RemoteIntegrationTest: workflow imprevements - Java version updated
- [`9d3b8d5`](https://github.com/mppjuro/PQChat.DHT/commit/9d3b8d583ef484872021b26d1884b05ee2d75f14) (2026-10-11) — **test**: fixed RealBep44RemoteIntegrationTest: retry loop + DHT connection extended timeout
- [`4d09e16`](https://github.com/mppjuro/PQChat.DHT/commit/4d09e161286d13d61794f64fe6f0bae6ea8125c5) (2026-10-11) — **test**: fixed CoverTrafficAckTest and TrafficThreatModelStatisticalTest
- [`4f9f0ae`](https://github.com/mppjuro/PQChat.DHT/commit/4f9f0aeaea777c5a9873dc8a9f70b679ab520b6a) (2026-10-11) — **ui**: przeniesienie ustawien kompresji PNG8 na poczatek i usuniecie przycisku z gornej belki czatu
- [`e929e1c`](https://github.com/mppjuro/PQChat.DHT/commit/e929e1c96244a4fefa712e83faea14b81b5ed50c) (2026-10-11) — **ui/crypto**: naprawa weryfikacji SAS i dodawania wielu rozmowcow
- [`b94b2f1`](https://github.com/mppjuro/PQChat.DHT/commit/b94b2f13ff725834d49a019e0757a250f862ad8e) (2026-10-08) — BEP 44 seq metadata leak with constant seq and unify frame buffer constants
- [`e2537a3`](https://github.com/mppjuro/PQChat.DHT/commit/e2537a342f5028144dece8c26399eff662acc484) (2026-10-07) — PQC rekey protocol state machine and add 200-message bidirectional integration test
- [`5c89de5`](https://github.com/mppjuro/PQChat.DHT/commit/5c89de54fd7b92a3eeb27ba1f94a4ed3561837ae) (2026-10-07) — **sync**: Show sync animation immediately on app launch and prevent timer freeze during initial DHT poll
- [`c885d92`](https://github.com/mppjuro/PQChat.DHT/commit/c885d92b485ecede5c3b5a36ce276fc9e7334d09) (2026-10-06) — **sync**: Keep sync animation active for entire DHT poll duration and transition directly to countdown
- [`aed1cf6`](https://github.com/mppjuro/PQChat.DHT/commit/aed1cf6ee8cf5f159a65bbba0120d2ba46338279) (2026-10-06) — **ui**: Redesign DHT sync countdown timer chip into wider rectangular badge
- [`b98a359`](https://github.com/mppjuro/PQChat.DHT/commit/b98a35908f0e0cd87fe7f98a68149a49b7ea7bfe) (2026-10-05) — DHT BEP 44 v field size limit to 900B, bypass local store for self-notes, and align confirmed loopback messages to left
- [`8978b6d`](https://github.com/mppjuro/PQChat.DHT/commit/8978b6d55c363aa28f35e105fb6d4cbdb9b49970) (2026-10-05) — BEP 44 mutable storage, chunk retrieval and loopback DHT delivery confirmation

## ⚡ Wydajność i Optymalizacje (Performance)

- [`c5f264d`](https://github.com/mppjuro/PQChat.DHT/commit/c5f264dd1b7a411d33b6f3676e33bf7dbc34a446) (2026-10-07) — screen change polling recalculation and resolve compiler and lint warnings
- [`2f01ee2`](https://github.com/mppjuro/PQChat.DHT/commit/2f01ee2280b3721c2ae6e5f098fcc3fd5bfa1f46) (2026-10-07) — DHT message polling with Fast Termination and asynchronous lookahead window

## 📦 Budowanie i Zależności (Build & CI)

- [`5fc983a`](https://github.com/mppjuro/PQChat.DHT/commit/5fc983a2d79c8780183c550c546e1e6229ed6a6f) (2026-10-14) — **deps**: bump org.junit.jupiter:junit-jupiter from 5.10.2 to 6.1.3
- [`6567d93`](https://github.com/mppjuro/PQChat.DHT/commit/6567d934be9a03e6182bf6724beaa591be0b67a3) (2026-10-14) — **deps**: bump org.robolectric:robolectric from 4.14.1 to 4.17
- [`9c34354`](https://github.com/mppjuro/PQChat.DHT/commit/9c34354f117fdff5c004859da974df96b8b67876) (2026-10-14) — **deps**: bump the androidx-and-compose group with 2 updates
- [`5772490`](https://github.com/mppjuro/PQChat.DHT/commit/57724905f2868ace963bc0ec1d40f6e4056c4b90) (2026-10-14) — **deps**: bump softprops/action-gh-release from 2 to 3
- [`237110b`](https://github.com/mppjuro/PQChat.DHT/commit/237110b29501bc22bdd58d7e49e212ef6089b733) (2026-10-14) — **deps**: update numpy requirement in /tools/threat_sim
- [`d25675a`](https://github.com/mppjuro/PQChat.DHT/commit/d25675abc919592ae9470691b10476dbdcf8bd4d) (2026-10-14) — **deps**: bump actions/setup-python from 5 to 7
- [`fd7e1d8`](https://github.com/mppjuro/PQChat.DHT/commit/fd7e1d8886ed59afd559960747647b274f2c11e5) (2026-10-12) — add issue and PR templates, nightly build and release workflows, and changelog automation
- [`44099a7`](https://github.com/mppjuro/PQChat.DHT/commit/44099a746e48e87813dc6e83e99e2227e458d6e3) (2026-10-12) — **dependencies**: updated dependencies in build.gradle.kts to last version
- [`20ff6b5`](https://github.com/mppjuro/PQChat.DHT/commit/20ff6b5b08c45b318902ce610aea5f73171b3a79) (2026-10-12) — **deps**: bump org.jetbrains.kotlinx:kotlinx-coroutines-android
- [`f97204f`](https://github.com/mppjuro/PQChat.DHT/commit/f97204f9f006919943be1e0e377c1dab3207e3c5) (2026-10-12) — **deps**: bump org.jetbrains.kotlinx:kotlinx-coroutines-test
- [`e177df6`](https://github.com/mppjuro/PQChat.DHT/commit/e177df622cb505bf09eeb2156ae9283eabb1c032) (2026-10-12) — **deps**: bump org.junit.vintage:junit-vintage-engine
- [`440d320`](https://github.com/mppjuro/PQChat.DHT/commit/440d320cd57a946ec7005bdf3273ac064ab18839) (2026-10-12) — migrate to AGP 9.4.1 built-in Kotlin, KSP 2.3.12 and Compose compiler plugin
- [`1b2b7ec`](https://github.com/mppjuro/PQChat.DHT/commit/1b2b7ec1d732be681cd59f36102293e1691c2c88) (2026-10-12) — **gradle**: upgrade to Gradle 9.8.1 and enforce Java 17 daemon toolchain
- [`026508f`](https://github.com/mppjuro/PQChat.DHT/commit/026508f7e7502e4b950f35a66a389cb80cc2eb02) (2026-10-12) — **deps**: update matplotlib requirement in /tools/threat_sim
- [`213919f`](https://github.com/mppjuro/PQChat.DHT/commit/213919fbc6ad5c79924d2fc777fef2cf666e1555) (2026-10-12) — **deps**: bump com.google.zxing:core from 3.5.3 to 3.5.4
- [`f5e1d10`](https://github.com/mppjuro/PQChat.DHT/commit/f5e1d10e2ede40f88d472907f5fe9622ff220921) (2026-10-12) — **deps**: bump com.code-intelligence:jazzer-api from 0.23.0 to 0.30.0
- [`fe28be3`](https://github.com/mppjuro/PQChat.DHT/commit/fe28be322fd7b19559fcc430c0e93cace6ef551c) (2026-10-12) — **deps**: bump gradle-wrapper from 8.7 to 9.8.1
- [`a1dfde3`](https://github.com/mppjuro/PQChat.DHT/commit/a1dfde3a324c65f266a60c7c1a17399b1daed146) (2026-10-12) — **deps**: update scipy requirement in /tools/threat_sim
- [`0dac745`](https://github.com/mppjuro/PQChat.DHT/commit/0dac7455e255a820a26cdf9f8b48841757787e22) (2026-10-12) — **deps**: update numpy requirement in /tools/threat_sim
- [`c4e627d`](https://github.com/mppjuro/PQChat.DHT/commit/c4e627d88056908e4a8ed08a45e5adba8aee078f) (2026-10-12) — **deps**: bump actions/upload-artifact from 6 to 7
- [`41de0aa`](https://github.com/mppjuro/PQChat.DHT/commit/41de0aa781e134995e9bcf6a71d717f601a1aa82) (2026-10-12) — **deps**: bump actions/setup-java from 5 to 6
- [`cefaf71`](https://github.com/mppjuro/PQChat.DHT/commit/cefaf717dc5054734c090e04bccfe2416e5cf2ac) (2026-10-12) — **deps**: bump actions/checkout from 5 to 7
- [`abb208d`](https://github.com/mppjuro/PQChat.DHT/commit/abb208d6b392cc6a5ab8155ea2f05bee88d9f805) (2026-10-12) — add dependabot configuration for gradle, github-actions and pip
- [`d0c7247`](https://github.com/mppjuro/PQChat.DHT/commit/d0c72472c5db993e20ee5708dd19f432ace29975) (2026-10-07) — update - emulator OS updated to ubuntu-latest
- [`c0f32e6`](https://github.com/mppjuro/PQChat.DHT/commit/c0f32e6e08efcc6b57224b8d4ab4feb122b793b7) (2026-10-07) — gradle-wrapper.jar and set as exclusion in .gitignore

## 🧪 Testy (Tests)

- [`7be283a`](https://github.com/mppjuro/PQChat.DHT/commit/7be283a006cb59ccd46b7ce039c2cf82d4b90600) (2026-10-08) — fix recovery round budget and initiator roles in testRandomizedLossAndReorderingProperty

## 📚 Dokumentacja (Documentation)

- [`0d4b973`](https://github.com/mppjuro/PQChat.DHT/commit/0d4b973559c1916bb6411210f84b7dd16dbfbda4) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`110ef8c`](https://github.com/mppjuro/PQChat.DHT/commit/110ef8cf1c477dc3b6ed411477ae16ae2ad9a178) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`2253862`](https://github.com/mppjuro/PQChat.DHT/commit/2253862c4db6e3b732969e7a14cfd861caea18b9) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`ef122c3`](https://github.com/mppjuro/PQChat.DHT/commit/ef122c3d13d39dc5b789499bf88389ba04584eaa) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`98dff72`](https://github.com/mppjuro/PQChat.DHT/commit/98dff72e2258f9a74f917adc51a29758cfdc0244) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`7a9048d`](https://github.com/mppjuro/PQChat.DHT/commit/7a9048d5dbe27c59a58c5617b6b1f06bff6af2c7) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`03d285a`](https://github.com/mppjuro/PQChat.DHT/commit/03d285aa704e333ba2de261932c55945b78fef90) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`4e17ed3`](https://github.com/mppjuro/PQChat.DHT/commit/4e17ed3884770ec6d213e62e7dec0848bc4b8130) (2026-10-14) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`62733a7`](https://github.com/mppjuro/PQChat.DHT/commit/62733a79b65dd350753718cc1f0bcbb70bbf12e2) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`dc86a0b`](https://github.com/mppjuro/PQChat.DHT/commit/dc86a0bc62e12b5b49e7c2a86363989cb768534b) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`f9d5f87`](https://github.com/mppjuro/PQChat.DHT/commit/f9d5f87defb26c98dde91d02419917cd1b1012d9) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`99b7e21`](https://github.com/mppjuro/PQChat.DHT/commit/99b7e21e2a9e5c08e69fc274cca4f91aaff467c4) (2026-10-13) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`ea2f14e`](https://github.com/mppjuro/PQChat.DHT/commit/ea2f14e61a67c94a7e24114f3b1ab194f11854f1) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`e532ff7`](https://github.com/mppjuro/PQChat.DHT/commit/e532ff732a58a7243392851d7d653cf325dc30ad) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`5bb55f1`](https://github.com/mppjuro/PQChat.DHT/commit/5bb55f1914ca9001a28210d85da21cfd00868678) (2026-10-12) — **changelog**: auto-update CHANGELOG.md [skip ci]
- [`9219c9c`](https://github.com/mppjuro/PQChat.DHT/commit/9219c9c00f4cadbad8e4df71bd06958e6062a811) (2026-10-12) — README with project details and instructions
- [`6c83661`](https://github.com/mppjuro/PQChat.DHT/commit/6c8366190eafb04307523a25f0d108050187caab) (2026-10-08) — add threat model, DHT correlation simulator, and upgrade CI actions to Node 24

## 🛠️ Pozostałe Zmiany (Other Changes)

- [`f72afdf`](https://github.com/mppjuro/PQChat.DHT/commit/f72afdf13624d4b5780031810e11f6c251dafca4) (2026-10-07) — DhtClient interface, implement FakeDht, isolate integration tests, and add GitHub Actions CI
- [`bc1d1da`](https://github.com/mppjuro/PQChat.DHT/commit/bc1d1da36148c82f091f0440326045a9748bee02) (2026-10-05) — commit
