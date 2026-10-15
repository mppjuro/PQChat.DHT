# Metodologia i Warunki Pomiarów Telemetrii BitTorrent Mainline DHT (BEP 44)

Niniejszy katalog zawiera surowe dane telemetryczne w formacie CSV oraz dokumentację metodologii pomiarów latencji i retencji rekordów w publicznej sieci BitTorrent Mainline DHT, zebranych za pomocą modułu `LoopbackMeasurementHarness` oraz testu integracyjnego `RealDhtLoopbackMeasurementTest`.

---

## 1. Warunki Pomiarowe (Testbed Context)

* **Data i Czas Pomiaru:** Październik 2026 r., strefa czasowa UTC / CEST (Central European Summer Time).
* **Region Geograficzny:** Europa Środkowa (Polska), węzeł końcowy w sieci szerokopasmowej FTTH o wysokiej stabilności.
* **Publiczne Węzły Bootstrap BitTorrent Mainline DHT:**
  - `router.bittorrent.com:6881`
  - `dht.transmissionbt.com:6881`
  - `router.utorrent.com:6881`
  - `dht.aelitis.com:6881`
  - `dht.libtorrent.org:25401`
* **Aktywny Rój DHT:** Węzeł liściowy (`DhtLeafNode`) utrzymuje aktywny kontakt z ponad 140–180 węzłami publicznymi Kademlia w przestrzeni identyfikatorów 160-bitowych (SHA-1).

---

## 2. Profile Badanych Środowisk Sieciowych

Pomiary wykonano w trzech zróżnicowanych profilach sieciowych:

1. **WIFI (`Wi-Fi (Stable)`):**
   - Połączenie stacjonarne FTTH przez Wi-Fi 6 (802.11ax).
   - Niski jitter (±12 ms), minimalna strata pakietów (<0.8%), brak ograniczeń czasowych tablicy NAT (timeout > 300 s).
2. **LTE (`Mobile LTE`):**
   - Emulacja charakterystyki interfejsu sieci komórkowej 4G/5G.
   - Wpływ promocji stanów modemu radiowego RRC (Radio Resource Control), zmienny RTT (±35 ms jitter) oraz podwyższony współczynnik strat UDP.
3. **RESTRICTIVE_NAT (`Restrictive NAT/CGNAT`):**
   - Emulacja środowiska z symetrycznym NAT lub restrykcyjnym CGNAT operatora komórkowego.
   - Krótkie czasy wygasania mapowania portów UDP (30 s), podwyższony jitter (±65 ms) oraz konieczność retransmisji zapytań KRPC.

---

## 3. Metodologia Pomiarowa

### 3.1. Architektura Pętli Zwrotnej (Self-Notes Loopback)
Każda iteracja `runLoopbackIteration`:
1. Generuje jednorazowe ziarno efemeryczne (32 bajty CSPRNG) i parę kluczy Ed25519 $`(pk_i, sk_i)`$.
2. Oblicza docelowy adres w przestrzeni DHT: $`\text{Target}_i = \text{SHA-1}(pk_i)`$.
3. Przygotowuje ładunek testowy o **sztywnym rozmiarze dokładnie 900 bajtów** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES`).
   - W formacie Bencode ładunek kodowany jest jako `"900:"` + 900 B = **904 bajty**, co spełnia sztywny limit BEP 44 ($`\le 1000`$ B).
4. Wykonuje operację `putMutable` z flagą **`skipLocalStore = true`**, co uniemożliwia odczyt z lokalnej pamięci podręcznej RAM i wymusza wysłanie zapytania KRPC do węzłów w sieci publicznej.
5. Po zapisaniu pobiera rekord operacją `getMutable` (`skipLocalStore = true`), weryfikuje podpis Ed25519 oraz zgodność bitową ładunku.
6. Mierzy czasy $`\text{RTT}_{\text{PUT}}`$, $`\text{RTT}_{\text{GET}}`$, $`\text{RTT}_{\text{TOTAL}}`$ oraz weryfikuje kworum odpowiadających węzłów.

### 3.2. Badanie Retencji Danych (Retention Scenarios)
Ewaluacja scenariuszy retencji `evaluateRetentionScenarios`:
* Horyzonty czasowe: **1h, 2h, 6h, 24h**.
* Warianty:
  - **Bez odświeżania (`republish = false`):** Zapis rekordu pod `seq = DEFAULT_MUTABLE_SEQ` i badanie jego dostępności po upływie czasu.
  - **Z aktywnym odświeżaniem (`republish = true`):** Symulacja mechanizmu `RepublishPolicy` z odświeżeniem pod `seq = DEFAULT_MUTABLE_SEQ + 1` przed upływem natywnego TTL BEP 44 (2 h).

---

## 4. Gwarancje Prywatności i Anonimizacji (Zero-Crypto Guarantee)

Wszystkie pliki CSV w niniejszym katalogu podlegają rygorystycznym regułom bezpieczeństwa:
* **Zero Plaintext:** Żadna treść wiadomości ani długość tekstu użytkownika nie jest rejestrowana.
* **Zero Cryptographic Keys:** Żadne klucze prywatne, klucze publiczne ani nasiona Ed25519/KEM nie są zapisywane w logach ani plikach CSV.
* **Czysta Telemetria Sieciowa:** Zapisywane są wyłącznie statystyki czasowe pakietów, kody błędów transportowych oraz flagi logiczne sukcesu dostarczenia.

---

## 5. Struktura Plików Telemetrycznych

* `loopback_wifi.csv` — Surowe pomiary dla środowiska Wi-Fi (100 iteracji).
* `loopback_lte.csv` — Surowe pomiary dla środowiska LTE (100 iteracji).
* `loopback_restrictive_nat.csv` — Surowe pomiary dla środowiska Restrictive NAT (100 iteracji).
* `loopback_all.csv` — Zbiorczy plik łączący pomiary ze wszystkich środowisk (300 iteracji).
* `retention_measured.csv` — Wyniki prób retencji dla horyzontów 1h, 2h, 6h i 24h.

Format nagłówka RFC 4180:
```csv
measurement_id,timestamp_epoch_ms,data_source,network_environment,operation,rtt_put_ms,rtt_get_ms,rtt_total_ms,delivery_success,retransmissions,retention_hours,republish_enabled,nodes_queried,nodes_responded,error_code
```
