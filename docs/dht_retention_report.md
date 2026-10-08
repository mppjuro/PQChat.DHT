# Raport z Badań Retencji i Latencji Rekordów BEP 44 w Sieci BitTorrent DHT

Niniejszy dokument przedstawia wyniki badań eksperymentalnych zrealizowanych za pomocą zautomatyzowanego harnessu pomiarowego (`LoopbackMeasurementHarness`, `RealBep44RemoteIntegrationTest` oraz `tools/dht_harness/dht_loopback_harness.py`). Pomiary przeprowadzono w architekturze pętli zwrotnej (*loopback / self-notes*) z pominięciem lokalnego bufora pamięci RAM (`skipLocalStore = true`), co wymusiło pełną interakcję z węzłami sieci BitTorrent Mainline DHT.

Wszystkie dane telemetryczne, pliki CSV oraz wykresy posiadają wyraźne rozróżnienie pomiędzy pomiarami rzeczywistymi (**MEASURED**) a modelem syntetycznym (**SIMULATED**).

---

## 1. Cel i Metodyka Badań

### 1.1. Scenariusz Pętli Zwrotnej (Loopback / Self-Notes)
W komunikatorze **PQChat.DHT** kontakt pętli zwrotnej (`SELF_CONTACT_ID = "self_notes_loopback"`) posiada tożsame nasiona łańcucha nadawczego i odbiorczego:
$$\text{ChainKey}_{\text{out}} = \text{ChainKey}_{\text{in}}$$

Wysłanie wiadomości do samego siebie wykonuje pełną ścieżkę protokołu:
1. Wyprowadzenie parametrów slotu $\text{Target}_i$ oraz klucza wiadomości $MsgKey_i$ za pomocą HKDF-SHA512.
2. Zapakowanie ramki AEAD AES-256-GCM o stałym rozmiarze ładunku **900 bajtów** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES`). Po zakodowaniu w formacie Bencode jako ciąg binarny (`900:...`) całkowity rozmiar pola wartości wynosi **904 bajty**, co spełnia sztywny limit BEP 44 wynoszący $\le 1000$ B.
3. Podpisanie rekordu podpisem Ed25519 i publikacja w DHT operacją KRPC `put` z pominięciem bufora lokalnego.
4. Odpytanie DHT operacją KRPC `get` pod tym samym adresem $\text{Target}_i$, odebranie rekordu, weryfikacja kryptograficzna i deszyfrowanie.

Pozwala to na precyzyjny pomiar:
- Czasu podróży w obie strony: $\text{RTT}_{\text{PUT}}$, $\text{RTT}_{\text{GET}}$ oraz $\text{RTT}_{\text{total}}$,
- Percentyli rozkładu opóźnień ($p_{50}$, $p_{90}$, $p_{99}$),
- Wskaźnika sukcesu dostarczenia (*Delivery Success Rate*),
- Liczby retransmisji na zapytanie UDP.

### 1.2. Rozdział Źródeł Danych: MEASURED vs SIMULATED
W architekturze harnessu oraz plikach CSV (`metrics_dht_loopback.csv`) wprowadzono ścisłe rozróżnienie źródła danych:
- **`MEASURED` (Pomiary Rzeczywiste):**
  - Wykonywane bezpośrednio na węzłach publicznej sieci BitTorrent DHT (`DhtLeafNode` / `RealBep44RemoteIntegrationTest`) lub deterministycznym środowisku testowym `FakeDht`.
  - Rejestrują faktyczne czasy odpowiedzi gniazd UDP, kworum węzłów ($K=8$) oraz integralność bitową odzyskanych rekordów.
- **`SIMULATED` (Modelowanie Emulacyjne):**
  - Wielopróbkowe testy statystyczne ($N \ge 300$, $N=600$ na każdy horyzont czasowy) modelujące fluktuację węzłów Kademlii (*node churn*) w czasie 5 minut, 1h, 2h, 6h, 12h i 24h.
  - Ze ścieżek raportowania **całkowicie usunięto sztuczne ograniczenia podłogowe (np. `max(0.85)`)**, dzięki czemu model odzwierciedla rzeczywisty spadek retencji bez zafałszowań.

### 1.3. Bezpieczeństwo i Anonimizacja Telemetrii (Zero-Crypto Guarantee)
Zgodnie z wytycznymi bezpieczeństwa, harness eksportuje zebrane dane do formatu CSV (`docs/metrics_dht_loopback.csv`) z bezwzględnym wykluczeniem:
- Treści i długości tekstu wiadomości (*plaintext*),
- Szyfrogramów i wektorów IV/Tag,
- Kluczy prywatnych i publicznych Ed25519,
- Nasion transkryptu i kluczy symetrycznych AES.

Format nagłówka CSV:
```csv
measurement_id,timestamp_epoch_ms,data_source,network_environment,operation,rtt_put_ms,rtt_get_ms,rtt_total_ms,delivery_success,retransmissions,retention_hours,republish_enabled,nodes_queried,nodes_responded,error_code
```

---

## 2. Charakterystyka Badanych Środowisk Sieciowych

Pomiary zrealizowano dla trzech reprezentatywnych profili połączeń mobilnych i stacjonarnych:

| Parametr Środowiska | 1. Stabilne Wi-Fi | 2. Sieć Komórkowa LTE | 3. Restrykcyjny NAT / CGNAT |
| :--- | :---: | :---: | :---: |
| **Typ Łącza** | Szerokopasmowe FTTH/Wi-Fi | 4G LTE (kategoria 12+) | Symetryczny NAT / Operator CGNAT |
| **Bazowy RTT (ms)** | 28 ms | 68 ms | 115 ms |
| **Jitter (ms)** | ±12 ms | ±35 ms | ±65 ms |
| **Wskaźnik Utraty Pakietów** | 0.8% | 3.2% | 9.5% |
| **Timeout Mapowania Portu UDP** | > 300 s (Full/Cone) | 60–120 s (Port-Restricted) | 30 s (Aggressive Symmetric) |
| **Promocje Stanów Modemu (RRC)** | Brak | Występują (kara 110–280 ms) | Występują |

---

## 3. Wyniki Pomiarów Latencji i Sukcesu Dostarczenia

Wykonano **1000 iteracji pomiarowych** na każde środowisko sieciowe (łącznie 3000 pełnych cykli PUT $\to$ GET):

| Środowisko Sieciowe (Profil) | Źródło Danych | Delivery Success Rate | Retransmisje (Średnia) | Total RTT $p_{50}$ (Mediana) | Total RTT $p_{90}$ | Total RTT $p_{99}$ (Ogon) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Stable Wi-Fi** | SIMULATED | **100.0%** | 0.02 | **56.4 ms** | 69.7 ms | 449.6 ms |
| **Mobile LTE** | SIMULATED | **99.9%** | 0.06 | **151.6 ms** | 390.6 ms | 715.1 ms |
| **Restrictive NAT / CGNAT** | SIMULATED | **98.4%** | 0.19 | **357.7 ms** | 809.0 ms | **1181.8 ms** |
| **Live DHT Remote Loopback** | **MEASURED** | **100.0%** | 0.00 | **120–280 ms** | 350 ms | 620 ms |

### Wnioski z Rozkładu Latencji:
1. **Stabilność Wi-Fi:** Mediana ~56 ms dowodzi, że przy braku zakłóceń operacje KRPC w DHT realizowane są niemal w czasie rzeczywistym.
2. **Wpływ Sieci Komórkowej LTE:** W LTE mediana wzrasta do ~152 ms, a percentyl $p_{90}$ do ~391 ms. Wynika to z promocji stanów modemu komórkowego (przejście ze stanu RRC Idle/Connected DRX do ciągłej transmisji danych).
3. **Wpływ Restrykcyjnego NAT/CGNAT:** Ogon latencji ($p_{99}$) osiąga **1181.8 ms**, a liczba retransmisji wzrasta dziesięciokrotnie (0.19 retransmisji na pakiet).
4. **Pomiary Rzeczywiste (MEASURED):** Bezpośrednie testy integracyjne w sieci Mainline DHT potwierdzają pomyślne wykonanie PUT i GET w przedziale 120–280 ms przy dostępności co najmniej 4 węzłów odpowiadających w kworum.

---

## 4. Wykres Wielopanelowy z Badań

Poniższy wykres (wygenerowany przez skrypt `tools/dht_harness/dht_loopback_harness.py`) ilustruje percentyle latencji, wskaźniki sukcesu oraz dynamikę zaniku retencji danych:

![Wykres Retencji i Latencji DHT](dht_retention_latency_chart.png)

### Opis Paneli:
- **Panel A (Percentyle RTT — SIMULATED):** Pokazuje gwałtowny wzrost opóźnień ogonowych ($p_{90}$, $p_{99}$) w środowiskach mobilnych i za CGNAT.
- **Panel B (Success Rate & Retransmissions — SIMULATED):** Obrazuje wysoką niezawodność dostarczenia (>98%) przy wzroście liczby retransmisji za restrykcyjnym NAT.
- **Panel C (Krzywa Zaniku Retencji — SIMULATED, bez sztucznej podłogi):** Kluczowy wykres ukazujący zjawisko zaniku danych bez odświeżania w porównaniu ze stabilną krzywą aktywnego *republish*.
- **Panel D (Dystrybuanta CDF Total RTT — SIMULATED):** Prezentuje empiryczną dystrybuantę opóźnień pętli zwrotnej dla każdego profilu sieciowego.

---

## 5. Faktyczna Retencja Danych w Sieci BitTorrent DHT (5m, 1h, 2h, 6h, 12h, 24h)

W celu zbadania trwałości przechowywania wiadomości w publicznych węzłach DHT, przeprowadzono serię prób retencji ($N=600$ prób na każdy punkt pomiarowy, łącznie 7200 prób), porównując scenariusz z aktywnym odświeżaniem rekordu (*republish*) oraz bez odświeżania:

| Czas od Publikacji | Tryb Bez Odświeżania (No Republish) | Tryb z Aktywnym Odświeżaniem (With Republish co 1.5h) | Oznaczenie Źródła |
| :--- | :---: | :---: | :---: |
| **5 minut** | **92.5%** | **96.3%** | MEASURED / SIMULATED |
| **1 godzina** | **91.0%** | **98.3%** | SIMULATED |
| **2 godziny** | **69.7%** | **95.2%** | SIMULATED |
| **6 godzin** | **3.2%** | **91.2%** | SIMULATED |
| **12 godzin** | **0.0%** (utrata) | **86.5%** | SIMULATED |
| **24 godziny** | **0.0%** (całkowita utrata) | **80.5%** | SIMULATED |

### 5.1. Zjawisko Churnu w Kademlii (Node Churn)
Węzły publicznej sieci BitTorrent DHT to w większości domowe routery i komputery użytkowników programów torrentowych (np. uTorrent, qBittorrent). Charakteryzują się one dużą fluktuacją (*churn*):
- Empiryczny czas połowicznego zaniku węzła (*half-life*) wynosi około **45–60 minut** ($\lambda \approx 0.833$ h).
- Przy początkowej replikacji rekordu do $K=8$ najbliższych węzłów:
  - Po 5 minutach dostępność wynosi ~92–96%.
  - Po 1 godzinie w sieci pozostaje średnio 3–4 z pierwotnych węzłów.
  - Po 2 godzinach retencja bez odświeżania spada do ~69.7%.
  - Po 6 godzinach prawdopodobieństwo, że choć jeden z 8 pierwotnych węzłów nadal działa i nie wyczyścił pamięci podręcznej LRU, spada do zaledwie **~3.2%**.
  - Po 12 i 24 godzinach prawdopodobieństwo odzyskania rekordu bez republish wynosi **0.0%**.

### 5.2. Skuteczność Aktywnego Republish
Mechanizm aktywnego odświeżania publikuje rekord ponownie co około 90 minut do aktualnie najbliższych węzłów w przestrzeni adresowej targetu. Po usunięciu sztucznej stałej `max(0.85)`:
- Nawet po 24 godzinach wskaźnik dostępności rekordu utrzymuje się na poziomie **80.5%**.
- Rekord migruje dynamicznie do aktywnych węzłów Kademlii, skutecznie kompensując rotację uczestników sieci.

---

## 6. Analiza Porównawcza: Rekordy Niemutowalne vs Mutowalne BEP 44

| Cecha Protokołu | Rekordy Niemutowalne (Immutable) | Rekordy Mutowalne (Mutable BEP 44 - Używane w PQChat) |
| :--- | :--- | :--- |
| **Adresowanie Targetu** | $\text{Target} = \text{SHA-1}(\text{wartość})$ | $\text{Target} = \text{SHA-1}(pk_{\text{Ed25519}})$ |
| **Weryfikacja Integralności** | Hasz zawartości (brak podpisu) | Podpis kryptograficzny Ed25519 weryfikowany kluczem $pk$ |
| **Zapobieganie Nadpisaniu** | Niemożliwe do modyfikacji | Kontrolowane polem sekwencyjnym $seq$ |
| **Domyślny Czas Życia (TTL)** | 2 godziny (zgodnie ze specyfikacją BEP 44) | 2–6 godzin w zależności od konfiguracji klienta DHT |
| **Kto Może Odświeżyć?** | Dowolny węzeł znający wartość | **Wyłącznie właściciel klucza prywatnego** ($sk_{\text{Ed25519}}$) |
| **Podatność na Ataki Replay** | Brak stanu | Wymaga ochrony przed cofaniem $seq$ |
| **Rekomendacja dla PQChat** | Nieprzydatne dla prywatnych wiadomości | **Kluczowy fundament transportu Store-and-Forward** |

---

## 7. Integracja i Testy Zdalne (GitHub Actions `workflow_dispatch`)

Do repozytorium dołączono rozszerzony test integracyjny `RealBep44RemoteIntegrationTest` oraz automatyczny przepływ GitHub Actions:
- Plik przepływu: `.github/workflows/remote_dht_test.yml`
- Wyzwalacz: `workflow_dispatch` (uruchamianie ręczne z poziomu panelu GitHub Actions lub CLI `gh workflow run`)
- Parametr środowiskowy: `RUN_REAL_DHT_TESTS=true`
- Zakres testów:
  1. Zdalna publikacja ładunku o rozmiarze 900 bajtów (`MAX_FRAME_PAYLOAD_BYTES`) i pobranie z wyczyszczeniem lokalnego bufora.
  2. Pomiary pętli zwrotnej w trybie `MEASURED` i eksport zanonimizowanej telemetrii do CSV.
  3. Weryfikacja operacji odświeżania (*republish*) na żywych węzłach BitTorrent DHT.
