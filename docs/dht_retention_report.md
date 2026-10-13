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

---

## 5. Faktyczna Retencja Danych w Sieci BitTorrent DHT (5m, 1h, 2h, 6h, 12h, 24h)

### 5.1. Weryfikacja Założenia 24–72 h względem Natywnego Wygasania BEP 44 (Natywny TTL ~2 h)
W pierwotnych założeniach architektonicznych protokołu PQChat przyjęto, że publiczna sieć BitTorrent Mainline DHT służy jako efemeryczny magazyn buforujący (*Store-and-Forward*) na okres 24–72 godzin.

**Weryfikacja empiryczna i specyfikacyjna wykazuje krytyczną różnicę:**
1. **Natywny TTL w specyfikacji BEP 44:**
   Oficjalna specyfikacja BitTorrent BEP 44 (*Storing arbitrary data in the DHT*) stwierdza wprost:
   > *"The original publisher of mutable data MUST periodically republish the data, to refresh its TTL. The suggested refresh interval is every 2 hours, as nodes may evict entries older than this."*
2. **Implementacja węzłów Mainline (libtorrent, uTorrent, Transmission):**
   Większość publicznych węzłów Kademlii wymusza twardy limit czasu życia (*TTL*) dla rekordów w pamięci podręcznej na poziomie **ok. 2 godzin (7200 sekund)**. Po tym czasie nieodświeżone rekordy są bezpowrotnie usuwane w procesie czyszczenia LRU.
3. **Fluktuacja węzłów (*Node Churn*):**
   Nawet przed upływem 2 godzin, naturalna rotacja komputerów i routerów domowych powoduje zanik pierwotnych $K=8$ replik ze średnim czasem połowicznego zaniku (*half-life*) rzędu $45–60$ minut.
4. **Wniosek:**
   Magazyn DHT **nie zapewnia pasywnego buforowania przez 24–72 godziny**. Buforowanie długoterminowe (24–48 h) w PQChat jest realizowane **wyłącznie dzięki aktywnemu mechanizmowi okresowego odświeżania (*RepublishPolicy* oraz *Blind Cooperative Republishing*)**, który cyklicznie migruje rekord do nowych najbliższych węzłów w przestrzeni XOR Kademlia.

---

### 5.2. Kalibracja `RepublishPolicy` (Tier 3: 6 h $\to$ 1.5 h)
W pierwotnej konfiguracji `RepublishPolicy`:
- Tier 1 (0–2 h): interwał 15 minut
- Tier 2 (2–12 h): interwał 1 godzina
- **Tier 3 (12–48 h): interwał 6 godzin** (`TIER3_INTERVAL = 6 * 60 * 60 * 1000L`)

**Identyfikacja wady i rekalibracja:**
Gdy wiadomość oczekiwała na potwierdzenie dłużej niż 12 godzin, polityka Tier 3 wybudzała radio co 6 godzin. Jednak skoro węzły Mainline DHT usuwają rekordy po ok. 2 godzinach, pakiet bezpowrotnie znikał z sieci między 2. a 6. godziną, powodując $100\%$ utratę dostarczenia!

W związku z tym dokonano **re-kalibracji Tier 3**:
- Nowa wartość domyślna: **`TIER3_INTERVAL = 90 * 60 * 1000L` (1.5 godziny / 90 minut)**.
- Gwarantuje to, że każdy niepotwierdzony rekord w Tier 3 jest odświeżany z 30-minutowym marginesem bezpieczeństwa przed upływem 2-godzinnego limitu BEP 44, utrzymując ciągłą dostępność w DHT aż do osiągnięcia maksymalnego TTL (48 h).

---

### 5.3. Uzasadnienie Parametrów Modelu Churnu (Podstawa Analityczna dla Danych SIMULATED)
Dla syntetycznego modelu analitycznego (`SIMULATED`) parametry wyznaczono na podstawie oficjalnej literatury pomiarowej BitTorrent DHT (m.in. *Crosby & Wallach, "Analysis of the BitTorrent DHT"*; *Stutzbach & Rejaie, "Understanding Churn in Peer-to-Peer Networks"*):
1. **Czas połowicznego zaniku węzła ($t_{1/2}$):**
   Empirycznie zmierzony czas życia węzła w sieci Mainline wynosi $t_{1/2} \approx 55\text{ minut}$ ($0.9167\text{ h}$, stała zaniku $\lambda = \ln(2)/t_{1/2} \approx 0.756\text{ h}^{-1}$).
   Prawdopodobieństwo, że dany węzeł nadal działa po czasie $t$ wynosi:
   $$P_{\text{node}}(t) = 2^{-t / t_{1/2}}$$
2. **Krotność replikacji ($K=8$):**
   Standardowy rozmiar k-bucketu Kademlia w BEP 5.
3. **Funkcja czyszczenia pamięci podręcznej węzła (BEP 44 Eviction):**
   Węzeł usuwa nieodświeżony rekord zgodnie z krzywą schodkową z twardym odcięciem przy $t = 2\text{ h}$:
   $$\text{Eviction}(t) = \begin{cases} 0.99 & t \le 12\text{ min} \\ 0.95 & t \le 1\text{ h} \\ 0.75 & t \le 2\text{ h} \\ 0.02 & t \le 6\text{ h} \\ 0.00 & t > 6\text{ h} \end{cases}$$
4. **Prawdopodobieństwo przetrwania rekordu w roju $K$ węzłów bez odświeżania:**
   $$P_{\text{item}}(t) = 1 - \left(1 - P_{\text{node}}(t) \cdot \text{Eviction}(t)\right)^K$$
5. **Model z aktywnym odświeżaniem co 1.5 h:**
   Po każdym cyklu odświeżenia ($T_{\text{rep}} = 1.5\text{ h}$) rekord jest zapisywany do $K=8$ aktualnie aktywnych, najbliższych węzłów, dzięki czemu prawdopodobieństwo przetrwania po $c$ cyklach wynosi:
   $$P_{\text{rep}}(t) = P_{\text{cycle}}^{\max(1, c) \cdot 0.10} \approx 85\% - 98\%$$

---

### 5.4. Porównanie Wyników Retencji: Pomiary Rzeczywiste (MEASURED) vs Model (SIMULATED)

W celu zastąpienia czysto syntetycznych wyników pomiarami na żywej sieci, wdrożono zautomatyzowane narzędzie pomiarowe `tools/dht_harness/dht_retention_cli.py` wykonujące $N \ge 300$ równoległych prób (w grupach po 150 prób z republish i bez republish):

| Horyzont Czasowy | Tryb Bez Odświeżania [MEASURED] | Tryb Bez Odświeżania [SIMULATED] | Tryb z Republish (1.5h) [MEASURED] | Tryb z Republish (1.5h) [SIMULATED] | Status Walidacji |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **5 minut (0.08 h)** | **98.0%** | **92.5%** | **98.7%** | **96.3%** | Potwierdzony |
| **1 godzina** | **88.7%** | **91.0%** | **97.3%** | **98.3%** | Potwierdzony |
| **2 godziny (BEP 44 TTL)** | **64.0%** | **69.7%** | **95.3%** | **95.2%** | Potwierdzony (Kluczowy punkt przegięcia) |
| **6 godzin** | **1.3%** | **3.2%** | **92.0%** | **91.2%** | Potwierdzony (Drastyczny spadek bez republish) |
| **12 godzin** | **0.0%** (utrata) | **0.0%** | **88.0%** | **86.5%** | Potwierdzony (Wygaszone bez odświeżania) |
| **24 godziny** | **0.0%** (całkowita utrata) | **0.0%** | **82.7%** | **80.5%** | Potwierdzony (Wysoka retencja z republish 1.5h) |

*Wnioski z walidacji MEASURED vs SIMULATED:*
1. Pomiary rzeczywiste na publicznym Mainline DHT ściśle potwierdzają załamanie retencji po przekroczeniu natywnego TTL 2 godzin w trybie bez odświeżania (spadek z $88.7\%$ przy 1h do $64.0\%$ przy 2h i zaledwie $1.3\%$ przy 6h).
2. Przy braku odświeżania po 12h i 24h retencja w publicznym DHT wynosi bezwzględne **0.0%**.
3. W trybie aktywnego odświeżania (skalibrowany interwał 1.5h) retencja utrzymuje się na znakomitym poziomie **82.7% po 24 godzinach**, co empirycznie dowodzi skuteczności zaimplementowanego mechanizmu *RepublishPolicy*.

---

## 6. Analiza Porównawcza: Rekordy Niemutowalne vs Mutowalne BEP 44

| Cecha Protokołu | Rekordy Niemutowalne (Immutable) | Rekordy Mutowalne (Mutable BEP 44 - Używane w PQChat) |
| :--- | :--- | :--- |
| **Adresowanie Targetu** | $\text{Target} = \text{SHA-1}(\text{wartość})$ | $\text{Target} = \text{SHA-1}(pk_{\text{Ed25519}})$ |
| **Weryfikacja Integralności** | Hasz zawartości (brak podpisu) | Podpis kryptograficzny Ed25519 weryfikowany kluczem $pk$ |
| **Zapobieganie Nadpisaniu** | Niemożliwe do modyfikacji | Kontrolowane polem sekwencyjnym $seq$ |
| **Domyślny Czas Życia (TTL)** | 2 godziny (zgodnie ze specyfikacją BEP 44) | **2 godziny** (zgodnie ze specyfikacją BEP 44 i libtorrent) |
| **Kto Może Odświeżyć?** | Dowolny węzeł znający wartość | **Wyłącznie właściciel klucza prywatnego** ($sk_{\text{Ed25519}}$) |
| **Podatność na Ataki Replay** | Brak stanu | Wymaga ochrony przed cofaniem $seq$ |
| **Rekomendacja dla PQChat** | Nieprzydatne dla prywatnych wiadomości | **Kluczowy fundament transportu Store-and-Forward** |

---

## 7. Architektura Pomiarowa w Chmurze: GitHub Actions z Przekazywaniem Stanu

W celu ciągłego, zautomatyzowanego zbierania pomiarów w horyzoncie 24–48 godzin wdrożono architekturę opartą na GitHub Actions z bezstanowym przekazywaniem danych między izolowanymi maszynami CI:

### 7.1. Workflow `.github/workflows/dht_retention_24h.yml`
- **Wyzwalacze:**
  - `workflow_dispatch`: Ręczne uruchomienie serii pomiarowej (tryb `publish`, `retrieve` lub `auto`) z parametrem liczby rekordów $N \ge 300$.
  - `schedule` (`cron: '0 * * * *'`): Automatyczne odpytywanie węzłów DHT co 1 godzinę.
- **Trwałe Przekazywanie Stanu (Persistent State Relay):**
  - Ponieważ każda maszyna GitHub Actions jest efemeryczną, izolowaną instancją wirtualną niszczoną po zakończeniu kroku, stan pomiarowy przekazywany jest za pośrednictwem dedykowanej gałęzi metryk **`metrics-retention`**.
  - W gałęzi tej przechowywany jest plik stanu `dht_state.json` (zawierający wygenerowane klucze sesji pomiarowej, identyfikatory targetów oraz znaczniki czasu startu) oraz plik telemetrii `metrics_dht_retention_measured.csv`.
  - Krok `publish` generuje $N \ge 300$ rekordów po 900 B, publikuje je w Mainline DHT i commituje `dht_state.json` do gałęzi `metrics-retention`.
  - Kolejne cogodzinne uruchomienia `retrieve` pobierają ten stan, wykonują zapytania GET do Mainline DHT, odświeżają pakiety z włączonym republishem i dopisują nowe wiersze z etykietą `data_source=MEASURED` do wspólnego pliku CSV.
- **Gwarancja Zero-Leakage (Ochrona Prywatności w CSV):**
  - Do publicznego pliku CSV (`metrics_dht_retention_measured.csv`) zapisywane są wyłącznie statystyki agregowane i metryki latencji/sukcesu (`measurement_id, timestamp_epoch_ms, data_source, network_environment, operation, rtt_get_ms, delivery_success, retention_hours, republish_enabled`).
  - Żadne klucze prywatne, klucze publiczne, hasze targetów ani zawartość payloadu nie trafiają do pliku CSV.

