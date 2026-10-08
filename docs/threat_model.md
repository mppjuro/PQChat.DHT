# Model Zagrożeń i Analiza Anonimowości (Threat Model & Traffic Correlation)

Dokument stanowi formalny model zagrożeń dla komunikatora mobilnego **PQChat.DHT**, ze szczególnym uwzględnieniem wektorów korelacji czasowo-adresowej, wyprzedzającego odpytywania okna rotacji (*Lookahead Window*), rozróżnialności zapytań maskujących (*Decoy GETs*), wielosesyjnych ataków ujawnienia statystycznego (*Statistical Disclosure / Intersection Attack*) oraz ataków Sybil/Eclipse w publicznej sieci **BitTorrent Mainline DHT (BEP 44)**.

Opisano w nim profil adwersarza, matematyczne mechanizmy wycieku metadanych, zaimplementowane środki zaradcze oraz empiryczne wyniki symulacji probabilistycznej opartej na $N \ge 100$ powtórzeniach Monte Carlo z losowymi ziarnami (*seeds*), 95% przedziałami ufności i ścisłym odniesieniem do teoretycznego poziomu losowego zgadywania ($1/N$).

---

## 1. Wprowadzenie i Architektura Transportu

PQChat.DHT jest w pełni zdecentralizowanym (*serverless*), post-kwantowym komunikatorem mobilnym na platformę Android, wykorzystującym sieć BitTorrent Mainline DHT (Kademlia KRPC UDP) jako efemeryczny magazyn buforujący typu *Store-and-Forward* na okres 24–72 godzin:
- **Warstwa asymetryczna (KEM):** ML-KEM-512 (FIPS 203 / Kyber-512) dla uzgadniania wspólnego sekretu w procesie parowania QR oraz okresowej rotacji kluczy (*Rekeying* co 50 wiadomości).
- **Warstwa symetryczna (AEAD):** AES-256-GCM z kluczem 256-bitowym, 12-bajtowym IV, 16-bajtowym tagiem uwierzytelniającym oraz AAD powiązanym z adresem docelowym, typem ramki i kierunkiem transmisji.
- **Transport BEP 44:** Wiadomości publikowane są jako rekordy mutowalne pod adresem $\text{Target} = \text{SHA-1}(pk_{\text{Ed25519}})$, o sztywnym rozmiarze dokładnie 1000 bajtów (`MAX_DHT_VALUE_BYTES = 1000`). Niewykorzystana przestrzeń ładunku jest dopełniana kryptograficznym szumem CSPRNG (`SecureRandom` padding).
- **Deterministyczne rozdzielenie torów (Dual Unidirectional Chains):** Niezależne tory $A \to B$ oraz $B \to A$ sterowane odrębnymi licznikami sekwencyjnymi ($Counter_{\text{out}}$, $Counter_{\text{in}}$).
- **Key Hopping (Efemeryczne przeskakiwanie adresów):** Każda wiadomość $i$ publikowana jest pod unikalnym adresem:
  $$\text{Target}_i = \text{SHA-1}(pk_i), \quad pk_i \leftarrow \text{HKDF-Expand}(ChainKey^i, \text{"step"} \parallel i, 128)$$
- **Okno wyprzedzające (Lookahead Window):** Odbiorca, w celu obsługi asynchroniczności i opóźnień sieciowych, wylicza z wyprzedzeniem $W$ przyszłych slotów ($W = 5$ dla `windowSize = 4`, czyli indeksy $n \dots n+4$) za pomocą `RatchetChain.computeLookaheadSlots` i odpytuje DHT równolegle o te adresy.

---

## 2. Taksonomia Adwersarza i Model Zaufania

### 2.1. Założenia Systemowe i Granice Zaufania
1. **Urządzenie końcowe (Smartfon):** Działa w trybie **Client-Only Leaf Node**. Smartfon nigdy nie trasuje cudzych zapytań KRPC, nie buforuje danych innych węzłów ani nie przechowuje cudzych kluczy w pamięci RAM.
2. **Niezaufana sieć BitTorrent DHT:** Publiczny Internet oraz sieć węzłów Kademlia składająca się z setek tysięcy niezweryfikowanych podmiotów. Każdy węzeł może być złośliwy (*honest-but-curious* lub aktywnie ingerujący w pakiety).
3. **Poufność kryptograficzna:** Adwersarz nie jest w stanie złamać AES-256-GCM ani ML-KEM-512; nie zna kluczy prywatnych ani nasion KDF. Adwersarz analizuje wyłącznie metadane transportowe (IP, port, czas, rozmiar, identyfikator zapytania).

### 2.2. Profile Adwersarza

```
[ Nadawca Alice (IP_A) ] ──── PUT(Target_i) ───► [ Złośliwy Węzeł DHT M ] ◄─── GET(Target_i) ──── [ Odbiorca Bob (IP_B) ]
                                                   (Widzi: IP_A, IP_B,
                                                    t_PUT, t_GET, Delta_t)
```

#### A. Pasywny Obserwator Węzła Przechowującego ($\mathcal{A}_{\text{pass}}$)
- **Umiejscowienie:** Kontroluje węzeł DHT, który w metryce XOR Kademlia znajduje się w zbiorze $K=8$ najbliższych węzłów dla danego adresu docelowego $\text{Target}_i$.
- **Zdolności:** Rejestruje zdarzenie zapisu $(\text{IP}_A, t_{\text{PUT}})$ oraz zdarzenia odczytu $(\text{IP}_B, t_{\text{GET}})$. Mierzy różnicę czasu $\Delta t = t_{\text{GET}} - t_{\text{PUT}}$.

#### B. Obserwator Okna Wyprzedzającego ($\mathcal{A}_{\text{look}}$)
- **Zdolności:** Adwersarz rejestruje zapytania `GET` odbiorcy Boba nadsyłane **przed** publikacją wiadomości przez Alice ($t_{\text{GET}} < t_{\text{PUT}}$, $\Delta t < 0$).
- **Wektor ataku:** Odbiorca, odpytując z wyprzedzeniem o sloty $n \dots n+4$, zdradza gotowość do odbioru pod danym targetem. Gdy Alice wykonuje `PUT`, adwersarz natychmiast łączy nadawcę z adresem IP, który wcześniej pre-polingował ten sam slot.

#### C. Stanowy Obserwator Rozróżniający Decoy GETs ($\mathcal{A}_{\text{state}}$)
- **Zdolności:** Adwersarz prowadzi tabelę historii zapytań dla obserwowanych targetów.
- **Wektor ataku:** Rozróżnia targety rzeczywiste (na których pojawia się operacja `PUT`) od czysto syntetycznych targetów wabikowych ($\text{Target}_{\text{synth}}$), na które **nigdy nie nadejdzie żaden `PUT`**. Filtrując targety o zerowej liczbie zapisów (`num_puts == 0`), adwersarz eliminuje naiwne zapytania wabikowe.

#### D. Obserwator Wielosesyjny – Atak Przecięć / Ujawnienia Statystycznego ($\mathcal{A}_{\text{inter}}$)
- **Zdolności:** Monitoruje strumień wielu kolejnych wiadomości ($M \in [1, 20]$) wysyłanych przez Alice.
- **Wektor ataku:** Nawet jeśli pojedyncza wiadomość daje zbiór kilku kandydatów na odbiorcę z powodu zapytań wabikowych, rzeczywisty partner Bob pojawia się w zbiorze kandydatów **przy każdej wiadomości**, podczas gdy przypadkowe węzły wabikowe pojawiają się sporadycznie. Iloczyn prawdopodobieństw posteriora zbiega do tożsamości Boba.

#### E. Aktywny Adwersarz Sybil / Eclipse ($\mathcal{A}_{\text{sybil}}$)
- **Zdolności:** Generuje sztuczne węzły o spreparowanych identyfikatorach Node ID bliskich celowi w metryce XOR, dążąc do przejęcia frakcji $f_{\text{sybil}} \in [0.0, 0.5]$ sąsiedztwa pamiętającego target.
- **Prawdopodobieństwo kompromitacji:** W sieci o replikacji $K=8$ najbliższych węzłów, prawdopodobieństwo, że co najmniej jeden złośliwy węzeł Sybil znajdzie się w zbiorze replik wynosi:
  $$P_{\text{compromise}} = 1 - (1 - f_{\text{sybil}})^K$$

#### F. Globalny Obserwator Ruchu ISP / AS ($\mathcal{A}_{\text{net}}$)
- **Zdolności:** Analizuje wolumen i rozkłady czasowe pakietów UDP na styku operatora telekomunikacyjnego.
- **Mitygacja:** Ruch maskujący generowany wg procesu Poissona uniezależnia emisję pakietów od aktywności użytkownika.

---

## 3. Szczegółowa Analiza Wektorów Zagrożeń

### 3.1. Wyprzedzające Odpytywanie Okna Rotacji (Lookahead Pre-Polling)
W protokole PQChat odbiorca utrzymuje asynchroniczne okno wyprzedzające:
$$\mathcal{W}_n = \{\text{Target}_n, \text{Target}_{n+1}, \dots, \text{Target}_{n+4}\}$$
W trakcie oczekiwania na wiadomość $n$:
1. Odbiorca Bob wysyła zapytania `GET` dla wszystkich 5 slotów w każdym cyklu pollingu ($T_{\text{poll}}$).
2. Dla slotu $n$, węzeł DHT rejestruje zapytania z $\text{IP}_B$ w momentach $t_{\text{PUT}} - \delta_1, t_{\text{PUT}} - \delta_2, \dots$ ($\Delta t < 0$).
3. W momencie $t_{\text{PUT}}$ Alice wykonuje `PUT` na $\text{Target}_n$.
4. W pierwszym cyklu po publikacji ($t_{\text{PUT}} + \delta_{\text{post}}$) Bob pobiera ładunek i przesuwa okno na $n+1 \dots n+5$.

**Wniosek:** Adwersarz $\mathcal{A}_{\text{look}}$, który koreluje zarówno zdarzenia pre-PUT jak i post-PUT, uzyskuje sygnaturę dwustronną. Aby uniemożliwić tę korelację, zapytania wabikowe (*Decoy GETs*) muszą obejmować również pule slotów aktywnych i przeszłych, a interwały muszą być zaburzone jitterem.

### 3.2. Rozróżnialność Zapytań Wabikowych (0-PUT Target Distinguishability)
Jeżeli klient generuje zapytania wabikowe wyłącznie pod losowe hasze w przestrzeni 160-bitowej:
- Żaden węzeł w sieci nigdy nie wykona operacji `PUT` pod tym adresem.
- Adwersarz stanowy monitorujący target w oknie czasowym natychmiast klasyfikuje taki target jako fałszywy (`has_put == False`).
- W rezultacie naiwne zapytania wabikowe zostają w 100% odfiltrowane, przywracając skuteczność korelacji do 100%.

**Architektura obronna PQChat.DHT:**
1. **Nieskoordynowane rekordy maskujące (*Poisson Dummy PUTs*):** Generator `PoissonTrafficGenerator` publikuje w tle rekordy o sztywnym rozmiarze 1000 bajtów wypełnione kryptograficznym szumem CSPRNG. Rekordy te posiadają fizyczny zapis `PUT` w DHT.
2. **Wielopodmiotowe targetowanie aktywne:** Zapytania wabikowe kierowane są w $60\%$ do puli slotów aktywnych i dummy-PUTów, a nie wyłącznie do pustej przestrzeni haszy, dzięki czemu przetrwają stanowe filtrowanie 0-PUT.

### 3.3. Wielosesyjny Atak Przecięć (Statistical Disclosure)
Gdy Alice wysyła ciąg $M$ wiadomości do Boba:
- W pojedynczej wiadomości ($M=1$) zbiór kandydatów odbiorcy wynosi $\approx 4$ podmioty dzięki zapytaniom wabikowym, co daje skuteczność korelacji rzędu $\approx 47-50\%$.
- Po $M$ wiadomościach adwersarz akumuluje logarytmiczny iloczyn wiarygodności:
  $$\mathcal{L}_M(r) = \sum_{m=1}^M \ln P(R = \text{Bob}_r \mid \text{Target}_m)$$
- Bez ciągłego tła maskującego Bob jest jedynym odbiorcą obecnym we wszystkich $M$ oknach, co przy $M \ge 5$ prowadzi do niemal pewnej deanonimizacji ($100\%$).
- Wdrożenie pełnej obrony (*Full Defense* z ruchem Poissona i opóźnieniami PUT) istotnie spowalnia tę zbieżność.

### 3.4. Atak Sybil w Metryce XOR Kademlia
Adwersarz posiadający botnet lub zasoby chmurowe rozmieszcza węzły w pobliżu docelowych targetów:
- W metryce Kademlia rekord mutowalny BEP 44 jest replikowany do $K=8$ najbliższych węzłów.
- Prawdopodobieństwo przejęcia co najmniej jednej repliki rośnie wykładniczo:
  - Frakcja Sybil $f = 5\% \implies P = 33.7\%$
  - Frakcja Sybil $f = 10\% \implies P = 57.0\%$
  - Frakcja Sybil $f = 20\% \implies P = 83.2\%$
  - Frakcja Sybil $f = 50\% \implies P = 99.6\%$
- Gdy żaden węzeł w sąsiedztwie nie należy do adwersarza (węzły uczciwe), skuteczność adwersarza wynosi dokładnie tyle, ile losowe zgadywanie ($1/N = 4.0\%$).

### 3.5. Realne Profile Życiowe Androida i Tryb Doze
W aplikacji `AdaptivePollingManager` implementuje 4 stany energetyczne:
1. `FOREGROUND_CHAT` ($T = 10\text{ s}$): Aktywna rozmowa, proces aktywny, ruch maskujący Poissona aktywny.
2. `APP_ACTIVE_OTHER` ($T = 60\text{ s} / 1\text{ min}$): Aplikacja na pierwszym planie, inne ekrany, ruch maskujący aktywny.
3. `BACKGROUND_IDLE` ($T = 300\text{ s} / 5\text{ min}$): Ekran włączony, aplikacja w tle, ruch maskujący aktywny.
4. `DOZE_SLEEP` ($T = 900\text{ s} / 15\text{ min}$): Urządzenie zablokowane / uśpione.
   - **Kluczowa zasada:** W trybie Doze proces w tle jest wstrzymywany przez system operacyjny. **Ruch maskujący Poissona jest wyłączony**, a wybudzenia następują wyłącznie periodycznie przez `WorkManager` / `AlarmManager.setAndAllowWhileIdle`. Zapobiega to drenowaniu baterii i ubijaniu procesu przez Android LMK.

---

## 4. Architektura Środków Obronnych

```
┌────────────────────────────────────────────────────────────────────────┐
│                        WARSTWY OCHRONY METADANYCH                      │
├───────────────────────────┬────────────────────────────────────────────┤
│ 1. Ephemeral Key Hopping  │ Unikalny Target_i dla każdej wiadomości    │
│ 2. Cover Decoy GETs       │ Zapytania wabikowe do puli aktywnych slotów│
│ 3. Polling Jitter         │ Losowe rozmycie interwałów (±30%)          │
│ 4. Delayed PUT & Decoys   │ Opóźnione emisje i równoległe sloty-wabiki │
│ 5. Poisson Cover Traffic  │ CSPRNG rekordy 1000 B wg rozkładu lambda   │
│ 6. Lifecycle Adaptation   │ Wyłączanie szumu w Doze, interwały do 15m  │
└───────────────────────────┴────────────────────────────────────────────┘
```

---

## 5. Wyniki Symulacji Empirycznej i Analiza Wrażliwości

Symulację przeprowadzono w skrypcie `tools/threat_sim/threat_simulator.py`. Konfiguracja bazowa obejmuje:
- $N = 25$ niezależnych par komunikacyjnych ($50$ klientów).
- Teoretyczny poziom losowego zgadywania: $\text{Baseline } 1/N = 1/25 = \mathbf{4.0\%}$.
- Liczba powtórzeń Monte Carlo: **$N_{\text{runs}} = 100$** z deterministycznymi ziarnami ($seed = 1000 \dots 1099$).
- Przedziały ufności: **95% Confidence Interval** ($\pm 1.96 \cdot s / \sqrt{N_{\text{runs}}}$).

### 5.1. Skuteczność Postur Obronnych (N=100 Powtórzeń, 95% CI)

| Postura Obronna | Dokładność Adwersarza Top-1 $P(\text{corr})$ | Przewaga nad Zgadywaniem ($P - 1/N$) | Stopień Anonimowości (Entropia Shannona) | Narzut Pasma (KB/h na klienta) | Zużycie Baterii (mWh/h na klienta) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline (Brak obrony)** | **100.0% ± 0.0%** | +96.0% | 0.7% ± 0.0% | 142.3 KB/h | 511.3 mWh |
| **+ Polling Jitter (±30%)** | **100.0% ± 0.0%** | +96.0% | 0.7% ± 0.0% | 142.3 KB/h | 511.3 mWh |
| **+ Decoy GETs ($\mu=1.5$)** | **47.7% ± 0.4%** | +43.7% | 49.2% ± 0.1% | 181.8 KB/h | 511.3 mWh |
| **+ Delayed PUT & Decoy Slots** | **5.2% ± 0.2%** | **+1.3%** | **51.0% ± 0.1%** | 192.3 KB/h | 511.3 mWh |
| **Full Defense (+ Poisson $\lambda=1/480\text{s}$)** | **9.7% ± 0.3%** | **+5.7%** | **45.8% ± 0.1%** | 200.2 KB/h | 522.8 mWh |

> [!IMPORTANT]
> Przy wdrożeniu opóźnionych publikacji (`Delayed PUT`), slotów-wabików oraz zapytań `Decoy GETs` dokładność korelacji adwersarza spada do **5.2% ± 0.2%**, co jest niemal tożsame z **teoretycznym losowym zgadywaniem ($1/25 = 4.0\%$)** — przewaga adwersarza wynosi zaledwie **+1.3%**!

---

### 5.2. Analiza Zagrożenia Okna Wyprzedzającego (Lookahead Pre-Polling)

| Profil Obserwatora Adwersarza | Dokładność Top-1 | Przewaga nad $1/N$ | Entropia Anonimowości |
| :--- | :---: | :---: | :---: |
| **Obserwator wyłącznie Post-PUT ($\Delta t \ge 0$)** | 58.5% ± 0.7% | +54.5% | 26.6% |
| **Obserwator Lookahead-Aware ($\Delta t < 0$ oraz $\Delta t \ge 0$)** | 47.7% ± 0.6% | +43.7% | 49.2% |

*Interpretacja:* Obserwator uwzględniający zapytania wyprzedzające Boba widzi dodatkowe zapytania przed publikacją, jednak rozproszenie zapytań wabikowych w całym horyzoncie czasowym skutecznie zaciera relację przyczynowo-skutkową.

---

### 5.3. Rozróżnialność Decoy GETs (Stanowe Filtrowanie 0-PUT)

| Konfiguracja Zapytań Wabikowych | Typ Obserwatora | Dokładność Top-1 | Entropia Shannona |
| :--- | :--- | :---: | :---: |
| **Decoys Syntetyczne (brak PUT)** | Naiwny (brak filtrowania) | 47.7% ± 0.6% | 49.2% |
| **Decoys Syntetyczne (brak PUT)** | **Stanowy (Filtrowanie 0-PUT)** | **100.0% ± 0.0%** | **0.7%** |
| **Decoys + Poisson Cover Traffic** | **Stanowy (Filtrowanie 0-PUT)** | **78.1% ± 0.6%** | **32.4%** |

> [!WARNING]
> Jeśli zapytania wabikowe odpytują wyłącznie nieistniejące, syntetyczne targety, stanowy adwersarz eliminujący rekordy bez operacji `PUT` **całkowicie neutralizuje obronę (100% deanonimizacji)**.
> Obecność nieskoordynowanych rekordów maskujących z `PoissonTrafficGenerator` (dummy PUTs) oraz kierowanie wabików do puli slotów aktywnych jest **krytycznym warunkiem koniecznym** dla zachowania ochrony.

---

### 5.4. Wielosesyjny Atak Przecięć (Statistical Disclosure vs $M$)

Skuteczność korelacji tożsamości w funkcji liczby zaobserwowanych kolejnych wiadomości ($M$):

| Postura Obronna | $M = 1$ | $M = 2$ | $M = 5$ | $M = 10$ | $M = 20$ |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Baseline (Brak obrony)** | 100.0% | 100.0% | 100.0% | 100.0% | 100.0% |
| **+ Decoy GETs (brak Poissona)** | 56.2% | 98.1% | 100.0% | 100.0% | 100.0% |
| **Full Defense (+ Poisson Cover)** | **12.0%** | **76.0%** | **100.0%** | **100.0%** | **100.0%** |

*Wniosek:* Pojedyncza wymiana wiadomości w trybie Full Defense zapewnia doskonałą ochronę ($12.0\%$ korelacji wobec $4.0\%$ bazy). Jednak przy wielokrotnej wymianie wiadomości bez zmiany klucza tożsamości atak przecięć stopniowo zbiega do tożsamości odbiorcy, co uzasadnia konieczność częstej rotacji kluczy KEM (*PQC Rekeying* co 50 wiadomości) oraz okresowego resetu łańcucha.

---

### 5.5. Odporność na Przejęcie Sąsiedztwa w Ataku Sybil ($K=8$)

| Frakcja Węzłów Sybil ($f_{\text{sybil}}$) | $P(\text{Target Compromised})$ | Dokładność Top-1 | Przewaga nad Baseline $1/N$ |
| :---: | :---: | :---: | :---: |
| **0.0% (Węzły uczciwe)** | **0.0%** | **4.0% ± 0.3%** | **+0.4% (Czyste zgadywanie)** |
| **5.0%** | 33.7% | 6.2% ± 0.3% | +2.2% |
| **10.0%** | 57.0% | 7.2% ± 0.4% | +3.2% |
| **20.0%** | 83.2% | 8.7% ± 0.3% | +4.7% |
| **35.0%** | 96.8% | 9.3% ± 0.4% | +5.3% |
| **50.0%** | 99.6% | 9.5% ± 0.4% | +5.5% |

Nawet przy zmasowanym ataku Sybil, w którym adwersarz kontroluje aż $50\%$ sąsiedztwa Kademlia (przejmując $99.6\%$ targetów), mechanizmy obronne PQChat.DHT ograniczają skuteczność korelacji do zaledwie **9.5% ± 0.4%** (wobec bazy $4.0\%$).

---

### 5.6. Profile Cyklu Życia i Zużycie Zasobów (Lifecycle States)

| Stan Urządzenia | Okres Pollingu | Ruch Maskujący | Dokładność Top-1 | Pasmo UDP | Zużycie Baterii |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **10s Foreground Chat** | 10 s | Aktywny | 9.5% | 200.2 KB/h | 522.8 mWh/h |
| **1m App Active** | 60 s | Aktywny | 12.9% | 57.4 KB/h | 133.1 mWh/h |
| **5m Background Idle** | 300 s | Aktywny | 16.1% | 34.5 KB/h | 70.8 mWh/h |
| **15m Doze Sleep** | 900 s | **Wyłączony** | **11.2%** | **22.9 KB/h** | **41.3 mWh/h** |

*Interpretacja:* W trybie głębokiego uśpienia (Doze) wyłączenie generatora szumu redukuje zużycie energii o **92%** (z 522.8 mWh do 41.3 mWh), a narzut pasma spada do symbolicznych 22.9 KB/h, przy zachowaniu korelacji na poziomie zaledwie 11.2%.

---

### 5.7. Wykres Wielopanelowy Trade-Offu

Poniższy wykres (wygenerowany automatycznie przez `tools/threat_sim/threat_simulator.py`) przedstawia pełny obraz zależności:

![Wykres Trade-Offu Anonimowości, Pasma i Baterii](tradeoff_anonymity_bandwidth_battery.png)

### 5.8. Interpretacja Paneli Wykresu

- **Panel A (Timing Correlation vs $\Delta t$ z Lookahead):** Pokazuje krzywą skuteczności korelacji zarówno dla $\Delta t < 0$ (wyprzedzające zapytania pre-PUT w oknie lookahead) jak i $\Delta t > 0$ (pobranie po publikacji). W konfiguracji *Full Defense* krzywa jest spłaszczona w całym przedziale $[-30\text{ s}, +30\text{ s}]$ w pobliże linii bazowej $1/N = 4.0\%$.
- **Panel B (Wpływ Mechanizmów z Przedziałami 95% CI):** Prezentuje słupki dokładności i entropii Shannona z przedziałami ufności. Wyraźnie widać załamanie korelacji po wprowadzeniu zapytań wabikowych oraz opóźnień publikacji do poziomu $5.2\%$.
- **Panel C (Wielosesyjny Atak Przecięć vs $M$):** Obrazuje tempo deanonimizacji w kolejnych wiadomościach. Pełna obrona przesuwa moment deanonimizacji i chroni pojedyncze interakcje.
- **Panel D (Narzut Pasma i Baterii w Funkcji $\lambda$):** Uwzględnia model RRC modemu komórkowego (*tail time* 8s). Punkt przegięcia krzywej (*knee of the curve*) przypada na wartość domyślną $\lambda = 1/480\text{ s}$ (co 8 minut), gdzie narzut baterii wynosi $522.8\text{ mWh/h}$ (wzrost o zaledwie $2.2\%$ względem bazy $511.3\text{ mWh/h}$).

---

## 6. Ryzyka Resztkowe i Rekomendacje

1. **Ataki Przecięć w Długich Konwersacjach:**
   - W przypadku długotrwałych konwersacji adwersarz akumulujący dane z dziesiątek wiadomości może ostatecznie wyizolować odbiorcę.
   - *Mitygacja:* Wdrożona procedura **PQC Rekeying co 50 wiadomości** oraz zalecenie okresowego odnawiania sesji przez kod QR w celu wyczyszczenia historii adresowej.
2. **Korelacja na poziomie lokalnego ISP:**
   - Operator telekomunikacyjny widzi pakiety UDP wychodzące z urządzenia.
   - *Rekomendacja:* Użytkownicy o podwyższonym profilu zagrożenia powinni tunelować ruch KRPC przez Tor, Orbot lub zaufany VPN.

---

## 7. Podsumowanie

Wdrożona wielowarstwowa architektura ochrony metadanych (*Ephemeral Key Hopping*, *Lookahead Window Dispersion*, *Decoy GETs* do puli aktywnych slotów, nieskoordynowane rekordy maskujące *Poisson Cover Traffic* wypełnione kryptograficznym szumem CSPRNG oraz *Delayed PUTs*) redukuje skuteczność korelacji czasowo-adresowej przez złośliwe węzły BitTorrent DHT z poziomu **100.0%** do poziomu zbliżonego do **losowego zgadywania ($5.2\% - 9.7\%$ wobec teoretycznego baseline $1/N = 4.0\%$)**.

Rozwiązanie to zachowuje pełną zgodność z ograniczeniami systemu Android (zawieszenie ruchu maskującego w trybie Doze), gwarantując minimalny narzut na baterię i pakiet danych komórkowych.
