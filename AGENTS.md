# AGENTS.md — Wytyczne Architektoniczne i Implementacyjne dla Agentów AI

Niniejszy plik definiuje specyfikację techniczną, model kryptograficzny, architekturę kodu oraz zasady implementacji dla zdecentralizowanego, post-kwantowego komunikatora mobilnego na platformę Android. Każdy agent AI pracujący w tym repozytorium jest zobowiązany do bezwzględnego przestrzegania poniższych wytycznych.

---

## 1. Przegląd Projektu i Filozofia Architektury

Projekt to w pełni zdecentralizowany (serverless), odporny na cenzurę i chroniący metadane komunikator mobilny na system Android, wykorzystujący publiczną sieć **BitTorrent Mainline DHT (BEP 44)** jako efemeryczny magazyn buforujący (Store-and-Forward) na okres 24–72 godzin.

### Główne Filary:
1. **Zero Centralizacji:** Brak jakichkolwiek serwerów pośredniczących, brokerów push (brak FCM/APNs) oraz stałych adresów IP/kont.
2. **Ochrona Metadanych (Metadata-Free Rendezvous):** Obserwator sieciowy ani węzły DHT nie są w stanie powiązać nadawcy z odbiorcą, określić faktu prowadzenia rozmowy ani zmierzyć częstotliwości wymiany wiadomości.
3. **Odporność Post-Kwantowa (PQC):** Ochrona przed atakiem *Harvest Now, Decrypt Later* za pomocą algorytmów standaryzowanych przez NIST (FIPS 203).
4. **Tryb Klienta Liścia (Client-Only / Leaf Node):** Smartfon nigdy nie trasuje cudzych zapytań ani nie buforuje danych innych użytkowników w RAM; jest wyłącznie inicjatorem efemerycznych zapytań UDP.

---

## 2. Stos Technologiczny

* **Język główny i wyłączny:** Kotlin (100% kodu aplikacji, sieci UDP KRPC DHT, Bencode, kryptografii, UI i serwisów tła — brak warstwy C++/JNI).
* **Interfejs UI:** Jetpack Compose + Material 3.
* **Baza danych:** Room (SQLite) z szyfrowaniem wrażliwych pól kluczem z Android Keystore.
* **Wielowątkowość:** Kotlin Coroutines (`Dispatchers.IO`, `Dispatchers.Default`) + Flow.
* **Praca w tle:** AndroidX WorkManager (zadania periodyczne) + Foreground Service (dla aktywnego czatu) + AlarmManager (`setAndAllowWhileIdle` dla trybu Doze).
* **Biblioteka kryptograficzna:** Bouncy Castle Java/Kotlin PQC Provider (`org.bouncycastle:bcprov-jdk18on`) + natywne API Androida `javax.crypto` (dla AES-GCM).

---

## 3. Specyfikacja Kryptograficzna

| Komponent | Standard / Algorytm | Zastosowanie |
| :--- | :--- | :--- |
| **KEM (Handshake & Rekey)** | Hybrydowy X25519 + ML-KEM-512 (FIPS 203 + RFC 7748) | Asymetryczne uzgadnianie wspólnego sekretu ($pk=832\text{ B}$, $ct=800\text{ B}$, $SS=32\text{ B}$) |
| **Szyfrowanie ładunku (AEAD)** | AES-256-GCM | Szyfrowanie symetryczne wiadomości (Klucz: 32 B, IV: 12 B, Tag: 16 B) |
| **Wyprowadzanie kluczy (KDF)** | HKDF-SHA512 (RFC 5869) | Derywacja łańcuchów kluczy, ziaren slotów i kluczy AES |
| **Wymóg transportowy DHT** | Ed25519 (RFC 8032) | Wymagany przez BEP 44 podpis węzła (używany wyłącznie jako **jednorazowy token efemeryczny**) |

### Deterministyczne Rozdzielenie Torów (Dual Unidirectional Chains):
Każdy kontakt posiada dwa niezależne łańcuchy sterowane odrębnymi licznikami:
* **Tor $A \to B$:** Alice inkrementuje $Counter_{out}$, Bob inkrementuje $Counter_{in}$.
* **Tor $B \to A$:** Bob inkrementuje $Counter_{out}$, Alice inkrementuje $Counter_{in}$.

Wysłanie wiadomości przez jedną stronę **nigdy** nie wpływa na numerację ani adresowanie w torze przeciwnym.

---

## 4. Specyfikacja Binarna Rekordów DHT (BEP 44 Value)

Każdy pakiet binarny ('v') zapisywany w DHT ma **sztywny rozmiar dokładnie 900 bajtów** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES = 900`). Wszelkie wolne bajty są wypełniane kryptograficznie bezpiecznym szumem (`CryptoUtils.secureRandomBytes`).

### Uzasadnienie rozmiaru 900 B i zgodność ze specyfikacją BEP 44:
Zgodnie ze specyfikacją BitTorrent BEP 44, całkowity rozmiar pola wartości `'v'` po zakodowaniu formatem Bencode **nie może przekraczać 1000 bajtów**:
* Format Bencode koduje ciąg bajtów jako `<długość>:<dane>`.
* Dla surowego ładunku 900 bajtów zakodowany ciąg wynosi `"900:"` (4 bajty prefiksu) + 900 bajtów danych = **dokładnie 904 bajty**, co spełnia sztywny limit BEP 44 ($\le 1000$ B).
* **Uwaga krytyczna:** Gdyby surowy ładunek miał 1000 bajtów, jego zakodowana postać Bencode wynosiłaby `"1000:"` (5 bajtów prefiksu) + 1000 bajtów danych = **1005 bajtów**, co **przekracza dopuszczalny limit BEP 44** i skutkuje natychmiastowym odrzuceniem pakietu przez publiczne węzły sieci BitTorrent DHT!

```
+───────────────────────────────────────────────────────────────────────────────+
|                   REKORD BEP 44 VALUE (SZTYWNE 900 BAJTÓW)                    |
+────────────┬─────────────┬────────────────────────────────────────────────────+
| IV (Nonce) |  AEAD Tag   |              SZYFROWANY ŁADUNEK                    |
|  12 bajtów |  16 bajtów  |                 872 bajty                          |
+────────────┴─────────────┴──────────────────┬──────────────────┬──────────────+
                           | Nagłówek (13 B)  |   Dane Typu      | CSPRNG Szum  |
                           +──────────────────┴──────────────────┴──────────────+
```

### Nagłówek wewnętrzny ładunku (Plaintext Header – 13 bajtów):
1. `MsgType` (1 bajt):
   * `0x01` – Handshake Online Finalize
   * `0x02` – Standardowa wiadomość tekstowa
   * `0x03` – PQC Rekey Offer (Nowy klucz publiczny)
   * `0x04` – PQC Rekey Response (Kryptogram potwierdzenia)
   * `0x05` – Segment transferu blokowego (Chunk)
   * `0x06` – Kontrola grupy (`TYPE_GROUP_CONTROL`: Invite, Rekey, Leave)
2. `SeqNum` (2 bajty, UInt16 Big-Endian): Licznik $`Counter_{out}`$ nadawcy.
3. `AckNum` (2 bajty, UInt16 Big-Endian): Ostatnio odebrany numer sekwencyjny partnera.
4. `TimestampUTC` (8 bajtów, Int64 Big-Endian): Czas uniksowy nadania w milisekundach.

### Dedykowane formaty wewnętrzne (przestrzeń 859 bajtów po odliczeniu nagłówka 872 - 13):

* **Typ 0x01 (Handshake Finalize):**
  * `Hybrid Ciphertext`: 800 bajtów (768 B ML-KEM-512 ct + 32 B X25519 eph pk)
  * `Salt`: 24 bajty
  * `Key Confirmation Tag`: 32 bajty
  * `CSPRNG Padding`: 3 bajty (859 - 856)
* **Typ 0x02 (Tekst):**
  * `TextLength` ($`L`$): 2 bajty (UInt16, wartość $`\le 857`$)
  * `UTF-8 Payload`: $`L`$ bajtów (maksymalnie 857 bajtów tekstu)
  * `CSPRNG Padding`: $`857 - L`$ bajtów
* **Typ 0x03 (PQC Rekey Offer):**
  * `RekeyEpoch`: 4 bajty (UInt32)
  * `Combined PublicKey`: 832 bajty (800 B ML-KEM-512 + 32 B X25519)
  * `CSPRNG Padding`: 23 bajty (859 - 836)
* **Typ 0x04 (PQC Rekey Response):**
  * `RekeyEpoch`: 4 bajty (UInt32)
  * `Hybrid Ciphertext`: 800 bajtów (768 B ML-KEM-512 ct + 32 B X25519)
  * `CSPRNG Padding`: 55 bajtów (859 - 804)
* **Typ 0x05 (Chunk Transfer – np. PNG):**
  * `TransferID`: 16 bajtów (UUID transferu)
  * `ChunkIndex`: 2 bajty (UInt16)
  * `TotalChunks`: 2 bajty (UInt16)
  * `ChunkLength` ($`C`$): 2 bajty (UInt16, wartość $`\le 837`$)
  * `BinaryData`: $`C`$ bajtów
  * `CSPRNG Padding`: $`837 - C`$ bajtów
* **Typ 0x06 (Group Control – ramka kontrolna grupy):**
  * `ControlSubType`: 1 bajt (`0x01` – `GROUP_SUBTYPE_INVITE`, `0x02` – `GROUP_SUBTYPE_REKEY`, `0x03` – `GROUP_SUBTYPE_LEAVE`)
  * `GroupID`: 16 bajtów (UUID grupy)
  * `GroupEpoch`: 4 bajty (UInt32 Big-Endian)
  * `SenderMemberID`: 16 bajtów (UUID nadawcy w grupie)
  * `SenderGroupChainKey`: 64 bajty (bieżący łańcuch nadawcy grupy)
  * `CurrentCounter`: 4 bajty (UInt32 Big-Endian)
  * `GroupNameLength` ($`N`$): 2 bajty (UInt16, wartość $`\le 64`$)
  * `GroupName`: $`N`$ bajtów UTF-8 (maksymalnie 64 bajty)
  * `MemberCount` ($`M`$): 2 bajty (UInt16, liczba uczestników, wartość $`\le 64`$)
  * `Members`: tablica $`M`$ wpisów: `MemberID` (16 B) + `NameLen` (1 B) + `MemberName` (do 32 B UTF-8)
  * `CSPRNG Padding`: wypełnienie do 859 bajtów.

### Czaty Grupowe i Tabele Bazy Danych (`groups` i `group_members`):
* **Model Dystrybucji i Adresowania:** Każdy uczestnik posiada własny łańcuch nadawczy ($`myChainKeyOut`$). Wiadomości grupowe nadawane są na indywidualne sloty odbiorców:
  $`\text{Target}_{slot} = \text{RatchetChain.deriveGroupRecipientSlot}(ChainKey, Counter, GroupID, SenderMemberID, RecipientMemberID)`$
  co całkowicie eliminuje korelację obserwatorów (Group Follower Correlation).
* **Wiązanie AAD:** Szyfrowanie ładunku grupowego AEAD AES-256-GCM wiąże kontekst:
  $`AAD = \text{Target} \parallel GroupID \parallel SenderMemberID`$
  co uniemożliwia podmianę nadawcy, grupy lub slotu docelowego.
* **Rotacja Automatyczna Nadawcy:** Następuje automatycznie co 50 wysłanych wiadomości grupowych (`GROUP_REKEY_MESSAGE_INTERVAL = 50`), generując świeży 64-bajtowy klucz CSPRNG, nową epokę $`groupEpoch + 1`$, zerując licznik wyjściowy i transmitując ramkę Typu `0x06` (`GROUP_SUBTYPE_REKEY`) do wszystkich aktywnych członków.
* **Wymuszona Rotacja Klucza przy Odejściu Członka (Forward Secrecy & PCS):** Po odebraniu ramki `GROUP_SUBTYPE_LEAVE` od dowolnego członka grupy następuje natychmiastowe oznaczenie wychodzącego członka jako nieaktywnego (`isActive = 0`), rotacja własnego klucza $`myChainKeyOut`$ do nowej epoki $`groupEpoch + 1`$ oraz rozesłanie ramki `GROUP_SUBTYPE_REKEY` wyłącznie do pozostałych, aktywnych członków grupy. Wyklucza to wychodzącego członka z dostępu do jakichkolwiek przyszłych wiadomości (Post-Compromise Security / Post-Leave Secrecy), chroniąc jednocześnie wiadomości przeszłe (Forward Secrecy).
* **Tabela `groups`:**
  * `groupId` (TEXT, PRIMARY KEY, UUID), `groupName` (TEXT), `myMemberId` (TEXT, UUID)
  * `myChainKeyOut` (BLOB, `EncryptedBlob` powiązany z wierszem w Keystore), `myCounterOut` (INTEGER), `groupEpoch` (INTEGER)
  * `createdAt` (INTEGER), `lastActive` (INTEGER), `isActive` (INTEGER, BOOLEAN)
* **Tabela `group_members`:**
  * `groupId` (TEXT), `memberId` (TEXT), PRIMARY KEY (`groupId`, `memberId`)
  * `contactId` (TEXT, NULLABLE — klucz obcy do kontaktu 1-na-1), `memberName` (TEXT)
  * `chainKeyIn` (BLOB, `EncryptedBlob` powiązany z wierszem w Keystore), `counterIn` (INTEGER)
  * `joinedAt` (INTEGER), `isActive` (INTEGER, BOOLEAN)
  * `receivedBitmapBase` (INTEGER), `receivedBitmap` (BLOB — przesuwna mapa bitowa replay protection)

### Dodatkowe Typy Rekordów o Tożsamym Rozmiarze 900 B:
* **Cover-Traffic ACK:** Szyfrowany pakiet potwierdzenia ukryty w szumie pod adresem $`Target_{ACK}`$, o stałym rozmiarze 900 bajtów (`CoverAckProtocol`).
* **Cover Traffic Dummy:** Nieskoordynowany rekord 900 bajtów wypełniony czystym szumem CSPRNG (`DhtLeafNode.sendCoverTrafficDummy`).
* **Bezpieczny Tombstone (Czyszczenie slotu po odebraniu):** Zastąpienie skonsumowanej wiadomości rekordem o sztywnym rozmiarze dokładnie 900 bajtów czystego szumu CSPRNG pod `seq = DEFAULT_MUTABLE_SEQ + 1` (`BinaryFrameCodec.createTombstonePayload`). Zastępuje to podatny wariant 0 B, który ujawniał węzłom i podsłuchiwaczom fakt oraz moment dostarczenia wiadomości. Dzięki zachowaniu stałego rozmiaru 900 B (904 B w Bencode) operacja tombstone jest całkowicie nierozróżnialna od normalnego zapisu lub ruchu maskującego.

---

## 5. Przebiegi Procesów (Workflows)

### A. Handshake (Skanowanie QR + Zakończenie Online):
1. **Alice (QR):** Generuje parę hybrydową X25519 + ML-KEM-512 $(pk_A, sk_A)$ oraz losowe $Seed_{init}$ (32 B). Prezentuje kod QR zawierający $pk_A \parallel Seed_{init}$ (łącznie 864 bajty).
2. **Bob (Scan & Put):** Skanuje kod, wykonuje `Encapsulate(pk_A)` $\to (SS_{init}, ct_B)$ (gdzie $ct_B$ ma 800 B: 768 B ML-KEM-512 + 32 B X25519 eph pk). Wylicza adres docelowy:
   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
   Wysyła pakiet Typu `0x01` pod $\text{Target}_0$ za pomocą efemerycznego rekordu BEP 44 (900 B).
3. **Alice (Get & Derive):** Odpytuje DHT o $\text{Target}_0$. Po pobraniu odszyfrowuje pakiet, wykonuje `Decapsulate(sk_A, ct_B)` i odzyskuje $SS_{init}$.
4. **Wyprowadzenie stanów:** Obie strony wyprowadzają:
   * $ChainKey_{A \to B} = \text{HKDF-Expand}(SS_{init}, \text{"AliceToBob"}, 64)$
   * $ChainKey_{B \to A} = \text{HKDF-Expand}(SS_{init}, \text{"BobToAlice"}, 64)$
   * Inicjalizują liczniki $Counter = 0$.

### B. Przeskakiwanie Adresów (Key Hopping):
Dla każdej wiadomości $i$:
1. $\text{Entropy}_i = \text{HKDF-Expand}(ChainKey^i, \text{"step"} \parallel i, 128)$.
2. Bajty 0–31: $MsgKey_i$ (klucz AES-256).
3. Bajty 32–63: $EdSeed_i$ (ziarno do generacji jednorazowej pary Ed25519 $pk_i, sk_i$).
4. Bajty 64–127: $ChainKey^{i+1}$.
5. Adres docelowy: $\text{Target}_i = \text{SHA-1}(pk_i)$.

### C. Rotacja PQC (Re-keying co 50 wiadomości):
* Gdy $Counter_{out} \equiv 0 \pmod{50}$ i $Counter_{out} > 0$:
  * Nadawca dołącza nowy efemeryczny hybrydowy klucz publiczny X25519 + ML-KEM-512 (832 B) w pakiecie Typu `0x03`.
  * Odbiorca odpowiada w swoim kanale wyjściowym hybrydowym kryptogramem KEM (800 B) w pakiecie Typu `0x04`.
  * Po skonsumowaniu obu stron nowy sekret $SS_{rekey}$ jest wstrzykiwany do głównego stanu:
    $$ChainKey \leftarrow \text{HKDF-Extract}(ChainKey, SS_{rekey})$$

---

## 6. Cykle Odpytywania i Ruch Maskujący (Anti-Traffic Analysis)

### Adaptacyjny Harmonogram Odpytywania (Polling):
1. **10 sekund:** Aktywne okno czatu z danym rozmówcą (`FOREGROUND_CHAT` — ekran włączony, aplikacja na pierwszym planie, wybrana konwersacja).
2. **1 minuta:** Aplikacja otwarta na pierwszym planie (`APP_ACTIVE_OTHER` — ekran włączony, lista kontaktów, diagnostyka lub ustawienia).
3. **5 minut:** Urządzenie jest w użyciu (`BACKGROUND_IDLE` — ekran włączony, ale aplikacja działa w tle / zminimalizowana).
4. **15 minut:** Urządzenie zablokowane / uśpione (`DOZE_SLEEP` — ekran wyłączony; realizowane przez `WorkManager` oraz `AlarmManager.setAndAllowWhileIdle`).

Szczegółowy model maszyny stanów, obsługa Android 12+ Cached App Freezer (CAF), limity Android 15 `dataSync` FGS (targetSdk 35) oraz mechanizm `BOOT_COMPLETED` opisane są w [docs/android_lifecycle_background_execution.md](file:///c:/Users/PJURO/PQChat.DHT/docs/android_lifecycle_background_execution.md).

### Spójne Przejścia Cyklu Życia (PollingLifecycleCoordinator):
Przejścia pomiędzy 4 stanami pollingu są centralnie koordynowane przez `PollingLifecycleCoordinator`:
* Wykorzystuje `ProcessLifecycleOwner` (śledzenie obecności procesu na pierwszym planie / w tle, niezależnie od rotacji i cyklu pojedynczych `Activity`).
* Wykrywa rzeczywisty stan ekranu za pomocą dynamicznego `ScreenStateReceiver` (`ACTION_SCREEN_ON`, `ACTION_SCREEN_OFF`) i `PowerManager.isInteractive`.
* Zdarzenie `ON_STOP` aktywności **nigdy nie jest tożsame z wyłączeniem ekranu**; minimalizacja aplikacji przy włączonym ekranie prowadzi do `BACKGROUND_IDLE` (5 min), a nie `DOZE_SLEEP`.

### Ruch Maskujący (Poisson Cover Traffic):
* W tle działa niezależny proces wyznaczający czas do kolejnego fałszywego zapisu na podstawie rozkładu wykładniczego:
  $$\Delta t = - \frac{1}{\lambda} \ln(U), \quad U \sim \mathcal{U}(0, 1)$$
* Po upływie $\Delta t$ generowany jest losowy $\text{Target}_{dummy}$ oraz rekord o stałym rozmiarze dokładnie 900 bajtów (904 bajty w Bencode) wypełniony czystym szumem.
* Pakiet jest wysyłany operacją `put` do sieci DHT w celu zatarcia korelacji pomiędzy aktywnością użytkownika a emisją pakietów UDP.

---

## 7. Struktura Modułów Projektu

Kod projektu zorganizowany jest w 100% w języku Kotlin:

```
app/src/main/java/org/pqchat/dht/
├── crypto/              # PqcEngine, MLKemEngine, AesGcmEngine, BinaryFrameCodec, Ed25519Engine, RatchetChain
├── data/
│   ├── local/           # Room Database (AppDatabase, DAOs, Encrypted Entities)
│   └── repository/      # ChatRepository, MessageChunker
├── dht/
│   ├── bencode/         # Wydajny dekoder/enkoder słowników Bencode w czystym Kotlinie
│   ├── krpc/            # Zarządzanie gniazdami UDP KRPC DHT
│   └── leaf/            # DhtLeafNode (klient BEP 44 put/get w trybie Leaf)
├── media/               # Png8Compressor, optymalizacja transferu obrazów
├── network/
│   └── tor/             # Obsługa embedded Tor i proxy SOCKS5
├── protocol/            # ProtocolEngine, CoverAckProtocol (potwierdzenia w szumie)
├── service/             # PollingScheduler, PollingLifecycleCoordinator, ScreenStateReceiver, BootReceiver, DhtAlarmReceiver, ChatHeadService
├── traffic/             # AdaptivePollingManager, PoissonTrafficGenerator, BlindRepublishPool, DecoyTargetPool, PollingWorker
└── ui/                  # ChatScreen, ContactsScreen, DiagnosticsScreen, SettingsScreen, motywy
```

---

## 8. Wskazówki i Ograniczenia Implementacyjne dla Agenta AI

1. **Bezpieczeństwo Pamięci i Kluczy:**
   * Po zakończeniu operacji kryptograficznych na kluczach efemerycznych tablice `ByteArray` muszą być bezzwłocznie zerowane (`array.fill(0)`).
   * Żadne dane jawne (plaintext), klucze prywatne ani zdeszyfrowane payloady nie mogą trafiać do logów systemowych (`Log.d`, `println`).
   * Przed każdym wypchnięciem commitu zweryfikuj czy nie są wysyłane klucze prywatne, np. API keys.
2. **Obsługa Błędów Sieci:**
   * Operacje `get` w sieci DHT są asynchroniczne i mogą zakończyć się przekroczeniem czasu oczekiwania (*timeout*). Brak odpowiedzi nie oznacza błędu krytycznego — oznacza jedynie brak nowej wiadomości lub konieczność ponowienia próby w kolejnym cyklu okna.
3. **Odporność na Replay i Kolizje:**
   * Wiadomości o numerach sekwencyjnych mniejszych niż bieżący stan $Counter_{in}$ muszą być natychmiast odrzucane.
   * Każdy rekord o nieprawidłowym tagu AEAD (`AEADBadTagException`) lub niezgodnym podpisie Ed25519 jest bezwzględnie ignorowany i usuwany z bufora.
4. **Czystość Kodu:**
   * Preferuj niemutowalne struktury danych (`data class`).
   * Zapewnij pełne pokrycie testami jednostkowymi modułów kryptograficznych (`KdfChainTest`, `PqcEngineTest`, `ChunkingTest`, `CryptoEngineTest`).
5. **Strategia Testowania i Praca z Repozytorium:**
   * **Podstawowe testy co commit (Fast Unit Tests):** Przed każdym commitem uruchamiaj standardowe testy jednostkowe: `.\gradlew.bat testDebugUnitTest`. Testy te pomijają czasochłonne scenariusze (`@Tag("slow")`) i wykonują się w kilkadziesiąt sekund. Gdy testy trwają dłużej niż 3 minuty napisz jaki jest status testów oraz rozważ wrzucenie czasochłonnego testu do testów czasochłonnych ("slow"), żeby zrobiły się w ramach testów nightly, a nie od razu, i poinformuj o tym fakcie.
   * **Testy czasochłonne (Slow Tests):** Testy repozytorium (`org.pqchat.dht.data.repository.*`), testy statystyczne Monte Carlo oraz symulacje loopback są oznaczone tagiem `@Tag("slow")`. Są one wykonywane automatycznie jako nocne zadanie CI w GitHub Workflows (`.github/workflows/nightly.yml`) oraz lokalnie na żądanie za pomocą: `.\gradlew.bat testDebugUnitTest -DrunSlowTests=true` lub `.\gradlew.bat slowTest`.
   * **Weryfikacja modeli formalnych:** Modele formalne ProVerif znajdujące się w `docs/formal/` weryfikuje się skryptem `bash docs/formal/run_verification.sh`. Obejmują one 7 modeli (.pv) weryfikujących 24 lematy (m.in. poufność kluczy i ładunków, uwierzytelnienie i transkrypt SAS anti-grinding, hybrydowy KEM ML-KEM-512 + X25519, Forward Secrecy, Post-Compromise Security, odporność na replay, nierozróżnialność 900-bajtowych tombstone'ów i cover traffic oraz poufność dystrybucji kluczy grupowych w ramce 0x06, autentyczność wiadomości grupowych z wiązaniem AAD i grupowe PCS/FS po odejściu członka).
   * **Pliki tekstowe:** W plikach README oraz innych plikach .md wyrażenia matematyczne muszą być w znacznikach $`wyrażenie\_pierwsze_{abc}`$ (jest to metoda bardziej odporna niż $wyrażenie\_pierwsze_{abc}$)
   * **Weryfikacja w emulatorze:** Każdą istotną zmianę interfejsu lub logiki czatu przetestuj w emulatorze (np. instalacja przez `.\gradlew.bat installDebug`, uruchomienie aktywności, zrobienie screenshotu do analizy).
   * **Zatwierdzanie zmian:** Po pomyślnym zakończeniu testów zrób commit z precyzyjnym opisem, a następnie push do repozytorium zdalnego.
