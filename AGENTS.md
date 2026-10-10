# \# AGENTS.md — Wytyczne Architektoniczne i Implementacyjne dla Agentów AI

# 

# Niniejszy plik definiuje specyfikację techniczną, model kryptograficzny, architekturę kodu oraz zasady implementacji dla zdecentralizowanego, post-kwantowego komunikatora mobilnego na platformę Android. Każdy agent AI pracujący w tym repozytorium jest zobowiązany do bezwzględnego przestrzegania poniższych wytycznych.

# 

# \---

# 

# \## 1. Przegląd Projektu i Filozofia Architektury

# 

# Projekt to w pełni zdecentralizowany (serverless), odporny na cenzurę i chroniący metadane komunikator mobilny na system Android, wykorzystujący publiczną sieć \*\*BitTorrent Mainline DHT (BEP 44)\*\* jako efemeryczny magazyn buforujący (Store-and-Forward) na okres 24–72 godzin.

# 

# \### Główne Filary:

# 1\. \*\*Zero Centralizacji:\*\* Brak jakichkolwiek serwerów pośredniczących, brokerów push (brak FCM/APNs) oraz stałych adresów IP/kont.

# 2\. \*\*Ochrona Metadanych (Metadata-Free Rendezvous):\*\* Obserwator sieciowy ani węzły DHT nie są w stanie powiązać nadawcy z odbiorcą, określić faktu prowadzenia rozmowy ani zmierzyć częstotliwości wymiany wiadomości.

# 3\. \*\*Odporność Post-Kwantowa (PQC):\*\* Ochrona przed atakiem \*Harvest Now, Decrypt Later\* za pomocą algorytmów standaryzowanych przez NIST (FIPS 203).

# 4\. \*\*Tryb Klienta Liścia (Client-Only / Leaf Node):\*\* Smartfon nigdy nie trasuje cudzych zapytań ani nie buforuje danych innych użytkowników w RAM; jest wyłącznie inicjatorem efemerycznych zapytań UDP.

# 

# \---

# 

# \## 2. Stos Technologiczny

# 

# \* \*\*Język główny:\*\* Kotlin (100% kodu warstwy aplikacji, UI i serwisów tła).

# \* \*\*Język natywny:\*\* C++20 (zarządzanie gniazdami UDP KRPC DHT, Bencode, niskopoziomowe operacje wektorowe).

# \* \*\*Interfejs UI:\*\* Jetpack Compose + Material 3.

# \* \*\*Baza danych:\*\* Room (SQLite) z szyfrowaniem wrażliwych pól kluczem z Android Keystore.

# \* \*\*Wielowątkowość:\*\* Kotlin Coroutines (`Dispatchers.IO`, `Dispatchers.Default`) + Flow.

# \* \*\*Praca w tle:\*\* AndroidX WorkManager (zadania periodyczne) + Foreground Service (dla aktywnego czatu) + AlarmManager (`setAndAllowWhileIdle` dla trybu Doze).

# \* \*\*Biblioteka kryptograficzna:\*\* Bouncy Castle Java/Kotlin PQC Provider (`org.bouncycastle:bcprov-jdk18on`) + natywne API Androida `javax.crypto` (dla AES-GCM).

# 

# \---

# 

# \## 3. Specyfikacja Kryptograficzna

# 

# | Komponent | Standard / Algorytm | Zastosowanie |

# | :--- | :--- | :--- |

# | \*\*KEM (Handshake \& Rekey)\*\* | ML-KEM-512 (FIPS 203 / Kyber-512) | Asymetryczne uzgadnianie wspólnego sekretu ($pk=800\\text{ B}$, $ct=768\\text{ B}$, $SS=32\\text{ B}$) |

# | \*\*Szyfrowanie ładunku (AEAD)\*\* | AES-256-GCM | Szyfrowanie symetryczne wiadomości (Klucz: 32 B, IV: 12 B, Tag: 16 B) |

# | \*\*Wyprowadzanie kluczy (KDF)\*\* | HKDF-SHA512 (RFC 5869) | Derywacja łańcuchów kluczy, ziaren slotów i kluczy AES |

# | \*\*Wymóg transportowy DHT\*\* | Ed25519 (RFC 8032) | Wymagany przez BEP 44 podpis węzła (używany wyłącznie jako \*\*jednorazowy token efemeryczny\*\*) |

# 

# \### Deterministyczne Rozdzielenie Torów (Dual Unidirectional Chains):

# Każdy kontakt posiada dwa niezależne łańcuchy sterowane odrębnymi licznikami:

# \* \*\*Tor $A \\to B$:\*\* Alice inkrementuje $Counter\_{out}$, Bob inkrementuje $Counter\_{in}$.

# \* \*\*Tor $B \\to A$:\*\* Bob inkrementuje $Counter\_{out}$, Alice inkrementuje $Counter\_{in}$.

# 

# Wysłanie wiadomości przez jedną stronę \*\*nigdy\*\* nie wpływa na numerację ani adresowanie w torze przeciwnym.

# 

# \---

# 

# \## 4. Specyfikacja Binarna Rekordów DHT (BEP 44 Value)

# 

# Każdy pakiet zapisywany w DHT ma \*\*sztywny rozmiar dokładnie 1000 bajtów\*\*. Wszelkie wolne bajty są wypełniane kryptograficznie bezpiecznym szumem (`SecureRandom`).

# 

# ```

# \+───────────────────────────────────────────────────────────────────────────────+

# |                  REKORD BEP 44 VALUE (SZTYWNE 1000 BAJTÓW)                    |

# \+────────────┬─────────────┬────────────────────────────────────────────────────+

# | IV (Nonce) |  AEAD Tag   |              SZYFROWANY ŁADUNEK                    |

# |  12 bajtów |  16 bajtów  |                 972 bajty                          |

# \+────────────┴─────────────┴──────────────────┬──────────────────┬──────────────+

# &#x20;                          | Nagłówek (13 B)  |   Dane Typu      | CSPRNG Szum  |

# &#x20;                          +──────────────────┴──────────────────┴──────────────+

# ```

# 

# \### Nagłówek wewnętrzny ładunku (Plaintext Header – 13 bajtów):

# 1\. `MsgType` (1 bajt):

# &#x20;  \* `0x01` – Handshake Online Finalize

# &#x20;  \* `0x02` – Standardowa wiadomość tekstowa

# &#x20;  \* `0x03` – PQC Rekey Offer (Nowy klucz publiczny)

# &#x20;  \* `0x04` – PQC Rekey Response (Kryptogram potwierdzenia)

# &#x20;  \* `0x05` – Segment transferu blokowego (Chunk)

# 2\. `SeqNum` (2 bajty, UInt16 Big-Endian): Licznik $Counter\_{out}$ nadawcy.

# 3\. `AckNum` (2 bajty, UInt16 Big-Endian): Ostatnio odebrany numer sekwencyjny partnera.

# 4\. `TimestampUTC` (8 bajtów, Int64 Big-Endian): Czas uniksowy nadania w milisekundach.

# 

# \### Dedykowane formaty wewnętrzne (przestrzeń 959 bajtów po odliczeniu nagłówka):

# 

# \* \*\*Typ 0x01 (Handshake):\*\*

# &#x20; \* `ML-KEM-512 Ciphertext`: 768 bajtów

# &#x20; \* `Salt`: 32 bajty

# &#x20; \* `Padding`: 159 bajtów

# \* \*\*Typ 0x02 (Tekst):\*\*

# &#x20; \* `TextLength` ($L$): 2 bajty (UInt16, wartość $\\le 957$)

# &#x20; \* `UTF-8 Payload`: $L$ bajtów (maksymalnie 957 bajtów czystego tekstu)

# &#x20; \* `Padding`: $957 - L$ bajtów

# \* \*\*Typ 0x03 (PQC Rekey Offer):\*\*

# &#x20; \* `RekeyEpoch`: 4 bajty (UInt32)

# &#x20; \* `ML-KEM-512 PublicKey`: 800 bajtów

# &#x20; \* `Padding`: 155 bajtów

# \* \*\*Typ 0x04 (PQC Rekey Response):\*\*

# &#x20; \* `RekeyEpoch`: 4 bajty (UInt32)

# &#x20; \* `ML-KEM-512 Ciphertext`: 768 bajtów

# &#x20; \* `Padding`: 187 bajtów

# \* \*\*Typ 0x05 (Chunk Transfer – np. PNG):\*\*

# &#x20; \* `TransferID`: 16 bajtów (UUID transferu)

# &#x20; \* `ChunkIndex`: 2 bajty (UInt16)

# &#x20; \* `TotalChunks`: 2 bajty (UInt16)

# &#x20; \* `ChunkLength` ($C$): 2 bajty (UInt16, wartość $\\le 937$)

# &#x20; \* `BinaryData`: $C$ bajtów

# &#x20; \* `Padding`: $937 - C$ bajtów

# 

# \---

# 

# \## 5. Przebiegi Procesów (Workflows)

# 

# \### A. Handshake (Skanowanie QR + Zakończenie Online):

# 1\. \*\*Alice (QR):\*\* Generuje parę ML-KEM-512 $(pk\_A, sk\_A)$ oraz losowe $Seed\_{init}$ (32 B). Prezentuje kod QR zawierający $pk\_A \\parallel Seed\_{init}$ (łącznie 832 bajty).

# 2\. \*\*Bob (Scan \& Put):\*\* Skanuje kod, wykonuje `Encapsulate(pk\_A)` $\\to (SS\_{init}, ct\_B)$. Wylicza adres docelowy:

# &#x20;  $$\\text{Target}\_0 = \\text{SHA-1}(\\text{HMAC-SHA512}(Seed\_{init}, \\text{"handshake\\\_rendezvous"}))$$

# &#x20;  Wysyła pakiet Typu `0x01` pod $\\text{Target}\_0$ za pomocą efemerycznego rekordu BEP 44.

# 3\. \*\*Alice (Get \& Derive):\*\* Odpytuje DHT o $\\text{Target}\_0$. Po pobraniu odszyfrowuje pakiet, wykonuje `Decapsulate(sk\_A, ct\_B)` i odzyskuje $SS\_{init}$.

# 4\. \*\*Wyprowadzenie stanów:\*\* Obie strony wyprowadzają:

# &#x20;  \* $ChainKey\_{A \\to B} = \\text{HKDF-Expand}(SS\_{init}, \\text{"AliceToBob"}, 64)$

# &#x20;  \* $ChainKey\_{B \\to A} = \\text{HKDF-Expand}(SS\_{init}, \\text{"BobToAlice"}, 64)$

# &#x20;  \* Inicjalizują liczniki $Counter = 0$.

# 

# \### B. Przeskakiwanie Adresów (Key Hopping):

# Dla każdej wiadomości $i$:

# 1\. $\\text{Entropy}\_i = \\text{HKDF-Expand}(ChainKey^i, \\text{"step"} \\parallel i, 128)$.

# 2\. Bajty 0–31: $MsgKey\_i$ (klucz AES-256).

# 3\. Bajty 32–63: $EdSeed\_i$ (ziarno do generacji jednorazowej pary Ed25519 $pk\_i, sk\_i$).

# 4\. Bajty 64–127: $ChainKey^{i+1}$.

# 5\. Adres docelowy: $\\text{Target}\_i = \\text{SHA-1}(pk\_i)$.

# 

# \### C. Rotacja PQC (Re-keying co 50 wiadomości):

# \* Gdy $Counter\_{out} \\equiv 0 \\pmod{50}$ i $Counter\_{out} > 0$:

# &#x20; \* Nadawca dołącza nowy efemeryczny klucz publiczny ML-KEM-512 w pakiecie Typu `0x03`.

# &#x20; \* Odbiorca odpowiada w swoim kanale wyjściowym kryptogramem KEM w pakiecie Typu `0x04`.

# &#x20; \* Po skonsumowaniu obu stron nowy sekret $SS\_{rekey}$ jest wstrzykiwany do głównego stanu:

# &#x20;   $$ChainKey \\leftarrow \\text{HKDF-Extract}(ChainKey, SS\_{rekey})$$

# 

# \---

# 

# \## 6. Cykle Odpytywania i Ruch Maskujący (Anti-Traffic Analysis)

# 

# \### Adaptacyjny Harmonogram Odpytywania (Polling):

# 1\. \*\*10 sekund:\*\* Aktywne okno czatu z danym rozmówcą (`Activity` w stanie `RESUMED` dla danej konwersacji).

# 2\. \*\*1 minuta:\*\* Aplikacja otwarta na pierwszym planie, ale otwarta jest inna rozmowa lub lista kontaktów.

# 3\. \*\*5 minut:\*\* Urządzenie jest w użyciu (ekran włączony), ale aplikacja działa w tle.

# 4\. \*\*15 minut:\*\* Urządzenie zablokowane / uśpione (tryb Doze; realizowane przez `WorkManager` oraz `AlarmManager.setAndAllowWhileIdle`).

# 

# \### Ruch Maskujący (Poisson Cover Traffic):

# \* W tle działa niezależny proces wyznaczający czas do kolejnego fałszywego zapisu na podstawie rozkładu wykładniczego:

# &#x20; $$\\Delta t = - \\frac{1}{\\lambda} \\ln(U), \\quad U \\sim \\mathcal{U}(0, 1)$$

# \* Po upływie $\\Delta t$ generowany jest losowy $\\text{Target}\_{dummy}$ oraz rekord 1000 bajtów wypełniony czystym szumem.

# \* Pakiet jest wysyłany operacją `put` do sieci DHT w celu zatarcia korelacji pomiędzy aktywnością użytkownika a emisją pakietów UDP.

# 

# \---

# 

# \## 7. Struktura Modułów Projektu

# 

# Agent tworzący pliki źródłowe powinien ściśle trzymać się następującej organizacji katalogów:

# 

# ```

# app/src/main/

# ├── cpp/

# │   ├── CMakeLists.txt

# │   ├── dht\_client.cpp         # Klient UDP KRPC (BEP 44 put/get w trybie Leaf)

# │   ├── bencode.cpp            # Wydajny dekoder/enkoder słowników Bencode

# │   └── native\_bridge.cpp      # Mostek JNI eksportujący metody do Kotlina

# ├── java/org/pqchat/dht/

# │   ├── crypto/

# │   │   ├── PqcEngine.kt       # Obsługa ML-KEM-512 (Bouncy Castle)

# │   │   ├── AesGcmEngine.kt    # Obsługa AES-256-GCM

# │   │   ├── KdfChain.kt        # Implementacja HKDF-SHA512 i przeskakiwania kluczy

# │   │   └── QrCodec.kt         # Kodowanie i dekodowanie payloadu parowania do QR

# │   ├── data/

# │   │   ├── local/             # Room Database (AppDatabase, DAOs, Encrypted Entities)

# │   │   │   ├── entity/        # MessageEntity, ContactEntity, SessionStateEntity

# │   │   │   └── dao/

# │   │   └── repository/        # ChatRepository, MessageChunker

# │   ├── network/

# │   │   ├── DhtBridge.kt       # Interfejs JNI łączący z warstwą C++

# │   │   ├── LookaheadWindow.kt # Logika asynchronicznego okna wyprzedzającego (n .. n+4)

# │   │   └── CoverTraffic.kt    # Generator szumu wg procesu Poissona

# │   ├── service/

# │   │   ├── PollingScheduler.kt# Koordynator interwałów (10s / 1m / 5m / 15m)

# │   │   ├── DhtWorker.kt       # Implementacja CoroutineWorker dla WorkManagera

# │   │   └── ChatHeadService.kt # Foreground service podtrzymujący pętlę 10s

# │   └── ui/

# │       ├── chat/              # ChatScreen, ChatViewModel, dymki wiadomości

# │       ├── contacts/          # ContactsScreen, parowanie QR

# │       └── theme/

# ```

# 

# \---

# 

# \## 8. Wskazówki i Ograniczenia Implementacyjne dla Agenta AI

# 

# 1\. \*\*Bezpieczeństwo Pamięci i Kluczy:\*\*

# &#x20;  \* Po zakończeniu operacji kryptograficznych na kluczach efemerycznych tablice `ByteArray` muszą być bezzwłocznie zerowane (`array.fill(0)`).

# &#x20;  \* Żadne dane jawne (plaintext), klucze prywatne ani zdeszyfrowane payloady nie mogą trafiać do logów systemowych (`Log.d`, `println`).

# 2\. \*\*Obsługa Błędów Sieci:\*\*

# &#x20;  \* Operacje `get` w sieci DHT są asynchroniczne i mogą zakończyć się przekroczeniem czasu oczekiwania (\*timeout\*). Brak odpowiedzi nie oznacza błędu krytycznego — oznacza jedynie brak nowej wiadomości lub konieczność ponowienia próby w kolejnym cyklu okna.

# 3\. \*\*Odporność na Replay i Kolizje:\*\*

# &#x20;  \* Wiadomości o numerach sekwencyjnych mniejszych niż bieżący stan $Counter\_{in}$ muszą być natychmiast odrzucane.

# &#x20;  \* Każdy rekord o nieprawidłowym tagu AEAD (`AEADBadTagException`) lub niezgodnym podpisie Ed25519 jest bezwzględnie ignorowany i usuwany z bufora.

# 4\. \*\*Czystość Kodu:\*\*

# &#x20;  \* Preferuj niemutowalne struktury danych (`data class`).

# &#x20;  \* Zapewnij pełne pokrycie testami jednostkowymi modułów kryptograficznych (`KdfChainTest`, `PqcEngineTest`, `ChunkingTest`).

# 5. **Strategia Testowania i Praca z Repozytorium:**
#
#    * **Podstawowe testy co commit (Fast Unit Tests):** Przed każdym commitem uruchamiaj standardowe testy jednostkowe: `.\gradlew.bat testDebugUnitTest`. Testy te pomijają czasochłonne scenariusze (`@Tag("slow")`) i wykonują się w kilkadziesiąt sekund.
#
#    * **Testy czasochłonne (Slow Tests):** Testy repozytorium (`org.pqchat.dht.data.repository.*`), testy statystyczne Monte Carlo oraz symulacje loopback są oznaczone tagiem `@Tag("slow")`. Są one wykonywane automatycznie jako nocne zadanie CI w GitHub Workflows (`.github/workflows/nightly_slow_tests.yml`) oraz lokalnie na żądanie za pomocą: `.\gradlew.bat testDebugUnitTest -DrunSlowTests=true` lub `.\gradlew.bat slowTest`.
#
#    * **Weryfikacja modeli formalnych:** Modele formalne ProVerif znajdujące się w `docs/formal/` weryfikuje się skryptem `bash docs/formal/run_verification.sh`.
#
#    * **Weryfikacja w emulatorze:** Każdą istotną zmianę interfejsu lub logiki czatu przetestuj w emulatorze (np. instalacja przez `.\gradlew.bat installDebug`, uruchomienie aktywności, zrobienie screenshotu do analizy).
#
#    * **Zatwierdzanie zmian:** Po pomyślnym zakończeniu testów zrób commit z precyzyjnym opisem, a następnie push do repozytorium zdalnego.



