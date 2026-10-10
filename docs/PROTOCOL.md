# PQChat.DHT Protocol Specification (v2.0)

Niniejszy dokument stanowi pełną specyfikację techniczną protokołu komunikacyjnego **PQChat.DHT** — zdecentralizowanego, post-kwantowego, asynchronicznego komunikatora mobilnego na platformę Android, wykorzystującego publiczną sieć BitTorrent Mainline DHT (BEP 44) jako efemeryczny bufor *Store-and-Forward*.

---

## 1. Architektura Systemu i Model Zagrożeń

### 1.1. Podstawowe Filary Architektury
1. **Serverless & Zero Metadata:** Całkowity brak serwerów centralnych, brokerów powiadomień Push (FCM/APNs) czy stałych identyfikatorów/kont.
2. **Tryb Klienta Liścia (Client-Only / Leaf Node):** Urządzenie mobilne nie trasuje cudzych pakietów KRPC ani nie buforuje danych innych węzłów w pamięci RAM. Jest wyłącznie inicjatorem zapytań UDP `put` / `get` (BEP 44).
3. **Efemeryczny Bufor DHT (Store-and-Forward):** Wiadomości są zapisywane jako mutowalne rekordy BEP 44 z czasem retencji rzędu 24–72 godzin.
4. **Odporność Post-Kwantowa (PQC):** Ochrona przed atakiem *Harvest Now, Decrypt Later* za pomocą standaryzowanego algorytmu NIST **ML-KEM-512** (FIPS 203 / Kyber-512).
5. **Maskowanie Ruchu (Anti-Traffic Analysis):** Emisja pakietów szumowych (dummy traffic) o rozkładzie Poissona w celu zatarcia korelacji czasowej między aktywnością użytkownika a emisją ramek UDP.

### 1.2. Założenia Kryptograficzne i Model Zagrożeń (Security Assumptions)

> [!IMPORTANT]
> **Założenie 1: Jawność ziarna w kodzie QR ($Seed_{init}$ jest jawny)**
> Kod QR prezentowany podczas parowania (Handshake) zawiera:
> $$QR = pk_A \ (800\text{ B}) \parallel Seed_{init} \ (32\text{ B}) \quad (\text{łącznie } 832\text{ bajty})$$
> Protokół **nie zakłada poufności** kodu QR przed obserwatorem fizycznym (np. osobą patrzącą zza pleców lub kamerą monitoringu).
> * $Seed_{init}$ służy wyłącznie do jednorazowego deterministycznego wyznaczenia punktu spotkania w sieci DHT:
>   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
>   oraz do powiązania transkryptu (transcript binding) i ochrony przed kolizjami.
> * Nawet jeśli adwersarz pozna $pk_A$ oraz $Seed_{init}$, **nie jest w stanie odszyfrować wiadomości ani poznać wspólnego sekretu**, ponieważ poufność wynika wprost z trudności problemu ML-KEM-512 (Module Learning With Errors — M-LWE).
> * Przed atakiem typu Man-in-the-Middle (podmiana odpowiedzi na DHT) chroni **Key Confirmation Tag** oraz **Short Authentication String (SAS)**.

> [!WARNING]
> **Założenie 2: Podpis Ed25519 w BEP 44 nie jest post-kwantowy**
> Publiczna sieć BitTorrent DHT (specyfikacja BEP 44) wymaga, aby każdy rekord mutowalny był autoryzowany kluczem publicznym $k$ ($32\text{ B}$) i podpisem Ed25519 ($64\text{ B}$).
> * W PQChat.DHT klucz Ed25519 jest **jednorazowym, efemerycznym tokenem transportowym** wyprowadzanym z bieżącego stanu łańcucha ($EdSeed_i$).
> * Ed25519 **nie szyfruje ładunku i nie uczestniczy w uzgadnianiu sekretu**.
> * Przeciwnik z dostępem do komputera kwantowego (algorytm Shora) mógłby złamać podpis Ed25519 i nadpisać wpis w DHT (atak typu Denial of Service lub podmiana ramek w locie), lecz **nie jest w stanie złamać szyfrowania ładunku (ML-KEM + AES-256-GCM)**. Wszelkie zmodyfikowane ramki zostaną natychmiast odrzucone przez odbiorcę z uwagi na błąd weryfikacji taga AEAD.

---

## 2. Faza Rendezvous i Handshake

Proces parowania składa się z 3 kroków: generacji QR przez Alice, przetworzenia i publikacji przez Boba oraz finalizacji i weryfikacji przez Alice.

```
       Alice                                                  Bob
  (Wyświetla QR)                                         (Skanuje QR)
         |                                                    |
  1. Generuje (pk_A, sk_A)                                    |
     Seed_init <- CSPRNG(32)                                  |
     Target_0 = SHA-1(...)                                    |
     Prezentuje QR: pk_A || Seed_init                         |
         | ---------------- Skanowanie QR (OOB) ------------> |
         |                                                    |
         |                                            2. Encapsulate(pk_A) -> (SS_init, ct_B)
         |                                               Generuje salt (32 B)
         |                                               Transcript = pk_A || ct_B || Seed_init || salt
         |                                               Commitment = SHA-256("PQChat_AntiGrind_v2" || Seed_init || Transcript)
         |                                               PRK = HKDF-Extract(salt, SS_init)
         |                                               MasterKey = HKDF-Expand(PRK, label || SHA-512(Transcript), 64)
         |                                               ConfirmTag = HKDF-Expand(MasterKey, "KeyConfirmationBob", 32)
         |                                               SAS = HKDF-Expand(MasterKey, "PQChat_SAS_v2_AntiGrind" || Commitment, 8)
         |                                               Tworzy ramkę Typu 0x01 (ct_B, salt, ConfirmTag)
         |                                               DHT putMutable(Target_0, Frame_0x01, sk_Ed)
         | <================= DHT PUT/GET (Target_0) ======== |
         |
  3. DHT GET(Target_0) -> Odbiera ramkę Typu 0x01
     Decapsulate(sk_A, ct_B) -> SS_init
     Transcript = pk_A || ct_B || Seed_init || salt
     Commitment = SHA-256("PQChat_AntiGrind_v2" || Seed_init || Transcript)
     PRK = HKDF-Extract(salt, SS_init)
     MasterKey = HKDF-Expand(PRK, label || SHA-512(Transcript), 64)
     Weryfikacja ConfirmTag == computeConfirmationTag(MasterKey)
     [BŁĄD -> zachowaj sk_A, oczekuj dalej]
     [SUKCES -> zeruj sk_A, wyprowadź łańcuchy, SAS = computeSas(MasterKey, Commitment)]
```

### 2.1. Krok 1 (Alice): Inicjalizacja i Prezentacja QR
1. Generacja pary kluczy: $(pk_A, sk_A) \leftarrow \text{ML-KEM-512.KeyGen}()$.
2. Generacja losowego ziarna: $Seed_{init} \leftarrow \text{CSPRNG}(32\text{ bajty})$.
3. Wyznaczenie punktu rendezvous $Target_0$:
   $$HMAC_0 = \text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"})$$
   $$Target_0 = \text{SHA-1}(HMAC_0)$$
4. Prezentacja ładunku QR o sztywnym rozmiarze 832 bajtów:
   $$QR_{payload} = pk_A \ (800\text{ B}) \parallel Seed_{init} \ (32\text{ B})$$

### 2.2. Krok 2 (Bob): Skanowanie, Enkapsulacja i Publikacja BEP 44
1. Rozpakowanie QR: odzyskanie $pk_A$ i $Seed_{init}$.
2. Enkapsulacja sekretu post-kwantowego:
   $$(SS_{init}, ct_B) \leftarrow \text{ML-KEM-512.Encapsulate}(pk_A)$$
   gdzie $SS_{init} \in \{0,1\}^{256}$, $ct_B \in \{0,1\}^{6144}$ ($768\text{ bajtów}$).
3. Wygenerowanie 32-bajtowej soli kryptograficznej: $salt \leftarrow \text{CSPRNG}(32\text{ B})$.
4. Związanie transkryptu (Transcript Binding):
   $$Transcript = pk_A \parallel ct_B \parallel Seed_{init} \parallel salt \quad (1632\text{ bajty})$$
   $$TranscriptHash = \text{SHA-512}(Transcript) \quad (64\text{ bajty})$$
5. Wyprowadzenie klucza głównego ($MasterKey$):
   $$PRK = \text{HKDF-Extract}(salt, SS_{init})$$
   $$MasterKey = \text{HKDF-Expand}(PRK, \text{"PQChat\_MasterKey\_Transcript"} \parallel TranscriptHash, 64)$$
6. Obliczenie taga potwierdzenia klucza (Key Confirmation Tag):
   $$ConfirmTag = \text{HKDF-Expand}(MasterKey, \text{"KeyConfirmationBob"}, 32)$$
7. Wyprowadzenie kluczy transportowych ramki powitalnej:
   $$k_{hs} = \text{HKDF-Derive}(null, Seed_{init}, \text{"hs\_enc"}, 32)$$
   $$EdSeed_{hs} = \text{HKDF-Derive}(null, Seed_{init}, \text{"hs\_ed25519"}, 32)$$
8. Skonstruowanie ładunku wewnętrznego (Typ `0x01` — Handshake Finalize):
   * Nagłówek (13 B): $MsgType = 0x01$, $SeqNum = 0$, $AckNum = 0$, $TimestampUTC$.
   * $ct_B$ (768 B).
   * $salt$ (32 B).
   * $ConfirmTag$ (32 B).
   * Padding CSPRNG (127 B).
   Szyfrowanie AEAD z kluczem $k_{hs}$ i $\text{AAD} = Target_0 \parallel \text{"BobToAlice"}$.
9. Zapis w sieci DHT operacją `putMutable` pod $Target_0$ z użyciem podpisu z $EdSeed_{hs}$.
10. Wyprowadzenie torów komunikacji i SAS:
    $$ChainKey_{A \to B} = \text{HKDF-Expand}(MasterKey, \text{"AliceToBob"}, 64)$$
    $$ChainKey_{B \to A} = \text{HKDF-Expand}(MasterKey, \text{"BobToAlice"}, 64)$$
    $$Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)$$
    $$SAS = \text{computeSas}(MasterKey, Commitment)$$

### 2.3. Krok 3 (Alice): Pobranie z DHT, Deszyfrowanie i Weryfikacja
1. Alice cyklicznie odpytuje DHT pod adresem $Target_0$.
2. Po odebraniu pakietu deszyfruje ramkę kluczem $k_{hs}$ z $\text{AAD} = Target_0 \parallel \text{"BobToAlice"}$.
3. Dekapsuluje sekret post-kwantowy:
   $$SS_{init} \leftarrow \text{ML-KEM-512.Decapsulate}(sk_A, ct_B)$$
4. Odtwarza $Transcript$, oblicza $TranscriptHash$, $PRK$ oraz $MasterKey$.
5. Weryfikuje $ConfirmTag$ w czasie stałym (`MessageDigest.isEqual`):
   * **Brak zgodności:** błąd autentyczności (np. nieprawidłowy kryptogram lub próba ataku). Alice **nie niszczy** $sk_A$, co pozwala jej nadal oczekiwać na poprawny pakiet Boba.
   * **Zgodność potwierdzona:** Alice bezzwłocznie zeruje pamięć klucza prywatnego $sk_A$ (`Arrays.fill(skA, 0)`), inicjalizuje tory $ChainKey_{A \to B}$, $ChainKey_{B \to A}$ i oblicza identyczny kod $SAS$.

---

## 3. Wzmocniony SAS (Short Authentication String) z Zobowiązaniem Przeciw Mieleniu

### 3.1. Zagrożenie Mieleniem (Grinding Attack)
W klasycznych kodach SAS o długości 6 cyfr ($10^6$ możliwości), aktywny atakujący podsłuchujący kod QR mógłby manipulować swoim wkładem (kryptogramem KEM lub solą $salt$), wykonując średnio $5 \cdot 10^5$ prób haszowania offline, aby doprowadzić do kolizji kodu SAS wyliczonego przez ofiary.

### 3.2. Zobowiązanie Przeciw Mieleniu (Anti-Grinding Commitment)
W PQChat.DHT wprowadzono kryptograficzne zobowiązanie oparte o pełny transkrypt oraz ziarno inicjatora:
$$Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)$$

### 3.3. Derywacja 8-Cyfrowego Kodu SAS
Kod SAS jest wyprowadzany z $MasterKey$ oraz $Commitment$ przy użyciu etykiety `PQChat_SAS_v2_AntiGrind`:
$$\text{Entropy}_{SAS} = \text{HKDF-Expand}(MasterKey, \text{"PQChat\_SAS\_v2\_AntiGrind"} \parallel Commitment, 8)$$
Bity są dzielone na dwie 4-cyfrowe grupy modulo 10000:
$$Part_1 = (\text{Uint32BE}(\text{Entropy}_{SAS}[0..3]) \ \& \ \text{0x7FFFFFFF}) \pmod{10000}$$
$$Part_2 = (\text{Uint32BE}(\text{Entropy}_{SAS}[4..7]) \ \& \ \text{0x7FFFFFFF}) \pmod{10000}$$
$$SAS = \text{format}(\text{"\%04d-\%04d"}, Part_1, Part_2)$$
* **Przestrzeń poszukiwań:** $10^8$ (100 milionów kombinacji, ~26.6 bita entropii).
* **Zobowiązanie:** Jakakolwiek modyfikacja $pk_A$, $ct_B$, $Seed_{init}$ lub $salt$ zmienia zarówno $MasterKey$, jak i $Commitment$, dając zupełnie inny kod SAS.
* **Weryfikacja w UI:** Użytkownicy widzą kod SAS w `HandshakeScreen` oraz `ChatScreen` i mogą jednym kliknięciem oznaczyć kontakt jako `isVerified = true`.

---

## 4. Deterministyczne Rozdzielenie Torów (Dual Unidirectional Chains)

Komunikacja między dwoma kontaktami opiera się na dwóch całkowicie rozłącznych, jednokierunkowych łańcuchach:

1. **Tor $A \to B$ (Alice do Boba):**
   * Stan początkowy: $ChainKey_{A \to B}$.
   * Alice inkrementuje swój $Counter_{out}$.
   * Bob inkrementuje swój $Counter_{in}$.
2. **Tor $B \to A$ (Bob do Alice):**
   * Stan początkowy: $ChainKey_{B \to A}$.
   * Bob inkrementuje swój $Counter_{out}$.
   * Alice inkrementuje swój $Counter_{in}$.

Wysłanie wiadomości w jednym kierunku **nigdy** nie zużywa kluczy ani nie zmienia numeracji w torze przeciwnym. Zapobiega to zakleszczeniom (deadlockom) i desynchronizacjom w asynchronicznym środowisku DHT.

---

## 5. Przeskakiwanie Adresów (Key Hopping)

Dla każdej kolejnej wiadomości $i$ w danym torze:

1. Wyprowadzenie 128 bajtów entropii:
   $$Entropy_i = \text{HKDF-Expand}(ChainKey^i, \text{"step"} \parallel \text{Uint32BE}(i), 128)$$
2. Podział entropii:
   * **Bajty 0–31 (32 B):** $MsgKey_i$ — klucz symetryczny AES-256 do zaszyfrowania ładunku wiadomości.
   * **Bajty 32–63 (32 B):** $EdSeed_i$ — jednorazowe ziarno efemerycznej pary kluczy Ed25519 $(pk_i^{Ed}, sk_i^{Ed})$ wymaganej przez BEP 44.
   * **Bajty 64–127 (64 B):** $ChainKey^{i+1}$ — stan klucza łańcucha dla następnej wiadomości.
3. Wyznaczenie adresu docelowego w DHT:
   $$Target_i = \text{SHA-1}(pk_i^{Ed})$$
4. Bezpieczne niszczenie pamięci: Po zakończeniu kroku tablice z $Entropy_i$, $EdSeed_i$ oraz $MsgKey_i$ są natychmiast zerowane (`fill(0)`).

Dzięki temu adres $Target_i$ jest pseudolosowy dla zewnętrznego obserwatora i znany wyłącznie nadawcy oraz odbiorcy posiadającemu $ChainKey^i$.

---

## 6. Rotacja Post-Kwantowa (Rekeying co 50 wiadomości)

W celu zapewnienia właściwości **Post-Compromise Security (PCS)** (samoleczenia stanu po ewentualnym wycieku kluczy z pamięci RAM), protokół wymusza asymetryczną renegocjację klucza KEM co 50 wysłanych wiadomości.

```
       Nadawca (Counter_out == 50k)                       Odbiorca
            |                                                 |
  1. Generuje nową parę ML-KEM-512                            |
     (pk_new, sk_new)                                         |
     Zapisuje PendingOffer(epoch+1, sk_new)                   |
     Wysyła pakiet Typu 0x03 (Rekey Offer: pk_new)            |
            | =================== DHT ======================> |
            |                                                 |
            |                                         2. Odbiera Typ 0x03
            |                                            Encapsulate(pk_new) -> (SS_rekey, ct_rekey)
            |                                            Wstrzykuje SS_rekey do swojego ChainKey_in:
            |                                            ChainKey_in <- HKDF-Extract(ChainKey_in, SS_rekey)
            |                                            Wysyła w torze powrotnym Typ 0x04 (ct_rekey)
            | <================== DHT ======================= |
            |
  3. Odbiera Typ 0x04 w torze powrotnym
     Decapsulate(sk_new, ct_rekey) -> SS_rekey
     ChainKey_out <- HKDF-Extract(ChainKey_out, SS_rekey)
     Wycofuje i zeruje sk_new
     Zwiększa rekeyEpoch
```

### 6.1. Typ 0x03: PQC Rekey Offer
Gdy $Counter_{out} > 0$ oraz $Counter_{out} \equiv 0 \pmod{50}$:
* Nadawca generuje świeżą parę $(pk_{new}, sk_{new}) \leftarrow \text{ML-KEM-512.KeyGen}()$.
* Zapisuje bezpiecznie $sk_{new}$ w bazie (zaszyfrowany Android Keystore) jako `PendingRekeyOfferEntity`.
* Nadaje pakiet Typu `0x03` zawierający $RekeyEpoch$ oraz $pk_{new}$ ($800\text{ B}$).

### 6.2. Typ 0x04: PQC Rekey Response
* Odbiorca po odebraniu oferty wykonuje `Encapsulate(pk_new)`, uzyskując $(SS_{rekey}, ct_{rekey})$.
* Natychmiast aplikuje nowy sekret do swojego łańcucha wejściowego:
  $$ChainKey_{in} \leftarrow \text{HKDF-Extract}(ChainKey_{in}, SS_{rekey})$$
* W swoim kanale wyjściowym nadaje pakiet Typu `0x04` zawierający $RekeyEpoch$ oraz $ct_{rekey}$ ($768\text{ B}$).

### 6.3. Konsumpcja Odpowiedzi przez Inicjatora
* Inicjator odbiera pakiet Typu `0x04` i dekapsuluje sekret:
  $$SS_{rekey} \leftarrow \text{ML-KEM-512.Decapsulate}(sk_{new}, ct_{rekey})$$
* Wstrzykuje sekret do łańcucha wyjściowego:
  $$ChainKey_{out} \leftarrow \text{HKDF-Extract}(ChainKey_{out}, SS_{rekey})$$
* Niszczy $sk_{new}$ i usuwa wpis z bazy danych.

---

## 7. Format Binarny Ramek DHT (BEP 44 Value)

Każdy rekord publikowany w DHT ma **sztywny, stały rozmiar dokładnie 1000 bajtów** (ochrona przed analizą wielkości pakietów).

```
+─────────────────────────────────────────────────────────────────────────────+
|                  REKORD BEP 44 VALUE (SZTYWNE 1000 BAJTÓW)                  |
+────────────┬─────────────┬──────────────────────────────────────────────────+
| IV (Nonce) |  AEAD Tag   |              SZYFROWANY ŁADUNEK                  |
|  12 bajtów |  16 bajtów  |                 972 bajty                        |
+────────────┴─────────────┴─────────────────┬──────────────────┬─────────────+
                           | Nagłówek (13 B) |   Dane Typu      | CSPRNG Szum |
                           +─────────────────┴──────────────────┴─────────────+
```

### 7.1. Uwierzytelnienie AEAD i AAD
* **Szyfrowanie:** AES-256-GCM.
* **AAD (Additional Authenticated Data):**
  $$\text{AAD} = Target \ (20\text{ B}) \parallel Direction \ (\text{"AliceToBob" lub "BobToAlice"})$$
  Wiązanie AAD uniemożliwia ataki typu reflection oraz podmianę adresu docelowego w węzłach DHT.

### 7.2. Nagłówek Wewnętrzny Ładunku (13 bajtów Plaintextu)
1. `MsgType` (1 B): identyfikator typu komunikatu.
2. `SeqNum` (2 B, UInt16 BE): numer sekwencyjny nadawcy $Counter_{out}$.
3. `AckNum` (2 B, UInt16 BE): ostatnio odebrany numer sekwencyjny rozmówcy.
4. `TimestampUTC` (8 B, Int64 BE): uniksowy znacznik czasu w milisekundach.

### 7.3. Typy Wiadomości i Struktury Ładunku (959 bajtów po odliczeniu nagłówka)
* **Typ 0x01 (Handshake Finalize):**
  * `ML-KEM-512 Ciphertext`: 768 B
  * `Salt`: 32 B
  * `Key Confirmation Tag`: 32 B
  * `CSPRNG Padding`: 127 B
* **Typ 0x02 (Wiadomość Tekstowa):**
  * `TextLength` ($L$): 2 B (UInt16, wartość $\le 957$)
  * `UTF-8 Payload`: $L$ bajtów
  * `CSPRNG Padding`: $957 - L$ bajtów
* **Typ 0x03 (PQC Rekey Offer):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `ML-KEM-512 PublicKey`: 800 B
  * `CSPRNG Padding`: 155 B
* **Typ 0x04 (PQC Rekey Response):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `ML-KEM-512 Ciphertext`: 768 B
  * `CSPRNG Padding`: 187 B
* **Typ 0x05 (Segment Transferu Blokowego — Chunk):**
  * `TransferID`: 16 B (UUID)
  * `ChunkIndex`: 2 B (UInt16 BE)
  * `TotalChunks`: 2 B (UInt16 BE)
  * `ChunkLength` ($C$): 2 B (UInt16, wartość $\le 937$)
  * `BinaryData`: $C$ bajtów
  * `CSPRNG Padding`: $937 - C$ bajtów

---

## 8. Epoki Sekwencji i Okno Wyprzedzające (Lookahead Window)

Z uwagi na asynchroniczny charakter sieci UDP i DHT, pakiety mogą docierać z opóźnieniem lub w zmienionej kolejności.

1. **Okno Wyprzedzające (Lookahead Window $n \dots n+4$):**
   * Odbiorca, którego bieżący licznik to $Counter_{in} = n$, oblicza klucze i odpytuje DHT o sloty $Target_n, Target_{n+1}, \dots, Target_{n+4}$.
   * Jeśli nadejdzie wiadomość $n+2$, klucze dla slotów $n$ oraz $n+1$ są zapisywane w bezpiecznej tabeli `skipped_keys` (zaszyfrowane Keystore'em) na wypadek późniejszego dotarcia tych pakietów.
2. **Mapa Bitowa Odebranych Wiadomości (Sliding Bitmap Window):**
   * Do wykrywania i odrzucania duplikatów (Anti-Replay) służy 1024-bitowa przesuwna mapa bitowa w `ContactEntity`.
   * Wiadomości o numerze $SeqNum < Counter_{in} - 1024$ są bezwzględnie odrzucane.

---

## 9. Formalna Weryfikacja Bezpieczeństwa (docs/formal/)

Wszystkie kluczowe własności protokołu zostały poddane rygorystycznemu symbolicznemu dowodowi w narzędziu **ProVerif 2.05** w katalogu `docs/formal/`:

1. **Poufność (Secrecy):** Dowiedziono niemożliwości poznania klucza głównego $MasterKey$, stanów łańcucha $ChainKey_{A \to B}$, $ChainKey_{B \to A}$ oraz ładunków wiadomości tekstowych przez adwersarza Dolev-Yao podsłuchującego publiczne zapytania DHT oraz jawny kod QR (`pqchat_protocol.pv`).
2. **Uwierzytelnienie i Transkrypt Handshake'u (Authentication & SAS Binding):** Dowiedziono injektywnej zgodności (`inj-event(AliceFinished) ==> inj-event(BobFinished)`), dowiązującej transkrypt i zobowiązanie SAS ($Commitment$).
3. **Forward Secrecy (Poufność Przeszła):** Dowiedziono (`pqchat_forward_secrecy.pv`), że wyciek stanu łańcucha $ChainKey_1$ nie pozwala na odszyfrowanie wcześniejszych wiadomości ($msg_0$).
4. **Post-Compromise Security (PCS / Samoleczenie):** Dowiedziono (`pqchat_post_compromise.pv`), że po wycieku kluczy łańcucha asymetryczna rotacja ML-KEM-512 przywraca pełną poufność kolejnych wiadomości.
5. **Odporność na Replay (Anti-Replay):** Dowiedziono injektywnej akceptacji pakietów (`pqchat_replay.pv` i `pqchat_protocol.pv`), uniemożliwiającej adwersarzowi wstrzyknięcie zduplikowanych ramek w sieci DHT.

Uruchomienie weryfikacji formalnej:
```bash
bash docs/formal/run_verification.sh
```

---

## 10. Strategia Testowania

Zgodnie z wytycznymi projektu testy podzielono na dwie kategorie:

1. **Szybkie testy jednostkowe co commit (Fast Unit Tests):**
   * Uruchamiane poleceniem: `.\gradlew.bat testDebugUnitTest`
   * Wykonują się w kilkadziesiąt sekund, automatycznie pomijając testy oznaczone adnotacją `@Tag("slow")`.
2. **Czasochłonne testy integracyjne i statystyczne (Slow Tests):**
   * Testy repozytorium (`org.pqchat.dht.data.repository.*`), testy statystyczne Monte Carlo (`TrafficThreatModelStatisticalTest`) oraz pomiary loopback (`LoopbackMeasurementHarnessTest`) są oznaczone `@Tag("slow")`.
   * Wykonywane w dedykowanym zadaniu nocnym GitHub Actions (`.github/workflows/nightly_slow_tests.yml`) o 02:00 UTC lub lokalnie:
     ```bash
     .\gradlew.bat testDebugUnitTest -DrunSlowTests=true
     # lub
     .\gradlew.bat slowTest
     ```

