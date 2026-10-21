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
> $$QR = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B}) \quad (\text{łącznie } 864\text{ bajty})$$
> Protokół **nie zakłada poufności** kodu QR przed obserwatorem fizycznym (np. osobą patrzącą zza pleców lub kamerą monitoringu).
> * $Seed_{init}$ służy wyłącznie do jednorazowego deterministycznego wyznaczenia punktu spotkania w sieci DHT:
>   $$\text{Target}_0 = \text{SHA-1}(\text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"}))$$
>   oraz do powiązania transkryptu (transcript binding) i ochrony przed kolizjami.
> * Nawet jeśli adwersarz pozna $pk_A$ oraz $Seed_{init}$, **nie jest w stanie odszyfrować wiadomości ani poznać wspólnego sekretu**, ponieważ poufność wynika wprost z trudności problemów ML-KEM-512 (Module Learning With Errors — M-LWE) oraz ECDH X25519 (DLP).
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
         |                                               Generuje salt (24 B)
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
1. Generacja pary kluczy: $(pk_A, sk_A) \leftarrow \text{Hybrid-KEM.KeyGen}()$ (832 B klucz publiczny: 800 B ML-KEM-512 + 32 B X25519).
2. Generacja losowego ziarna: $Seed_{init} \leftarrow \text{CSPRNG}(32\text{ bajty})$.
3. Wyznaczenie punktu rendezvous $Target_0$:
   $$HMAC_0 = \text{HMAC-SHA512}(Seed_{init}, \text{"handshake\_rendezvous"})$$
   $$Target_0 = \text{SHA-1}(HMAC_0)$$
4. Prezentacja ładunku QR o sztywnym rozmiarze 864 bajtów:
   $$QR_{payload} = pk_A \ (832\text{ B}) \parallel Seed_{init} \ (32\text{ B})$$

### 2.2. Krok 2 (Bob): Skanowanie, Enkapsulacja i Publikacja BEP 44
1. Rozpakowanie QR: odzyskanie $pk_A$ i $Seed_{init}$.
2. Enkapsulacja sekretu hybrydowego:
   $$(SS_{init}, ct_B) \leftarrow \text{Hybrid-KEM.Encapsulate}(pk_A)$$
   gdzie $SS_{init} \in \{0,1\}^{256}$, $ct_B \in \{0,1\}^{6400}$ ($800\text{ bajtów}$: 768 B ML-KEM + 32 B X25519 eph pk).
3. Wygenerowanie 24-bajtowej soli kryptograficznej: $salt \leftarrow \text{CSPRNG}(24\text{ B})$.
4. Związanie transkryptu (Transcript Binding):
   $$Transcript = pk_A \parallel ct_B \parallel Seed_{init} \parallel salt \quad (1688\text{ bajtów})$$
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
   * $ct_B$ (800 B).
   * $salt$ (24 B).
   * $ConfirmTag$ (32 B).
   * Padding CSPRNG (3 B).
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
3. Dekapsuluje sekret hybrydowy:
   $$SS_{init} \leftarrow \text{Hybrid-KEM.Decapsulate}(sk_A, ct_B)$$
4. Odtwarza $Transcript$, oblicza $TranscriptHash$, $PRK$ oraz $MasterKey$.
5. Weryfikuje $ConfirmTag$ w czasie stałym (`MessageDigest.isEqual`):
   * **Brak zgodności:** błąd autentyczności (np. nieprawidłowy kryptogram lub próba ataku). Alice **nie niszczy** $sk_A$, co pozwala jej nadal oczekiwać na poprawny pakiet Boba.
   * **Zgodność potwierdzona:** Alice bezzwłocznie zeruje pamięć kluczy prywatnych $sk_A$ (ML-KEM oraz X25519), inicjalizuje tory $ChainKey_{A \to B}$, $ChainKey_{B \to A}$ i oblicza identyczny kod $SAS$.

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
* Nadawca generuje świeżą parę $(pk_{new}, sk_{new}) \leftarrow \text{Hybrid-KEM.KeyGen}()$.
* Zapisuje bezpiecznie $sk_{new}$ w bazie (zaszyfrowany Android Keystore) jako `PendingRekeyOfferEntity`.
* Nadaje pakiet Typu `0x03` zawierający $RekeyEpoch$ oraz $pk_{new}$ ($832\text{ B}$: 800 B ML-KEM-512 + 32 B X25519).

### 6.2. Typ 0x04: PQC Rekey Response
* Odbiorca po odebraniu oferty wykonuje `Encapsulate(pk_new)`, uzyskując $(SS_{rekey}, ct_{rekey})$.
* Natychmiast aplikuje nowy sekret do swojego łańcucha wejściowego:
  $$ChainKey_{in} \leftarrow \text{HKDF-Extract}(ChainKey_{in}, SS_{rekey})$$
* W swoim kanale wyjściowym nadaje pakiet Typu `0x04` zawierający $RekeyEpoch$ oraz $ct_{rekey}$ ($800\text{ B}$: 768 B ML-KEM-512 + 32 B X25519 eph pk).

### 6.3. Konsumpcja Odpowiedzi przez Inicjatora
* Inicjator odbiera pakiet Typu `0x04` i dekapsuluje sekret:
  $$SS_{rekey} \leftarrow \text{Hybrid-KEM.Decapsulate}(sk_{new}, ct_{rekey})$$
* Wstrzykuje sekret do łańcucha wyjściowego:
  $$ChainKey_{out} \leftarrow \text{HKDF-Extract}(ChainKey_{out}, SS_{rekey})$$
* Niszczy $sk_{new}$ (zerując pamięć klucza ML-KEM i X25519) i usuwa wpis z bazy danych.

### 6.4. Unikalne Adresy Docelowe BEP 44 per Odbiorca w Czatach Grupowych
W czatach grupowych zamiast jednego wspólnego adresu docelowego $`Target = \text{RatchetChain.deriveSlot}(myChainKeyOut, counterOut)`$ używanego dla wszystkich członków grupy, nadawca wyprowadza unikalny adres docelowy dla każdego członka:
$`\text{memberTarget} = \text{HKDF-Expand}(myChainKeyOut, \text{"group\_target:"} \parallel groupId \parallel counterOut \parallel memberId, 32)`$
a następnie za pomocą `RatchetChain.deriveGroupRecipientSlot` generuje dedykowane parametry slotu (`msgKey`, `edPrivateKeySeed`, `target`).

Nadawca wykonuje osobne operacje `putMutable` pod każdym unikalnym adresem docelowym ($`N`$ targetów dla $`N`$ członków). W `pollGroupIncoming` każdy członek odpytuje **wyłącznie swój unikalny target, a nie wspólny**.

**Uzasadnienie bezpieczeństwa:** Same-target dla wszystkich członków umożliwia obserwatorowi DHT skorelowanie $`N`$ odbiorców przez równoległe zapytania `GET` na ten sam slot, łamiąc tajność celu komunikacji grupowej (Group Follower Correlation). Rozdzielenie slotów na $`N`$ niezależnych pseudolosowych adresów gwarantuje brak możliwości powiązania odbiorców ani wykrycia faktu ich przynależności do tej samej grupy.

---

## 7. Format Binarny Ramek DHT (BEP 44 Value)

Każdy rekord binarny ('v') publikowany w DHT ma **sztywny, stały rozmiar dokładnie 900 bajtów** (`BinaryFrameCodec.MAX_FRAME_PAYLOAD_BYTES = 900`).

### 7.1. Uzasadnienie Rozmiaru 900 B i Zgodność ze Specyfikacją BEP 44
Zgodnie ze specyfikacją BitTorrent BEP 44, całkowity rozmiar pola wartości `'v'` po zakodowaniu formatem Bencode **nie może przekraczać 1000 bajtów**:
* W formacie Bencode ciąg binarny kodowany jest z prefiksem długości: `<długość>:<dane>`.
* Dla surowego ładunku 900 bajtów zakodowany ciąg wynosi `"900:"` (4 bajty) + 900 bajtów danych = **dokładnie 904 bajty**, co spełnia sztywny limit BEP 44 ($\le 1000$ B).
* **Uwaga krytyczna:** Gdyby surowy ładunek miał 1000 bajtów, jego postać Bencode wynosiłaby `"1000:"` (5 bajtów) + 1000 bajtów danych = **1005 bajtów**, co **przekracza dopuszczalny limit BEP 44** i skutkuje odrzuceniem pakietu przez publiczne węzły sieci BitTorrent DHT!

```
+─────────────────────────────────────────────────────────────────────────────+
|                   REKORD BEP 44 VALUE (SZTYWNE 900 BAJTÓW)                  |
+────────────┬─────────────┬──────────────────────────────────────────────────+
| IV (Nonce) |  AEAD Tag   |              SZYFROWANY ŁADUNEK                  |
|  12 bajtów |  16 bajtów  |                 872 bajty                        |
+────────────┴─────────────┴─────────────────┬──────────────────┬─────────────+
                           | Nagłówek (13 B) |   Dane Typu      | CSPRNG Szum |
                           +─────────────────┴──────────────────┴─────────────+
```

### 7.2. Uwierzytelnienie AEAD i AAD
* **Szyfrowanie:** AES-256-GCM.
* **AAD (Additional Authenticated Data):**
  $$\text{AAD} = Target \ (20\text{ B}) \parallel Direction \ (\text{"AliceToBob" lub "BobToAlice"})$$
  Wiązanie AAD uniemożliwia ataki typu reflection oraz podmianę adresu docelowego w węzłach DHT.

### 7.3. Nagłówek Wewnętrzny Ładunku (13 bajtów Plaintextu)
1. `MsgType` (1 B): identyfikator typu komunikatu.
   * `0x01` – Handshake Online Finalize
   * `0x02` – Standardowa wiadomość tekstowa
   * `0x03` – PQC Rekey Offer (Nowy klucz publiczny)
   * `0x04` – PQC Rekey Response (Kryptogram potwierdzenia)
   * `0x05` – Segment transferu blokowego (Chunk)
   * `0x06` – Kontrola grupy (`TYPE_GROUP_CONTROL`: Invite, Rekey, Leave)
2. `SeqNum` (2 B, UInt16 BE): numer sekwencyjny nadawcy $`Counter_{out}`$.
3. `AckNum` (2 B, UInt16 BE): ostatnio odebrany numer sekwencyjny rozmówcy.
4. `TimestampUTC` (8 B, Int64 BE): uniksowy znacznik czasu w milisekundach.

### 7.4. Typy Wiadomości i Struktury Ładunku (859 bajtów po odliczeniu nagłówka 872 - 13)
* **Typ 0x01 (Handshake Finalize):**
  * `Hybrid Ciphertext`: 800 B (768 B ML-KEM-512 ct + 32 B X25519 eph pk)
  * `Salt`: 24 B
  * `Key Confirmation Tag`: 32 B
  * `CSPRNG Padding`: 3 B (859 - 856)
* **Typ 0x02 (Wiadomość Tekstowa):**
  * `TextLength` ($`L`$): 2 B (UInt16, wartość $`\le 857`$)
  * `UTF-8 Payload`: $`L`$ bajtów (maksymalnie 857 B czystego tekstu)
  * `CSPRNG Padding`: $`857 - L`$ bajtów
* **Typ 0x03 (PQC Rekey Offer):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `Combined PublicKey`: 832 B (800 B ML-KEM-512 + 32 B X25519)
  * `CSPRNG Padding`: 23 B (859 - 836)
* **Typ 0x04 (PQC Rekey Response):**
  * `RekeyEpoch`: 4 B (UInt32 BE)
  * `Hybrid Ciphertext`: 800 B (768 B ML-KEM-512 ct + 32 B X25519)
  * `CSPRNG Padding`: 55 B (859 - 804)
* **Typ 0x05 (Segment Transferu Blokowego — Chunk):**
  * `TransferID`: 16 B (UUID)
  * `ChunkIndex`: 2 B (UInt16 BE)
  * `TotalChunks`: 2 B (UInt16 BE)
  * `ChunkLength` ($`C`$): 2 B (UInt16, wartość $`\le 837`$)
  * `BinaryData`: $`C`$ bajtów
  * `CSPRNG Padding`: $`837 - C`$ bajtów
* **Typ 0x06 (Kontrola Grupy — TYPE_GROUP_CONTROL):**
  * `ControlSubType`: 1 B (`0x01` – `GROUP_SUBTYPE_INVITE`, `0x02` – `GROUP_SUBTYPE_REKEY`, `0x03` – `GROUP_SUBTYPE_LEAVE`)
  * `GroupID`: 16 B (UUID grupy)
  * `GroupEpoch`: 4 B (UInt32 BE)
  * `SenderMemberID`: 16 B (UUID nadawcy w grupie)
  * `SenderGroupChainKey`: 64 B (bieżący łańcuch nadawcy grupy)
  * `CurrentCounter`: 4 B (UInt32 BE)
  * `GroupNameLength` ($`N`$): 2 B (UInt16, wartość $`\le 64`$)
  * `GroupName`: $`N`$ bajtów UTF-8 (maksymalnie 64 bajty)
  * `MemberCount` ($`M`$): 2 B (UInt16, liczba uczestników, wartość $`\le 64`$)
  * `Members`: tablica $`M`$ wpisów: `MemberID` (16 B) + `NameLen` (1 B) + `MemberName` (do 32 B UTF-8)
  * `CSPRNG Padding`: $`859 - \text{długość}`$ bajtów

### 7.5. Dodatkowe Typy Rekordów o Stałym Rozmiarze 900 B
* **Cover-Traffic ACK:** Szyfrowany pakiet potwierdzenia ukryty w szumie pod adresem $`Target_{ACK}`$, sformatowany dokładnie do 900 bajtów (`CoverAckProtocol`).
* **Cover Traffic Dummy:** Nieskoordynowany rekord 900 bajtów wypełniony czystym szumem CSPRNG (`DhtLeafNode.sendCoverTrafficDummy`).
* **Bezpieczny Tombstone (Czyszczenie slotu po odebraniu):** Zastąpienie skonsumowanej wiadomości rekordem o sztywnym rozmiarze dokładnie 900 bajtów czystego szumu CSPRNG pod `seq = DEFAULT_MUTABLE_SEQ + 1` (`BinaryFrameCodec.createTombstonePayload`). Zastępuje to podatny wariant 0 B, który ujawniał węzłom i podsłuchiwaczom fakt oraz dokładny moment dostarczenia wiadomości. Dzięki zachowaniu stałego rozmiaru 900 B (904 B w Bencode) operacja tombstone jest całkowicie nierozróżnialna od normalnego zapisu lub ruchu maskującego.

---

## 8. Czaty Grupowe, Dystrybucja Kluczy i Tabele Bazy Danych

Architektura czatów grupowych w PQChat.DHT opiera się na zdecentralizowanym protokole **Sender Keys** transportowanym w całości przez bezpieczne kanały punkt-punkt (1-na-1) chronione hybrydowym KEM (ML-KEM-512 + X25519) i AES-256-GCM.

### 8.1. Dystrybucja Kluczy Grupowych (Ramka Typu 0x06)
1. Każdy uczestnik generuje niezależny, własny 64-bajtowy stan łańcucha nadawczego $`myChainKeyOut`$.
2. Klucz nadawcy ($`senderGroupChainKey`$) jest dystrybuowany do innych członków za pomocą ramki Typu `0x06` (`TYPE_GROUP_CONTROL`):
   * `GROUP_SUBTYPE_INVITE` (`0x01`): zaproszenie do grupy, lista członków oraz początkowy klucz nadawcy.
   * `GROUP_SUBTYPE_REKEY` (`0x02`): rotacja klucza nadawcy (nowa epoka $`groupEpoch + 1`$, licznik zresetowany do 0).
   * `GROUP_SUBTYPE_LEAVE` (`0x03`): opuszczenie grupy przez członka.
3. Ramki Typu `0x06` są przesyłane wyłącznie w torach 1-na-1 pomiędzy zweryfikowanymi kontaktami, co gwarantuje pełną poufność kluczy grupowych (udowodnione w lemacie 7.1 ProVerif).

### 8.2. Adresowanie bez Śledzenia Grupy (Individual Recipient Slots)
Aby wyeliminować korelację obserwatorów sieciowych DHT monitorujących zapytania (Group Follower Correlation), nadawca generuje **unikalny, niezależny adres docelowy DHT dla każdego odbiorcy wiadomości grupowej**:
$`\text{Target}_{slot} = \text{RatchetChain.deriveGroupRecipientSlot}(ChainKey, Counter, GroupID, RecipientMemberID)`$
gdzie kontekst derywacji oparty jest na:
$`\text{Info} = \text{"group\_target:"} \parallel GroupID \ (16\text{ B}) \parallel Counter \ (4\text{ B, BE}) \parallel RecipientMemberID \ (16\text{ B})`$
$`\text{memberEntropy} = \text{HKDF-Expand}(myChainKeyOut, \text{Info}, 64)`$
z którego wyznaczany jest klucz ładunku $`msgKey`$ (pierwsze 32 bajty) oraz ziarno klucza Ed25519 $`edSeed`$ (kolejne 32 bajty), dające unikalny adres $`\text{Target} = \text{SHA-1}(pk_{Ed25519})`$.

Dzięki temu operacja nadania wiadomości do $`N`$ odbiorców skutkuje $`N`$ odrębnymi operacjami `putMutable` pod pseudolosowe adresy, a żaden węzeł DHT nie jest w stanie powiązać ze sobą slotów ani ustalić składu grupy. W `pollGroupIncoming` każdy członek odpytuje wyłącznie swój unikalny target, a nie wspólny. Uzasadnienie: Same-target dla wszystkich członków umożliwia obserwatorowi DHT skorelowanie $`N`$ odbiorców przez równoległe GET-y na ten sam slot, łamiąc tajność celu komunikacji grupowej.

### 8.3. Wiązanie Kontekstu AEAD (Group AAD Binding)
Każda wiadomość grupowa (tekst Typu `0x02` lub chunk Typu `0x05`) szyfrowana jest algorytmem AES-256-GCM z dowiązaniem AAD o sztywnej strukturze:
$`\text{AAD} = \text{Target} \ (20\text{ B}) \parallel GroupID \ (16\text{ B}) \parallel SenderMemberID \ (16\text{ B})`$
Próba przekierowania rekordu do innej grupy lub podszycia się pod innego członka powoduje natychmiastowy błąd weryfikacji taga AEAD (`AEADBadTagException`).

### 8.4. Rotacja Kluczy Grupowych: Forward Secrecy i Post-Compromise Security (PCS)
1. **Automatyczna rotacja co 50 wiadomości:**
   Gdy $`Counter_{out} > 0`$ oraz $`Counter_{out} \equiv 0 \pmod{50}`$ (`GROUP_REKEY_MESSAGE_INTERVAL = 50`), nadawca generuje nowy klucz CSPRNG, zwiększa epokę $`groupEpoch + 1`$, zeruje licznik i rozsyła `GROUP_SUBTYPE_REKEY` do wszystkich aktywnych członków.
2. **Wymuszona rotacja przy odejściu członka (`GROUP_SUBTYPE_LEAVE`):**
   Gdy dowolny uczestnik opuszcza grupę i nadaje `GROUP_SUBTYPE_LEAVE`:
   * Wszyscy pozostali członkowie natychmiast oznaczają go w bazie danych jako nieaktywnego (`isActive = false`).
   * Każdy aktywny członek natychmiast rotuje swój $`myChainKeyOut`$ do nowej epoki $`groupEpoch + 1`$.
   * Ramka `GROUP_SUBTYPE_REKEY` jest transmitowana **wyłącznie do pozostałych, aktywnych członków** (`if (!member.isActive || member.memberId == myMemberId) continue`).
   * Zapewnia to **Post-Compromise Security / Post-Leave Secrecy**: wychodzący uczestnik nie ma dostępu do nowego stanu łańcucha i nie jest w stanie odszyfrować żadnej przyszłej wiadomości grupowej. Jednocześnie jednokierunkowość KDF chroni wiadomości przeszłe (**Forward Secrecy**).

### 8.5. Schemat Tabel Bazy Danych Room

#### Tabela `groups`:
```sql
CREATE TABLE IF NOT EXISTS groups (
    groupId TEXT NOT NULL PRIMARY KEY,
    groupName TEXT NOT NULL,
    myMemberId TEXT NOT NULL,
    myChainKeyOut BLOB NOT NULL,
    myCounterOut INTEGER NOT NULL DEFAULT 0,
    groupEpoch INTEGER NOT NULL DEFAULT 1,
    createdAt INTEGER NOT NULL,
    lastActive INTEGER NOT NULL,
    isActive INTEGER NOT NULL DEFAULT 1
);
```
* `myChainKeyOut`: 64-bajtowy stan łańcucha wyjściowego chroniony przez `EncryptedBlob` kluczem z Android Keystore powiązanym z wierszem `groups_${groupId}`.
* `groupEpoch`: numer epoki klucza (inkrementowany przy każdym rekeyu lub odejściu członka).

#### Tabela `group_members`:
```sql
CREATE TABLE IF NOT EXISTS group_members (
    groupId TEXT NOT NULL,
    memberId TEXT NOT NULL,
    contactId TEXT,
    memberName TEXT NOT NULL,
    chainKeyIn BLOB NOT NULL,
    counterIn INTEGER NOT NULL DEFAULT 0,
    joinedAt INTEGER NOT NULL,
    isActive INTEGER NOT NULL DEFAULT 1,
    receivedBitmapBase INTEGER NOT NULL DEFAULT 0,
    receivedBitmap BLOB NOT NULL,
    PRIMARY KEY(groupId, memberId)
);
CREATE INDEX IF NOT EXISTS index_group_members_groupId ON group_members (groupId);
CREATE INDEX IF NOT EXISTS index_group_members_contactId ON group_members (contactId);
```
* `chainKeyIn`: 64-bajtowy stan łańcucha wejściowego danego członka chroniony przez `EncryptedBlob` powiązany z `group_members_${groupId}_${memberId}`.
* `isActive`: flaga aktywności (`1` = aktywny, `0` = opuścił grupę / usunięty).
* `receivedBitmap`: przesuwna mapa bitowa replay protection zapobiegająca duplikacji pakietów grupowych.

---

## 9. Epoki Sekwencji i Okno Wyprzedzające (Lookahead Window)

Z uwagi na asynchroniczny charakter sieci UDP i DHT, pakiety mogą docierać z opóźnieniem lub w zmienionej kolejności.

1. **Okno Wyprzedzające (Lookahead Window $`n \dots n+4`$):**
   * Odbiorca, którego bieżący licznik to $`Counter_{in} = n`$, oblicza klucze i odpytuje DHT o sloty $`Target_n, Target_{n+1}, \dots, Target_{n+4}`$.
   * Jeśli nadejdzie wiadomość $`n+2`$, klucze dla slotów $`n`$ oraz $`n+1`$ są zapisywane w bezpiecznej tabeli `skipped_keys` (zaszyfrowane Keystore'em) na wypadek późniejszego dotarcia tych pakietów.
2. **Mapa Bitowa Odebranych Wiadomości (Sliding Bitmap Window):**
   * Do wykrywania i odrzucania duplikatów (Anti-Replay) służy 1024-bitowa przesuwna mapa bitowa w `ContactEntity` oraz `GroupMemberEntity`.
   * Wiadomości o numerze $`SeqNum < Counter_{in} - 1024`$ są bezwzględnie odrzucane.

---

## 10. Formalna Weryfikacja Bezpieczeństwa (docs/formal/)

Wszystkie kluczowe własności protokołu zostały poddane rygorystycznemu symbolicznemu dowodowi w narzędziu **ProVerif 2.05** w katalogu `docs/formal/` (24 lematy w 7 modelach):

| Własność Bezpieczeństwa | Plik Modelu | Weryfikowane Gwarancje Kryptograficzne | Wynik ProVerif |
| :--- | :--- | :--- | :--- |
| **Zunifikowany Protokół** | `pqchat_protocol.pv` | MasterKey, tory $`A \to B`$ i $`B \to A`$, ładunki AAD, transkrypt SAS i odporność na replay | `RESULT: True` (8/8) |
| **Poufność i Potwierdzenie** | `pqchat_secrecy.pv` | Poufność ładunków i injektywne uwierzytelnienie w hybrydowym KEM (ML-KEM-512 + X25519) | `RESULT: True` (5/5) |
| **Poufność Przeszła (FS)** | `pqchat_forward_secrecy.pv` | Ochrona dawnych wiadomości przy kompromitacji stanu łańcucha w pamięci RAM | `RESULT: True` (2/2) |
| **Samoleczenie (PCS)** | `pqchat_post_compromise.pv` | Przywrócenie poufności po wycieku kluczy dzięki rotacji asymetrycznej KEM | `RESULT: True` (2/2) |
| **Ochrona przed Replay** | `pqchat_replay.pv` | Injektywność akceptacji pakietów i unieważnianie slotów tombstone'ami | `RESULT: True` (2/2) |
| **Anonimowość i Tombstone'y** | `pqchat_unlinkability.pv` | Równoważność obserwacyjna adresów docelowych i nierozróżnialność 900-bajtowych tombstone'ów | `RESULT: True` (1/1) |
| **Protokół Grupowy i PCS/FS** | `pqchat_group_protocol.pv` | Dystrybucja kluczy nadawcy, wiązanie AAD i grupowe PCS/FS po odejściu członka | `RESULT: True` (4/4) |

### Szczegółowy opis dowiedzionych własności:

1. **Poufność (Secrecy):** Dowiedziono niemożliwości poznania klucza głównego $`MasterKey`$, stanów łańcucha $`ChainKey_{A \to B}, ChainKey_{B \to A}`$ oraz ładunków wiadomości tekstowych przez adwersarza Dolev-Yao podsłuchującego publiczne zapytania DHT oraz jawny kod QR (`pqchat_protocol.pv`, `pqchat_secrecy.pv`).
2. **Uwierzytelnienie i Transkrypt Handshake'u (Authentication & SAS Binding):** Dowiedziono injektywnej zgodności (`inj-event(AliceFinished) ==> inj-event(BobFinished)`), dowiązującej transkrypt, obronę dualną **Hybrid KEM (ML-KEM-512 + X25519)** oraz zobowiązanie SAS ($`Commitment`$).
3. **Forward Secrecy (Poufność Przeszła):** Dowiedziono (`pqchat_forward_secrecy.pv`), że wyciek stanu łańcucha $`ChainKey_1`$ nie pozwala na odszyfrowanie wcześniejszych wiadomości ($`msg_0`$).
4. **Post-Compromise Security (PCS / Samoleczenie):** Dowiedziono (`pqchat_post_compromise.pv`), że po wycieku kluczy łańcucha asymetryczna rotacja hybrydowa KEM przywraca pełną poufność kolejnych wiadomości.
5. **Odporność na Replay (Anti-Replay):** Dowiedziono injektywnej akceptacji pakietów (`pqchat_replay.pv` i `pqchat_protocol.pv`), uniemożliwiającej adwersarzowi wstrzyknięcie zduplikowanych ramek w sieci DHT oraz dowiedziono bezpiecznego unieważniania slotu pod sekwencją monotoniczną.
6. **Brak powiązania z tożsamością i Nierozróżnialność Tombstone'ów (Unlinkability & Tombstone Indistinguishability):** Dowiedziono równoważności obserwacyjnej (`diff-equivalence` w `pqchat_unlinkability.pv`) gwarantującej, że adresy $`\text{Target}_i = \text{SHA-1}(pk_i)`$ nie ujawniają tożsamości stron (Metadata-Free Rendezvous), a 900-bajtowe rekordy Tombstone (szum CSPRNG) są nierozróżnialne od normalnych ramek i ruchu maskującego.
7. **Czaty Grupowe i Rotacja Kluczy (Group Protocol & PCS/FS):** Dowiedziono (`pqchat_group_protocol.pv`):
   * poufności klucza łańcucha nadawcy grupy dystrybuowanego w ramce Typu `0x06` (`TYPE_GROUP_CONTROL`) przez hybrydowy kanał 1-na-1 (ML-KEM-512 + X25519),
   * autentyczności wiadomości grupowych z wiązaniem AAD ($`\text{Target} \parallel GroupID \parallel SenderMemberID`$),
   * Forward Secrecy dawnych wiadomości grupowych przed odejściem członka,
   * Post-Compromise Security / Post-Leave Secrecy wiadomości w nowej epoce $`groupEpoch + 1`$ po odejściu członka (`GROUP_SUBTYPE_LEAVE`) i rotacji kluczy.

Uruchomienie weryfikacji formalnej:
```bash
bash docs/formal/run_verification.sh
```

---

## 11. Strategia Testowania

Zgodnie z wytycznymi projektu testy podzielono na dwie kategorie:

1. **Szybkie testy jednostkowe co commit (Fast Unit Tests):**
   * Uruchamiane poleceniem: `.\gradlew.bat testDebugUnitTest`
   * Wykonują się w kilkadziesiąt sekund, automatycznie pomijając testy oznaczone adnotacją `@Tag("slow")`.
2. **Czasochłonne testy integracyjne i statystyczne (Slow Tests):**
   * Testy repozytorium (`org.pqchat.dht.data.repository.*`), testy statystyczne Monte Carlo (`TrafficThreatModelStatisticalTest`) oraz pomiary loopback (`LoopbackMeasurementHarnessTest`) są oznaczone `@Tag("slow")`.
   * Wykonywane w dedykowanym zadaniu nocnym GitHub Actions (`.github/workflows/nightly.yml`) o 02:00 UTC lub lokalnie:
     ```bash
     .\gradlew.bat testDebugUnitTest -DrunSlowTests=true
     # lub
     .\gradlew.bat slowTest
     ```

