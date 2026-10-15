# Formalna Weryfikacja Bezpieczeństwa Protokołu PQChat.DHT (ProVerif 2.05)

Katalog zawiera kompletne formalne modele kryptograficzne oraz dowody bezpieczeństwa protokołu **PQChat.DHT** w symbolicznym modelu Dolev-Yao przy użyciu analizatora **ProVerif 2.05**.

---

## 1. Zakres Modeli i Weryfikowane Własności

Protokół łączy:
* **Hybrydowy mechanizm hermetyzacji kluczy (Hybrid KEM):** Połączenie post-kwantowego **ML-KEM-512** (FIPS 203) oraz klasycznego **X25519 ECDH** (RFC 7748) dla obrony dualnej (*Dual-Defense / IND-CCA2*).
* **Jednostronne podwójne łańcuchy (Dual Unidirectional Chains):** Oparte na **HKDF-SHA512** (RFC 5869), gdzie tor $A \to B$ i tor $B \to A$ są całkowicie odseparowane numerycznie i adresowo.
* **Szyfrowanie ładunków z dowiązanym kontekstem (AEAD):** **AES-256-GCM** z dowiązaniem AAD do adresu target i kierunku transmisji.
* **Zobowiązanie przeciw mieleniu i SAS (Anti-Grinding & SAS):** Skrót **SHA-256** ze zobowiązaniem transkryptu $`Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)`$ oraz 8-cyfrowy kod **Short Authentication String (SAS)**.
* **Jednorazowe podpisy transportowe Ed25519 (BEP 44):** Wykorzystywane jako jednorazowy token efemeryczny do zapisu w sieci DHT.
* **Skakanie po slotach (Key Hopping):** Efemeryczny adres docelowy $\text{Target}_i = \text{SHA-1}(pk_i)$.
* **Bezpieczne czyszczenie slotu (900-bajtowy Tombstone):** Nadpisanie skonsumowanego rekordu w DHT sztywną 900-bajtową ramką szumu CSPRNG pod numerem sekwencji $\text{seq} + 1$, co uniemożliwia węzłom DHT oraz podsłuchiwaczom wykrycie momentu odbioru wiadomości.

Weryfikacji poddano sześć fundamentalnych filarów bezpieczeństwa:

### (1) Poufność (Secrecy)
* **Poufność Klucza Głównego i Łańcuchów (`pqchat_protocol.pv`, `pqchat_secrecy.pv`):**
  * `Query not attacker(secret_master_key[]) is true`
  * `Query not attacker(secret_chain_A2B[]) is true`
  * `Query not attacker(secret_chain_B2A[]) is true`
  * Obserwator publicznej sieci DHT oraz fizyczny obserwator jawnego kodu QR ($pk_A^{hybrid} \parallel Seed_{init}$) nie są w stanie poznać klucza głównego $MasterKey$ ani kluczy torów $ChainKey_{A \to B}$, $ChainKey_{B \to A}$.
* **Poufność Ładunków Wiadomości:**
  * `Query not attacker(secret_msg_A2B[]) is true`
  * `Query not attacker(secret_msg_B2A[]) is true`
  * Treści wymieniane w obu kierunkach są nieosiągalne dla adwersarza Dolev-Yao.

### (2) Uwierzytelnienie i Transkrypt Handshake'u (Authentication & SAS Binding)
* **Zgodność Injektywna Stron (`pqchat_protocol.pv`, `pqchat_secrecy.pv`):**
  * `Query inj-event(AliceFinished(pkA_kem, pkA_x, seed, ckA2B, ckB2A, sas)) ==> inj-event(BobFinished(pkA_kem, pkA_x, seed, ckA2B, ckB2A, sas)) is true`
  * Zakończenie fazy handshake przez Alice gwarantuje, że Bob brał udział w tej samej sesji z identycznym transkryptem, tożsamymi kluczami hybrydowymi KEM (ML-KEM-512 + X25519) oraz zgodnym kodem SAS.
  * Zobowiązanie przeciw mieleniu $Commitment$ uniemożliwia adwersarzowi manipulację parametrami w locie przy zachowaniu zgodnego kodu SAS.

### (3) Forward Secrecy (Poufność Przeszła)
* **Odporność na Kompromitację Stanu Łańcucha (`pqchat_forward_secrecy.pv`):**
  * `Query not attacker(secret_msg_0[]) is true`
  * `Query not attacker(secret_msg_1[]) is false` (dowód nietrywialności ataku)
  * Gdy adwersarz uzyska fizyczny dostęp do pamięci urządzenia w kroku $i=1$ i pozna $ChainKey_1$, jednokierunkowość HKDF-SHA512 gwarantuje, że nie może on wyliczyć wstecz $ChainKey_0$, a zatem wiadomość $msg_0$ pozostaje w pełni poufna.

### (4) Post-Compromise Security / PCS (Samoleczenie Stanu)
* **Regeneracja Poufności po Rotacji Hybrydowej KEM (`pqchat_post_compromise.pv`):**
  * `Query not attacker(secret_new_chain_key[]) is true`
  * `Query not attacker(secret_msg_post_rekey[]) is true`
  * Nawet jeśli adwersarz całkowicie przejmie stan łańcucha ($ChainKey_{old}$), po przeprowadzeniu asymetrycznego rekeyingu hybrydowego ML-KEM-512 + X25519 (oferta Typu `0x03` + odpowiedź Typu `0x04`), wstrzyknięcie świeżego sekretu:
    $$ChainKey_{new} \leftarrow \text{HKDF-Extract}(ChainKey_{old}, SS_{rekey}^{hybrid})$$
    przywraca pełną poufność kluczy i wszystkich kolejnych wiadomości.

### (5) Odporność na Replay (Replay Resistance)
* **Injektywność Dostarczenia Pakietów (`pqchat_replay.pv` i `pqchat_protocol.pv`):**
  * `Query inj-event(HandshakeAccepted(target, ct, pkx, salt)) ==> inj-event(HandshakeSent(target, ct, pkx, salt)) is true`
  * `Query inj-event(BobRecvMsg(target, seq, msg)) ==> inj-event(AliceSentMsg(target, seq, msg)) is true`
  * `Query inj-event(AliceRecvReply(target, seq, msg)) ==> inj-event(BobSentReply(target, seq, msg)) is true`
  * Żaden pakiet w sieci DHT nie może zostać zaakceptowany powtórnie. Wynika to z unikalnych adresów przeskakiwania $Target_i = \text{SHA-1}(pk_i)$, świeżych wektorów IV, wiązania AAD, okna sekwencji oraz bezpiecznego nadpisywania slotu tombstone'em.

### (6) Anonimowość i Nierozróżnialność Tombstone'ów (Unlinkability & Tombstone Indistinguishability)
* **Równoważność Obserwacyjna (`pqchat_unlinkability.pv`):**
  * `Query Observational equivalence is true`
  * Węzły sieci DHT obserwujące zapytania pod adresy $\text{Target}_i = \text{SHA-1}(pk_i)$ nie są w stanie odróżnić zapytań sesji $(Alice, Bob)$ od zapytań sesji $(Charlie, Dave)$ (Metadata-Free Rendezvous).
  * Sztywny 900-bajtowy rekord Tombstone (CSPRNG noise) zapisywany po odebraniu wiadomości jest matematycznie nierozróżnialny od normalnej 900-bajtowej ramki zaszyfrowanej AES-256-GCM ani od 900-bajtowego pakietu ruchu maskującego (Poisson cover traffic dummy).

---

## 2. Zunifikowany Zestaw Modeli Formalnych

| Plik | Opis i Weryfikowane Własności |
| :--- | :--- |
| `pqchat_protocol.pv` | **Główny, zunifikowany model protokołu:** dowodzi poufności klucza głównego i łańcuchów, ładunków wiadomości, injektywnego uwierzytelnienia z dowiązaniem SAS i transcriptu, dwukierunkowej wymiany z AAD oraz odporności na replay i bezpiecznych 900-bajtowych tombstone'ów. |
| `pqchat_secrecy.pv` | **Dedykowany model poufności i potwierdzenia klucza:** weryfikacja $ChainKey_{A \to B}, ChainKey_{B \to A}$, poufności ładunków oraz injektywnego porozumienia stron z handshake'iem hybrydowym X25519 + ML-KEM-512. |
| `pqchat_forward_secrecy.pv` | **Model Forward Secrecy:** formalny dowód ochrony przeszłych wiadomości przy wycieku późniejszych stanów łańcucha w pamięci RAM. |
| `pqchat_post_compromise.pv` | **Model Post-Compromise Security (PCS):** formalny dowód samoleczenia stanu po rotacji hybrydowej X25519 + ML-KEM-512. |
| `pqchat_replay.pv` | **Model Anti-Replay:** dowód injektywnej akceptacji pakietów handshake i transmisji danych z unieważnianiem slotu. |
| `pqchat_unlinkability.pv` | **Model Unlinkability & Tombstones:** dowód równoważności obserwacyjnej (`diff-equivalence`) dla przeskakiwania targetów oraz nierozróżnialności 900-bajtowych tombstone'ów od normalnych ramek i cover traffic. |
| `run_verification.sh` | Skrypt automatyzujący uruchomienie dowodów w ProVerif, agregację wyników, rygorystyczne sprawdzenie 20 lematów i generowanie raportu `report.txt`. |
| `report.txt` | Pełny raport z wynikami analizy Dolev-Yao wygenerowany przez ProVerif. |

---

## 3. Instrukcja Uruchomienia Dowodów

Do uruchomienia modeli wymagane jest środowisko z zainstalowanym **ProVerif** (wersja $\ge 2.04$):

```bash
# Uruchomienie pełnego zestawu dowodów (20 lematów w 6 modelach):
bash docs/formal/run_verification.sh
```

Skrypt automatycznie:
1. Wykrywa binaria ProVerif w PATH, `/usr/local/bin`, WSL Ubuntu lub kompiluje bezpośrednio ze źródeł Inria w środowisku Linux/CI.
2. Wykonuje analizę symboliczną każdego z 6 modeli `.pv`.
3. Weryfikuje dokładne formuły lematów (20/20 PASS).
4. Generuje szczegółowy raport w pliku `docs/formal/report.txt`.
5. Zwraca kod wyjścia `0` w przypadku zdania wszystkich lematów.
