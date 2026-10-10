# Formalna Weryfikacja Bezpieczeństwa Protokołu PQChat.DHT (ProVerif)

Katalog zawiera kompletne formalne modele kryptograficzne oraz dowody bezpieczeństwa protokołu **PQChat.DHT** w symbolicznym modelu Dolev-Yao przy użyciu analizatora **ProVerif 2.05**.

---

## 1. Zakres Modelu i Weryfikowane Własności

Protokół łączy post-kwantowy mechanizm hermetyzacji kluczy (**ML-KEM-512** / FIPS 203), jednostronny podwójny ratchet (**Dual Unidirectional Chains** oparty na **HKDF-SHA512**), szyfrowanie z dowiązanym kontekstem (**AES-256-GCM** z AAD), jednorazowe podpisy transportowe **Ed25519 (BEP 44)**, skakanie po slotach DHT (**Key Hopping** $\text{Target}_i = \text{SHA-1}(pk_i)$) oraz wzmocniony **Short Authentication String (SAS)** ze zobowiązaniem przeciw mieleniu (**Anti-Grinding Commitment**).

Weryfikacji poddano pięć fundamentalnych własności bezpieczeństwa:

### (1) Poufność (Secrecy)
* **Poufność Klucza Głównego i Łańcuchów (`pqchat_protocol.pv`):**
  * `Query not attacker(secret_master_key[]) is true`
  * `Query not attacker(secret_chain_A2B[]) is true`
  * `Query not attacker(secret_chain_B2A[]) is true`
  * Obserwator publicznej sieci DHT oraz fizyczny obserwator jawnego kodu QR ($pk_A \parallel Seed_{init}$) nie są w stanie poznać klucza głównego $MasterKey$ ani kluczy torów $ChainKey_{A \to B}$, $ChainKey_{B \to A}$.
* **Poufność Ładunków Wiadomości:**
  * `Query not attacker(secret_msg_A2B[]) is true`
  * `Query not attacker(secret_msg_B2A[]) is true`
  * Treści wymieniane w obu kierunkach są nieosiągalne dla adwersarza Dolev-Yao.

### (2) Uwierzytelnienie i Transkrypt Handshake'u (Authentication & SAS Binding)
* **Zgodność Injektywna Stron (`pqchat_protocol.pv`):**
  * `Query inj-event(AliceFinished(pkA, seed, ckA2B, ckB2A, sas)) ==> inj-event(BobFinished(pkA, seed, ckA2B, ckB2A, sas)) is true`
  * Zakończenie fazy handshake przez Alice gwarantuje, że Bob brał udział w tej samej sesji z identycznym transkryptem, tożsamymi kluczami łańcucha oraz identycznym 8-cyfrowym kodem SAS.
  * Zobowiązanie przeciw mieleniu $Commitment = \text{SHA-256}(\text{"PQChat\_AntiGrind\_v2"} \parallel Seed_{init} \parallel Transcript)$ uniemożliwia adwersarzowi manipulację parametrami w locie przy zachowaniu zgodnego kodu SAS.

### (3) Forward Secrecy (Poufność Przeszła)
* **Odporność na Kompromitację Stanu Łańcucha (`pqchat_forward_secrecy.pv`):**
  * `Query not attacker(secret_msg_0[]) is true`
  * `Query not attacker(secret_msg_1[]) is false` (dowód nietrywialności ataku)
  * Gdy adwersarz uzyska fizyczny dostęp do pamięci urządzenia w kroku $i=1$ i pozna $ChainKey_1$, jednokierunkowość HKDF-SHA512 gwarantuje, że nie może on wyliczyć wstecz $ChainKey_0$, a zatem wiadomość $msg_0$ pozostaje w pełni poufna.

### (4) Post-Compromise Security / PCS (Samoleczenie Stanu)
* **Regeneracja Poufności po Rotacji ML-KEM-512 (`pqchat_post_compromise.pv`):**
  * `Query not attacker(secret_new_chain_key[]) is true`
  * `Query not attacker(secret_msg_post_rekey[]) is true`
  * Nawet jeśli adwersarz całkowicie przejmie stan łańcucha ($ChainKey_{old}$), po przeprowadzeniu asymetrycznego rekeyingu ML-KEM-512 (oferta Typu `0x03` + odpowiedź Typu `0x04`), wstrzyknięcie świeżego sekretu post-kwantowego:
    $$ChainKey_{new} \leftarrow \text{HKDF-Extract}(ChainKey_{old}, SS_{rekey})$$
    przywraca pełną poufność kluczy i wszystkich kolejnych wiadomości.

### (5) Odporność na Replay (Replay Resistance)
* **Injektywność Dostarczenia Pakietów (`pqchat_replay.pv` i `pqchat_protocol.pv`):**
  * `Query inj-event(HandshakeAccepted(target, ct, salt)) ==> inj-event(HandshakeSent(target, ct, salt)) is true`
  * `Query inj-event(BobRecvMsg(target, seq, msg)) ==> inj-event(AliceSentMsg(target, seq, msg)) is true`
  * `Query inj-event(AliceRecvReply(target, seq, msg)) ==> inj-event(BobSentReply(target, seq, msg)) is true`
  * Żaden pakiet w sieci DHT nie może zostać zaakceptowany powtórnie. Wynika to z kombinacji unikalnych adresów przeskakiwania $Target_i = \text{SHA-1}(pk_i)$, świeżych wektorów IV, wiązania AAD oraz przesuwnego okna sekwencji.

---

## 2. Pliki Modeli Formalnych

| Plik | Opis i Weryfikowane Własności |
| :--- | :--- |
| `pqchat_protocol.pv` | **Główny, zunifikowany model protokołu:** dowodzi poufności kluczy i wiadomości, injektywnego uwierzytelnienia z dowiązaniem SAS i transcriptu, oraz odporności na replay wiadomości na obu torach. |
| `pqchat_forward_secrecy.pv` | **Model Forward Secrecy:** formalny dowód ochrony przeszłych wiadomości przy wycieku późniejszych stanów łańcucha. |
| `pqchat_post_compromise.pv` | **Model Post-Compromise Security (PCS):** formalny dowód samoleczenia stanu po rotacji ML-KEM-512. |
| `pqchat_replay.pv` | **Model Anti-Replay:** dowód injektywnej akceptacji pakietów handshake i transmisji danych. |
| `run_verification.sh` | Skrypt automatyzujący uruchomienie dowodów w ProVerif i agregację wyników. |

---

## 3. Instrukcja Uruchomienia Dowodów

Do uruchomienia modeli wymagane jest środowisko z zainstalowanym **ProVerif** (wersja $\ge 2.04$):

```bash
# Uruchomienie pełnego zestawu dowodów:
bash docs/formal/run_verification.sh
```

Wszystkie zapytania (`RESULT ... is true`) zostają pomyślnie zweryfikowane bez fałszywych alarmów ani zapętleń reguł Horna.
