# Formalna Weryfikacja Protokołu PQChat.DHT (ProVerif)

Katalog zawiera formalną specyfikację i dowody bezpieczeństwa protokołu **PQChat.DHT** w symbolicznym modelu Dolev-Yao przy użyciu narzędzia **ProVerif 2.05**.

---

## 1. Zakres Modelu i Dowiedzione Własności

Protokół łączy post-kwantowy mechanizm hermetyzacji kluczy (**ML-KEM-512** / FIPS 203), jednostronny podwójny ratchet (**Dual Unidirectional Ratchet** oparty o **HKDF-SHA512**), szyfrowanie **AES-256-GCM**, jednorazowe podpisy transportowe **Ed25519 (BEP 44)** oraz przeskakiwanie hashy (**Key Hopping** $\text{Target}_i = \text{SHA-1}(pk_i)$).

Weryfikacji poddano cztery kluczowe filary bezpieczeństwa:

### (a) Poufność Kluczy Łańcucha i Wiadomości (`pqchat_secrecy.pv`)
* **Lemat A1 / A2 (`secret_chain_A2B`, `secret_chain_B2A`):** Obserwator sieci DHT nie jest w stanie poznać początkowych ani kolejnych kluczy łańcucha $ChainKey_{A \to B}$ i $ChainKey_{B \to A}$.
* **Lemat A3 / A4 (`secret_msg_A2B`, `secret_msg_B2A`):** Ładunki przesyłanych wiadomości na obu torach transmisyjnych są w pełni poufne.
* **Lemat A5 (Key Confirmation & Authentication):** Uwierzytelnienie i transkrypt handshake'u (`inj-event(AliceFinished) ==> inj-event(BobFinished)`) gwarantują odporność na atak podszywania się, podmianę `ct` KEM oraz desynchronizację kluczy.

### (b) Forward Secrecy po Kompromitacji Klucza Efemerycznego (`pqchat_forward_secrecy.pv`)
* **Lemat B1 (`secret_msg_0`):** Wyciek późniejszego stanu łańcucha $ChainKey_1$ do adwersarza (np. w wyniku analizy pamięci RAM po restarcie urządzenia) **nie pozwala** odszyfrować wcześniejszych wiadomości ($msg_0$). Wynika to z jednokierunkowości funkcji wyprowadzania HKDF-SHA512.
* **Lemat B2 (`secret_msg_1`):** Wiadomość powiązana z ujawnionym kluczem zostaje skompromitowana, co dowodzi poprawności i nietrywialności modelu adwersarza.

### (c) Post-Compromise Security po Rekey PQC (`pqchat_post_compromise.pv`)
* **Lemat C1 (`secret_new_chain_key`):** Po pełnej kompromitacji bieżącego stanu $ChainKey_{old}$, przeprowadzenie rotacji epoki za pomocą świeżej pary kluczy ML-KEM-512 ($pk_{rekey}, sk_{rekey}$) przywraca poufność nowego stanu:
  $$ChainKey_{new} = \text{HKDF-Extract}(ChainKey_{old}, SS_{rekey})$$
* **Lemat C2 (`secret_msg_post_rekey`):** Wszystkie wiadomości nadane po rotacji epoki odzyskują pełną ochronę kryptograficzną (samoleczenie / Post-Compromise Security).

### (d) Anonimowość i Brak Powiązania Targetu z Tożsamością (`pqchat_unlinkability.pv`)
* **Lemat D1 (Observational Equivalence):** Węzły publicznej sieci BitTorrent DHT obserwujące zapytania PUT/GET pod adres $\text{Target}_i = \text{SHA-1}(pk_i)$ nie są w stanie odróżnić zapytań sesji $(Alice, Bob)$ od zapytań sesji $(Charlie, Dave)$ ani od ciągów pseudolosowych.
* Dowiedziono równoważności obserwacyjnej (`diff-equivalence` w ProVerif), co potwierdza brak wycieku metadanych (Metadata-Free Rendezvous).

---

## 2. Uruchomienie Testów

Aby uruchomić pełny zestaw dowodów i wygenerować raport:

```bash
./formal/run.sh
```

Skrypt automatycznie:
1. Wykrywa instalację ProVerif (w ścieżce systemowej, WSL Ubuntu lub binariach lokalnych).
2. Weryfikuje każdy z 4 modeli `.pv`.
3. Sprawdza poprawność wyników zapytań.
4. Generuje szczegółowy raport w pliku `formal/report.txt`.
5. Kończy działanie kodem wyjścia `0` w przypadku zdania wszystkich lematów.
