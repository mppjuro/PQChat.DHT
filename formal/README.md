# Modele Formalnej Weryfikacji ProVerif (docs/formal/)

Modele formalne ProVerif zostały zunifikowane i zaktualizowane w katalogu **[`docs/formal/`](../docs/formal/)**.

Aby uruchomić pełny zestaw dowodów formalnych (6 modeli, 20 sprawdzonych lematów):

```bash
bash docs/formal/run_verification.sh
```

lub za pośrednictwem skryptu przekierowującego:

```bash
./formal/run.sh
```

Szczegółowy opis modeli kryptograficznych (hybrydowy KEM ML-KEM-512 + X25519, 900-bajtowe bezpieczne tombstone'y, zobowiązanie przeciw mieleniu Anti-Grinding SAS, podwójne niezależne tory transmisyjne) znajduje się w **[`docs/formal/README.md`](../docs/formal/README.md)**.
