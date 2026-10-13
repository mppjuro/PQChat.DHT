# Cykl Życia Pollingu i Praca w Tle na Platformie Android (PQChat DHT)

Niniejszy dokument opisuje architekturę maszyny stanów cyklu życia pollingu, odporność na zamrażanie procesów pod Android 12+ (Cached App Freezer), ograniczenia Foreground Service `dataSync` pod Android 15 (targetSdk 35) oraz mechanizmy przywracania pracy w tle po restarcie urządzenia (`BOOT_COMPLETED` + WorkManager).

---

## 1. Architektura 4-Stanowej Maszyny Stanów Pollingu

Zgodnie z wytycznymi w [AGENTS.md](file:///c:/Users/PJURO/PQChat.DHT/AGENTS.md#L146-L151), interwały odpytywania sieci DHT są adaptacyjnie dostosowywane do kontekstu użytkownika i urządzenia:

| Stan | Interwał Bazowy | Warunki Aktywacji | Sterowanie / Pętla |
| :--- | :--- | :--- | :--- |
| **`FOREGROUND_CHAT`** | 10 sekund ($\pm 30\%$ jitter) | Ekran WŁĄCZONY + Aplikacja na pierwszym planie + Aktywne okno rozmowy (`activeChatContactId != null`) | In-process Coroutine Loop (`AdaptivePollingManager`) |
| **`APP_ACTIVE_OTHER`** | 60 sekund ($\pm 30\%$ jitter) | Ekran WŁĄCZONY + Aplikacja na pierwszym planie + Brak aktywnego czatu (lista kontaktów, diagnostyka, ustawienia) | In-process Coroutine Loop (`AdaptivePollingManager`) |
| **`BACKGROUND_IDLE`** | 300 sekund / 5 min ($\pm 30\%$ jitter) | Ekran WŁĄCZONY + Aplikacja w tle (zminimalizowana, użytkownik korzysta z telefonu) | In-process Coroutine Loop + AlarmManager fallback |
| **`DOZE_SLEEP`** | 900 sekund / 15 min | Ekran WYŁĄCZONY (urządzenie zablokowane / uśpione, tryb Doze) | Pętla wstrzymana; sterowanie wyłącznie przez `AlarmManager.setAndAllowWhileIdle` + `WorkManager` |

### Tabela Prawdy (Deterministyczna Rezolucja Stanu)

Rezolucja stanu jest czystą funkcją deterministyczną `AdaptivePollingManager.resolvePollingState`:

$$\text{PollingState} = f(\text{isScreenInteractive}, \text{isAppForeground}, \text{activeChatContactId})$$

| `isScreenInteractive` (Ekran) | `isAppForeground` (Aplikacja) | `activeChatContactId` (Rozmowa) | Rezultat Maszyny Stanów |
| :---: | :---: | :---: | :--- |
| **`false`** | *dowolny* | *dowolny* | **`DOZE_SLEEP`** (15 min) |
| **`true`** | **`false`** | *dowolny* | **`BACKGROUND_IDLE`** (5 min) |
| **`true`** | **`true`** | `null` | **`APP_ACTIVE_OTHER`** (1 min) |
| **`true`** | **`true`** | `ID != null` | **`FOREGROUND_CHAT`** (10 s) |

### Naprawa Błędu Cyklu Życia (Separacja Ekranu i Aktywności):
* **Błąd pierwotny:** Mapowanie `ON_STOP` pojedynczej `Activity` bezpośrednio na zdarzenie wyłączenia ekranu (`onDeviceScreenOff()`) prowadziło do fałszywego wprowadzania aplikacji w tryb głębokiego uśpienia `DOZE_SLEEP` (15 min) w momencie, gdy użytkownik po prostu zminimalizował aplikację, a ekran telefonu pozostał włączony (powinien nastąpić stan `BACKGROUND_IDLE`, 5 min). Ponadto, zmiana konfiguracji aktywności (rotacja ekranu) tymczasowo wywoływała `ON_STOP`, zakłócając polling.
* **Rozwiązanie w `PollingLifecycleCoordinator`:**
  1. `ProcessLifecycleOwner` śledzi stan całego procesu aplikacji na poziomie systemu (ignorując transientne restarty aktywności przy rotacji ekranu).
  2. Stan ekranu jest weryfikowany niezależnie za pomocą dynamicznego odbiornika `ScreenStateReceiver` (`Intent.ACTION_SCREEN_OFF` i `Intent.ACTION_SCREEN_ON`) oraz odpytywania `PowerManager.isInteractive`.
  3. Pojedynczy punkt decyzyjny `PollingLifecycleCoordinator` aktualizuje wejścia maszyny stanów przez `AdaptivePollingManager.updateInputs(...)`, gwarantując spójność atomową bez wyścigów wątków.

---

## 2. Zachowanie pod Android 12+ (API 31+) — Cached App Freezer (CAF)

### Mechanizm Działania Cached App Freezer:
Od wersji Android 11 (jako eksperyment) i Android 12+ (jako standard), system operacyjny wykorzystuje mechanizm jądra Linux **cgroup v2 freezer** (`/sys/fs/cgroup/uid_.../cgroup.freeze`).

Gdy proces aplikacji przechodzi do stanu pamięci podręcznej (`CACHED_APP` — brak widocznych aktywności, brak aktywnej usługi Foreground Service z blokadą WakeLock), system w ciągu 10–60 sekund zamraża wszystkie wątki procesu:
* Wszystkie wątki JVM oraz coroutines Kotlin (`delay()`) przestają otrzymywać czas procesora.
* Gniazda UDP/TCP przestają przetwarzać pakiety w buforach odbiorczych.
* Zwykła pętla `delay(300_000L)` uruchomiona w coroutine w stanie `BACKGROUND_IDLE` **nie wykona się o wyznaczonym czasie**, dopóki proces nie zostanie odmrożony przez zewnętrzne zdarzenie systemowe.

### Architektura Odmrażania w PQChat:
1. **Odmrażanie przez `AlarmManager.setAndAllowWhileIdle`:**
   * Przy przejściu w stan `BACKGROUND_IDLE` lub `DOZE_SLEEP` rejestrowany jest alarm `DhtAlarmReceiver`.
   * Alarm z flagą `RTC_WAKEUP` i `setAndAllowWhileIdle` wybudza proces z zamrożenia nawet w najgłębszych fazach Doze.
   * `DhtAlarmReceiver` natychmiast przejmuje `PARTIAL_WAKE_LOCK` (maks. 30 s), uniemożliwiając ponowne zamrożenie procesu podczas wykonywania zapytań KRPC DHT i odzyskiwania wiadomości.
2. **Periodyczne Konserwacje WorkManager (`PollingWorker`):**
   * Co 15 minut (minimalny dopuszczalny interwał WorkManager) system Android uruchamia `PollingWorker` z ograniczeniem `NetworkType.CONNECTED`.
   * Odmraża to proces w oficjalnym oknie konserwacji systemu, synchronizując skrzynkę i retransmitując pakiety podlegające mechanizmowi Exponential Backoff.
3. **Natychmiastowe Odmrażanie Zdarzeniami Użytkownika:**
   * Włączenie ekranu (`ACTION_SCREEN_ON`) lub ponowne otwarcie aplikacji (`ProcessLifecycleOwner.ON_START`) powoduje natychmiastowe odmrożenie procesu przez system i synchroniczne przeliczenie stanu w `PollingLifecycleCoordinator`.

---

## 3. Ograniczenia `dataSync` Foreground Service pod Android 15 (targetSdk 35)

### Restrykcje Systemowe Android 15 (API 35):
W systemie Android 15 (API 35) firma Google wprowadziła rygorystyczne limity czasu wykonania dla usług Foreground Service o typie `dataSync` (`FOREGROUND_SERVICE_TYPE_DATA_SYNC`):
1. **Budżet Czasowy:** Maksymalnie **6 godzin łącznego działania w ruchomym oknie 24-godzinnym**.
2. **Obsługa Przekroczenia Limitu (`onTimeout`):**
   * Gdy 6-godzinny budżet dobiega końca, system wywołuje metodę:
     ```kotlin
     Service.onTimeout(startId: Int, fgsType: Int)
     ```
   * Aplikacja otrzymuje krótki czas (kilka sekund) na zatrzymanie usługi przez `stopSelf(startId)`.
   * Niezastosowanie się do tego wymogu skutkuje natychmiastowym rzuceniem przez system nieprzechwytywalnego wyjątku `ForegroundServiceDidNotStopInTimeException` i zatrzymaniem (crashem) całej aplikacji!

### Implementacja w `ChatHeadService`:
1. `ChatHeadService` nadpisuje metodę `onTimeout(startId, fgsType)`:
   * Rejestruje ostrzeżenie w logach systemowych.
   * Anuluje bieżącą pętlę coroutines.
   * Wywołuje `stopSelf(startId)`, gwarantując czyste i bezpieczne zamknięcie usługi bez błędu ANR / crashu.
2. **Architektoniczne Rozdzielenie Odpowiedzialności:**
   * `ChatHeadService` jest traktowany wyłącznie jako **opcjonalna optymalizacja** dla użytkowników pragnących widocznego wskaźnika aktywnej łączności P2P.
   * Podstawowe, niezawodne działanie komunikatora w tle **nie opiera się na ciągłym Foreground Service**, lecz na połączeniu `AlarmManager.setAndAllowWhileIdle` oraz `WorkManager`. Dzięki temu aplikacja zachowuje 100% odporności na 6-godzinny limit Androida 15 i spełnia rygorystyczne wymogi Google Play.

---

## 4. Przywracanie po Restarcie Urządzenia (`BOOT_COMPLETED` i WorkManager)

### Problem Utraty Zadań przy Restarcie:
1. Wszystkie alarmy zarejestrowane przez `AlarmManager` w systemie Android są **bezpowrotnie usuwane z pamięci systemu** w momencie restartu urządzenia lub wyłączenia zasilania.
2. Proces aplikacji nie jest automatycznie uruchamiany po starcie telefonu, chyba że zarejestrowano dedykowany odbiornik rozgłoszeniowy.

### Podwójna Warstwa Przywracania w PQChat:

```
[ Restart Urządzenia / BOOT_COMPLETED ]
                   │
         ┌─────────┴─────────┐
         ▼                   ▼
 [ WorkManager workdb ]    [ BootReceiver ]
         │                   │
         ▼                   ├─► Re-enqueue PollingWorker
 Automatyczny restart        ├─► Reschedule AlarmManager Doze Alarm
 periodycznych zadań         └─► Restore Pending Republish Tasks
 w tle (SQLite)
```

1. **`BootReceiver` (`android.intent.action.BOOT_COMPLETED` & `ACTION_MY_PACKAGE_REPLACED`):**
   * Zadeklarowany statycznie w `AndroidManifest.xml` z uprawnieniem `RECEIVE_BOOT_COMPLETED`.
   * Po restarcie urządzenia natychmiast wywołuje `goAsync()` i w wątku `Dispatchers.IO`:
     - Przywraca alarm Doze przez `PollingScheduler.scheduleNextDozeAlarm()`.
     - Weryfikuje i przywraca harmonogram retransmisji wiadomości oczekujących w bazie Room (`applyRepublishSchedule()`).
     - Ponownie zgłasza zadanie `PollingWorker.enqueuePeriodicWork(context)`.
2. **Wewnętrzna Persystencja WorkManager:**
   * Zadania okresowe zarejestrowane przez `WorkManager.enqueueUniquePeriodicWork` z flagą `ExistingPeriodicWorkPolicy.KEEP` są persystowane w wewnętrznej bazie danych SQLite WorkManager (`androidx.work.workdb`).
   * Biblioteka `androidx.work` posiada własny wbudowany `RescheduleReceiver`, który niezależnie weryfikuje i wznawia zadania po restarcie urządzenia.

---

## 5. Podsumowanie Weryfikacji i Testów

Prawidłowość działania maszyny stanów została potwierdzona deterministycznymi testami jednostkowymi bez użycia opóźnień czasowych (`Thread.sleep`, `delay`):
* `AdaptivePollingStateMachineTest`: testy pełnej tabeli prawdy, przejść 4 stanów, minimalizacji aplikacji bez utraty celu czatu, wygaszania ekranu i odporności na szybkie przełączanie.
* `PollingLifecycleCoordinatorTest`: testy integracji z `LifecycleOwner` (Robolectric), odbiornikiem ekranu oraz automatycznej synchronizacji alarmu Doze.
* `ScreenStateReceiverTest` & `BootReceiverTest`: testy odbiorników rozgłoszeniowych i filtrów intencji.
