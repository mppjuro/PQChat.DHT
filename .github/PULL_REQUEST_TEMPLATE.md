## Opis zmian
Zwięzłe podsumowanie wprowadzonych zmian, rozwiązanych problemów lub dodanych funkcjonalności.

## Powiązane zgłoszenia (Issues)
Zamyka: #... / Odnosi się do: #...

## Typ zmian
- [ ] 🐛 Poprawka błędu (`fix:`)
- [ ] ✨ Nowa funkcjonalność (`feat:`)
- [ ] ♻️ Refaktoryzacja kodu (`refactor:`)
- [ ] ⚡ Optymalizacja wydajności (`perf:`)
- [ ] 📚 Dokumentacja (`docs:`)
- [ ] 📦 Zależności / Gradle (`build:` / `ci:`)
- [ ] 🧪 Testy (`test:`)

## Checklista weryfikacyjna
Przed zgłoszeniem Pull Requesta upewnij się, że spełniasz poniższe kryteria:
- [ ] **Testy jednostkowe przechodzą:** Wykonano pomyślnie `./gradlew testDebugUnitTest` lokalnie.
- [ ] **Brak hardcodowanych sekretów:** W kodzie nie ma osadzonych kluczy prywatnych, tokenów, ziaren KDF ani logowania plaintextu (`Log.d`, `println`).
- [ ] **Kod sformatowany:** Kod jest sformatowany zgodnie z konwencją Kotlina i przechodzi analizę statyczną `./gradlew lintDebug`.
- [ ] **Bezpieczeństwo pamięci:** Tablice bajtów z efemerycznymi kluczami są bezzwłocznie zerowane (`array.fill(0)`).
- [ ] **Zgodność z architekturą AGENTS.md:** 
  - Rozmiar ładunku BEP 44 to dokładnie 900 bajtów (`MAX_FRAME_PAYLOAD_BYTES = 900`).
  - Podwójny jednokierunkowy łańcuch kluczy (Dual Unidirectional Chains) i niezależne numeratory `Counter`.
- [ ] **Aktualizacja dokumentacji:** W razie potrzeby zaktualizowano `README.md`, `AGENTS.md` lub modele ProVerif.
