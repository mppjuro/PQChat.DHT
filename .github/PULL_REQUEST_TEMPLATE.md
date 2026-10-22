## Description
Concise summary of changes made, problems resolved, or features added.

## Related Issues
Closes: #... / References: #...

## Type of Change
- [ ] 🐛 Bug fix (`fix:`)
- [ ] ✨ New feature (`feat:`)
- [ ] ♻️ Code refactoring (`refactor:`)
- [ ] ⚡ Performance optimization (`perf:`)
- [ ] 📚 Documentation (`docs:`)
- [ ] 📦 Dependencies / Gradle (`build:` / `ci:`)
- [ ] 🧪 Tests (`test:`)

## Verification Checklist
Before submitting this Pull Request, ensure the following criteria are met:
- [ ] **Unit tests pass:** `./gradlew testDebugUnitTest` executed successfully locally.
- [ ] **No hardcoded secrets:** No embedded private keys, tokens, KDF seeds, or plaintext logging (`Log.d`, `println`).
- [ ] **Code formatted:** Code is formatted according to Kotlin conventions and passes `./gradlew lintDebug`.
- [ ] **Memory safety:** Byte arrays containing ephemeral keys are wiped immediately (`array.fill(0)`).
- [ ] **Compliance with AGENTS.md architecture:** 
  - BEP 44 payload size is exactly 900 bytes (`MAX_FRAME_PAYLOAD_BYTES = 900`).
  - Dual Unidirectional Chains and independent `Counter` sequences.
- [ ] **Documentation updated:** Updated `README.md`, `AGENTS.md`, or ProVerif models if applicable.
