# Changelog

## 1.0.1 — 2026-10-24

- Correct the loopback integration test's assumption that a non-listening port must be
  refused within a short timeout. Assert the portable connection contract while preserving
  exact refusal and timeout classification in deterministic Winsock regression tests.
- Describe common Winsock connect errors explicitly, including a contextual timeout message
  for code 10035, instead of displaying `Unknown error` from the POSIX error formatter.
- Document Windows PowerShell setup, version selection, expected demo timeout observations,
  and the intentional Windows skip for the POSIX subprocess SIGINT test.
- Ignore version-specific virtual environments such as `.venv314` in Git.

## 1.0.0 — 2026-10-24

Initial implementation: bounded TCP connect scanning, explicit authorization, passive banners,
service hints, progress, JSON/CSV exports, unit and localhost tests, documentation, and CI.
