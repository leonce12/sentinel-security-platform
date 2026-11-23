# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning](https://semver.org/): MAJOR for incompatible API or schema changes, MINOR for new features, PATCH for fixes. Releases are tagged `vMAJOR.MINOR.PATCH`.

## [1.0.0] - 2026-11-23

First release.

### Added
- Authentication with Argon2id, rotating refresh tokens, lockout and rate limiting; four roles with backend-enforced permissions; user management and ingestion API keys.
- Log ingestion from CSV, JSON, NDJSON, a form and an authenticated API, with validation, normalization, duplicate detection and per-job summaries.
- Ten deterministic detection rules with configurable parameters, a deterministic windowing strategy and duplicate-free reprocessing.
- Explainable risk scoring, alert triage with false-positive review, incidents with automatic creation and correlation, notes, assignments and timelines.
- Threat intelligence (local dataset and optional VirusTotal), experimental Isolation Forest anomaly detection, optional AI analyst with deterministic fallback.
- Dashboard with database-backed statistics and charts; PDF reports; CSV and JSON exports; in-app notifications; append-only audit log.
- Synthetic demonstration dataset and generator; Docker Compose deployment; CI workflow.
- Test suites: 180 backend tests, 17 frontend tests and an 18-step offline end-to-end acceptance test.
