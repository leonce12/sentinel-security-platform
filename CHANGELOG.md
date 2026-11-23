# Changelog

All notable changes are recorded here. The project follows [Semantic Versioning](https://semver.org/): MAJOR for incompatible API or schema changes, MINOR for new features, PATCH for fixes. Releases are tagged `vMAJOR.MINOR.PATCH`.

## [1.1.0] - 2026-11-23

Public deployment release.

### Added
- Single-service Docker image and Render Blueprint (`render.yaml`) for free hosting with an external PostgreSQL (Neon).
- Public landing page and a read-only demo sign-in (`POST /auth/demo`) backed by a shared Viewer account with no usable password.
- First administrator created from environment variables on hosts without shell access.
- Automatic loading of the synthetic dataset into an empty database.
- Browser smoke test for deployed sites (`e2e/smoke_public.py`).
- CI security job: gitleaks over the full history, pip-audit, bandit, npm audit; CI builds of all Docker images.

### Security
- Request bodies are capped while they stream in.
- Per-account login rate limit independent of the client address.
- Production mode adds HSTS and Cross-Origin-Opener-Policy and turns off the interactive API docs.
- The database URL no longer has a default value in code.
- Separate Content Security Policies for the API and the web app.

### Fixed
- Application loggers were disabled when Alembic configured logging in the same process.

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
