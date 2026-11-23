# Development report

This report records what was built, how it was verified and what remains. Every result below was produced by running the tests or the application; nothing is estimated. Version 1.0.0, completed 23 November 2026.

## 1. Completed modules

| Module | Status | Verified by |
|--------|--------|-------------|
| Authentication and user management | Complete | 17 auth tests; role matrix tests; offline E2E sign-in |
| Role-based access control (4 roles) | Complete | 27 authorization tests calling endpoints directly with every role |
| Log ingestion (CSV, JSON, NDJSON, form, API key) | Complete | 39 ingestion tests; E2E uploads through the UI |
| Normalization, validation, duplicate detection | Complete | Same |
| Detection engine and 10 rules | Complete | 40 rule tests, 11 engine tests; all 10 rules fire on the demo dataset |
| Risk scoring | Complete | 8 scoring tests; score factors checked against stored values in E2E |
| Alert management and false-positive review | Complete | Engine and incident tests; UI test for the false-positive reason |
| Incident management and correlation | Complete | 5 incident tests (multi-step workflows); E2E steps 12 to 14 |
| Threat intelligence (local, VirusTotal with cache) | Complete | Mocked HTTP for every response type |
| AI security analyst with deterministic fallback | Complete | Fake providers for valid, invalid, incomplete and failing responses |
| Dashboard and analytics | Complete | Numbers compared with SQL counts in tests and E2E |
| Event explorer, filters, pagination, exports | Complete | Ingestion and frontend tests; E2E CSV export |
| PDF reports (daily, weekly, incident) | Complete | Text extracted from generated PDFs in tests and E2E |
| In-app notifications | Complete | Assignment and failed-ingestion notifications tested |
| Audit logging (append-only) | Complete | Database trigger tested; secret redaction tested |
| Synthetic dataset and demo reset | Complete | Demo load and reset test keeps user records |
| Frontend (17 screens) | Complete | Typecheck, 17 Vitest tests, screenshots of every page, E2E |
| Documentation, CI workflow | Complete | Reviewed against the code; API and rule references generated from code |

## 2. Partially completed

| Item | State |
|------|-------|
| Anomaly detection | Works and is tested, but is experimental by design: no persisted model and no labelled evaluation data. |
| Docker deployment | Dockerfiles, nginx config and compose file written. The backend image's runtime steps (clean install from `requirements.txt`, migrations, startup, the health check command) were verified in a fresh virtualenv against a new database. `docker compose up` itself could not be run because no Docker daemon was available in the build environment. |
| Responsive design | Desktop-first; verified at 1500 px and 390 px (phone) widths. Tablet sizes were not inspected separately. |

## 3. Not implemented

- Email notifications (the specification marks them optional; notifications are in-app only and the UI says so).
- Live log collectors (syslog, agents) and background job processing.

## 4. Automated tests executed

| Suite | Command | Count |
|-------|---------|-------|
| Backend unit and integration (PostgreSQL 16) | `cd backend && pytest` | 180 |
| Frontend unit and component | `cd frontend && npm test` | 17 |
| Frontend type checking | `npm run typecheck` | whole project |
| Offline end-to-end (Playwright, Chrome) | `e2e/offline_acceptance.py` | 18 steps |
| Dependency audits | `pip-audit -r backend/requirements.txt`, `npm audit --omit=dev` | all runtime packages |

## 5. Actual results

- **Backend:** 180 passed, 0 failed. Line coverage 91% overall; detection rules 98%, detection engine 96%, scoring 100%, ingestion service 99%, normalization 91%, alert service 90%, incident service 92%.
- **Frontend:** 17 passed; TypeScript reports no errors; production build succeeds.
- **Offline acceptance test:** 18 of 18 steps passed. The stack ran inside a Linux network namespace with only a loopback interface; the test confirmed `Network is unreachable` before starting. No AI provider was configured and external intelligence was disabled. Full observed results: [offline-acceptance-results.md](offline-acceptance-results.md).
- **Dependency audits:** no known vulnerabilities after upgrading React Router from 6.30 to 7.18.6 (the audit flagged two moderate advisories in 6.x).
- **Migrations:** upgrade, downgrade and upgrade on an empty PostgreSQL database succeeded; the test suite also builds its schema with the migration.
- **SQLite development mode:** migration and demo load produced the same 6,928 events and 16 alerts as PostgreSQL.

### Defects found and fixed during testing

| Defect | How it was found | Fix |
|--------|------------------|-----|
| Hour-of-day rules used the database server's local time (UTC+3), flagging normal 16:00 UTC logins as off-hours | Demo alerts reviewed after the first load | Sessions pinned to UTC; rules convert to UTC explicitly |
| Frequency rule alerted on a system's first busy period because missing history counted as zero | Rule unit test | Baseline only uses periods after the first event and requires enough of them |
| Old access tokens could survive a password change made within the same second | Intermittent auth test | Password version stored with microsecond precision |
| Auto-created incidents did not include related lower-score alerts about the same account | Engine test | Correlation by account and IP within 24 hours |
| Numeric severities mapped inconsistently | Ingestion test | CVSS-style bands |
| Empty-table placeholders missing in PDF reports (operator precedence) | Code review while testing reports | Parenthesized fallbacks |
| Date range selector stretched to full width; daily buckets hid short spikes | Screenshot review | Width handling in form controls; hourly buckets up to 8 days |
| React Router 6 advisories | `npm audit` | Upgraded to 7.18.6, all tests re-run |

## 6. Known bugs

No known functional bugs remain open at release. Two caveats: the `/auth/refresh` call made on page load before sign-in returns 401 by design, which browsers show as a console error; and Recharts adds a few hundred kilobytes to the frontend bundle (786 KB before gzip, 223 KB gzipped).

## 7. Security limitations

- In-memory rate limiting per process (database lockout still applies).
- No MFA or SSO.
- HTTPS must be provided by a reverse proxy; set `SENTINEL_COOKIE_SECURE=true` behind it.
- A database owner can truncate the audit table; protect database credentials.
- No independent security review or penetration test has been carried out.

## 8. External services that need keys (all optional)

| Service | Variable | Without it |
|---------|----------|-----------|
| VirusTotal IP reputation | `SENTINEL_VIRUSTOTAL_API_KEY` plus the Settings toggle | Local dataset only; lookups report "unavailable" for VirusTotal |
| LLM provider (OpenAI-compatible or Anthropic) | `SENTINEL_AI_PROVIDER`, `SENTINEL_AI_API_KEY`, `SENTINEL_AI_MODEL`, `SENTINEL_AI_BASE_URL` plus the Settings toggle | Built-in deterministic explanations and glossary |

## 9. Installation

See the README: Docker Compose (`cp .env.example .env`, set two secrets, `docker compose up --build`, then `create-admin`) or services without Docker (PostgreSQL, `pip install -r requirements-dev.txt`, `alembic upgrade head`, `uvicorn`, `npm ci`, `npm run dev`).

## 10. Running the application

- Docker: http://localhost:8080
- Development: backend http://localhost:8000 (API docs at `/api/v1/docs`), frontend http://localhost:5173

## 11. Demonstrating the main functionality

Follow "Demonstration workflow" in the README, or run the automated version:

```bash
python e2e/offline_acceptance.py --base-url http://localhost:5173 \
  --db "dbname=sentinel user=sentinel host=localhost password=..." \
  --admin admin --admin-password-env E2E_ADMIN_PASSWORD --analyst <an analyst username>
```

The script expects a freshly migrated database with one administrator and one SOC analyst.

## 12. Recommendations for future development

1. Run `docker compose up --build` on a machine with Docker and add the result to this report.
2. Background job queue for ingestion and scheduled detection runs.
3. Syslog and Windows Event Log collectors; Sigma rule import; MITRE ATT&CK mapping.
4. Per-user baselines and time zones for login analytics.
5. MFA and OIDC single sign-on; a shared rate limiter.
6. Labelled evaluation data for the anomaly model and model persistence.
7. Code-split the charts to reduce the initial bundle.
