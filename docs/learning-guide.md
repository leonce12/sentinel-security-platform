# Technical learning guide and interview preparation

This guide is for understanding and explaining Sentinel: what each module does, why it exists, how it works, where the code is, how it was tested and what its limits are. It ends with a walkthrough of one attack through the whole system and an interview preparation section whose answers are based on the actual code.

---

## Part 1: The big picture

A SIEM (Security Information and Event Management system) does five things: **collect** logs, **normalize** them into one format, **detect** suspicious patterns, **prioritize** what it finds and **support the response**. Sentinel does each of these in a separate module:

```
files / API / form
      │
      ▼
 ingestion ──► normalization ──► PostgreSQL (security_events)
                                        │
                                        ▼
                              detection engine (10 rules)
                                        │ findings
                                        ▼
                     alerts ◄── risk scoring ◄── threat intel, asset importance
                        │
                        ▼
                    incidents ──► notes, assignments, PDF reports
                        │
                 audit log records every step
```

Optional modules (threat intelligence lookups, anomaly detection, AI analyst) add context around this pipeline but the pipeline never depends on them.

---

## Part 2: Module by module

### 2.1 Authentication and authorization

- **What:** sign-in, sessions, password management and role-based access control for four roles.
- **Why:** a security tool that anyone can read or change is itself a vulnerability.
- **How:** passwords are hashed with Argon2id, a memory-hard algorithm that makes offline guessing expensive. Login returns a JWT access token valid for 15 minutes and sets a refresh token cookie. The refresh token is random, stored only as a SHA-256 hash and replaced on every use (rotation); if an old one is used again, all of that user's sessions are revoked because it suggests theft. Every API route declares the permission it needs (`Depends(require(Perm.ALERTS_MANAGE))`); `require` loads the user, checks the role's permission set and writes an audit record if access is denied.
- **Main files:** `app/security/passwords.py`, `tokens.py`, `permissions.py`, `deps.py`; `app/services/users.py`; `app/api/routes/auth.py`, `users.py`; `frontend/src/contexts/AuthContext.tsx`, `services/api.ts`.
- **Relationships:** every other module receives the `User` object from these dependencies and passes it to the audit log.
- **Security points:** uniform error message and dummy hash for unknown users (no username enumeration by message or timing), lockout after 5 failures, rate limiting, tokens invalidated on password change via a password version claim, `none` algorithm rejected, access token never stored in localStorage.
- **Limitations:** rate limiter is per process; no MFA or SSO.
- **Tested by:** `tests/test_auth.py` (17 tests) and `tests/test_authorization.py` (a 20-endpoint by 4-role matrix plus specific cases).

### 2.2 Log ingestion and normalization

- **What:** accepts CSV, JSON (array, `{"events": [...]}`, or NDJSON), single events from a form and batches from other systems using an API key; turns each record into one normalized event.
- **Why:** detection rules can only be simple and reliable if every event has the same shape and UTC timestamps.
- **How:** `parsers.py` checks size, rejects binary and non-UTF-8 content and parses with pandas (`dtype=str`, so nothing is guessed) or the `json` module. `normalize.py` looks up each field under several aliases (`src_ip`, `client_ip`, `ip` all mean `source_ip`), parses timestamps (ISO 8601, common formats, epoch seconds or milliseconds) into UTC, validates IP addresses, maps severities and outcomes, infers a missing category from the event type, strips control characters, limits lengths and keeps unknown fields in `raw_data`. A record with an invalid timestamp, missing event type or invalid IP is rejected with field-level reasons. Duplicates are detected with a SHA-256 fingerprint: of `source_system + event_id` when the source provides an ID, otherwise of the normalized content. The fingerprint column is unique in the database.
- **Main files:** `app/ingestion/parsers.py`, `normalize.py`, `service.py`; `app/api/routes/events.py`.
- **Relationships:** after storing events, `ingest_records` calls the detection engine for the job's time span.
- **Security points:** uploaded content is never executed or interpreted; limits on size (10 MB), records (50,000) and raw payload (16 KB); every rejection is reported, not silently dropped.
- **Limitations:** one upload is processed inside one request; no streaming collectors (syslog, agents).
- **Tested by:** `tests/test_ingestion.py` (39 tests): timestamp formats, invalid data, aliases, sanitization, truncation, fingerprints, all file formats, size limits, duplicate detection within and across uploads, API keys, CSV injection.

### 2.3 Detection engine

- **What:** ten rules that turn stored events into findings: repeated authentication failures and password spraying, unusual logins, suspicious privilege changes, restricted resource access, failed access attempts, IP reputation, unusual event frequency, critical events, disabled security controls and critical configuration changes.
- **Why:** rules are transparent. An analyst can read exactly why something fired, which is not true of a black-box model.
- **How:** each rule is a small class with `relevant(event)`, `lookback(params)` and `evaluate(events, params, ctx)`. Rules are pure: they receive lightweight `EventView` objects and return `Finding` objects, never touching the database. The engine (`engine.py`) decides the period to evaluate, loads events for each rule with enough history before and after, applies the rule and keeps findings that include at least one event in the period. Threshold rules use greedy windows so the same events always produce the same bursts. The unusual-login rule builds a per-user baseline of previous login IPs; the frequency rule compares each 5-minute bucket with the median of the previous hour, but only once enough history exists.
- **Main files:** `app/detection/definitions.py` (metadata and default parameters), `rules.py` (logic), `engine.py` (orchestration).
- **Relationships:** findings go to the alert service (`app/incidents/alerts.py`); threat intelligence supplies the reputation map used by the reputation rule and by scoring.
- **Security points:** rule parameters are validated before saving (only existing keys, same types, positive numbers); wording never claims a confirmed attack.
- **Limitations:** business hours are one UTC window; rules only see ingested data; rule order would affect related-activity scoring if there were no second pass.
- **Tested by:** `tests/test_detection_rules.py` (40 tests including normal, suspicious, borderline, incomplete and out-of-window cases for every rule and a 50,000-event performance test) and `tests/test_detection_engine.py` (idempotency, merging, false-positive reopening, configuration, auto-incidents).

### 2.4 Alerts and duplicate control

- **What:** stores each finding as an alert with its evidence, score, status, assignment and history.
- **How duplicates are prevented:** before creating anything, the service removes from the finding every event that already backs an alert of the same rule. If nothing is left, nothing happens. If an alert for the same rule and group key (for example `username:nora.b`) exists within the rule's window, the new events are merged into it and it is rescored. Otherwise a new alert is created. Running detection three times on the same data therefore creates no new alerts (tested).
- **False positives:** marking a false positive requires a reason and is recorded in the alert history and the audit log. It is not a suppression rule: if new evidence for the same activity arrives, the alert reopens.
- **Main files:** `app/incidents/alerts.py`, `app/api/routes/alerts.py`.

### 2.5 Risk scoring

- **What:** a 0 to 100 score for every alert with a factor-by-factor explanation.
- **How:** `subtotal = base + frequency + accounts + reputation + asset + rule context + related activity` (capped at 100), then `score = subtotal × (0.6 + 0.4 × confidence)`. Base scores come from the rule; frequency grows logarithmically; reputation counts once for the strongest IP and is skipped for the reputation rule itself; related activity counts other open alerts on the same account or IP that do not share evidence. Incident risk is the maximum of its alerts.
- **Why this way:** every point has an explanation, and the rules for avoiding double counting are explicit. No AI is involved.
- **Main file:** `app/scoring/engine.py`; scoring of stored alerts in `app/incidents/alerts.py::score_alert`.
- **Tested by:** `tests/test_scoring.py` (each factor, caps, confidence, no double counting, "every point is explained").

### 2.6 Incidents

- **What:** investigations that group alerts, with assignment, notes, status workflow, timeline and resolution.
- **How:** alerts can be converted into a new incident or added to an open one. High-risk alerts (80 or more) create incidents automatically; when that happens, other open alerts sharing an account or IP within 24 hours are linked as related evidence. Status changes follow allowed transitions; resolving or closing requires resolution details; reopening a closed incident requires a reason. There is no delete endpoint and the database refuses to delete an incident that has alerts.
- **Main files:** `app/incidents/incidents.py`, `app/api/routes/incidents.py`.
- **Tested by:** `tests/test_incidents.py`.

### 2.7 Threat intelligence

- **What:** reputation context for IP addresses from a local dataset (offline) and optionally VirusTotal.
- **How:** verdicts are `malicious`, `suspicious`, `no_detections`, `no_information` or `unavailable`. VirusTotal results are cached for a configurable time; rate-limit and network errors are reported as unavailable and not cached. Only public IPs are ever sent, and only when an administrator enabled external lookups. `reputation_map()` collects the negative verdicts for the detection engine; absence from the map means "nothing negative known", never "safe".
- **Main files:** `app/intelligence/providers.py`, `service.py`.
- **Tested by:** mocked HTTP transports for every response type in `tests/test_intel_ai_anomaly.py`.

### 2.8 Anomaly detection (experimental)

- **What:** an Isolation Forest that scores each account-hour by how different it is from the rest of the history.
- **How:** pandas builds seven features per account per hour; a scikit-learn pipeline imputes missing values, scales and fits the model; results are rescaled to 0..1 and explained by the features furthest from the mean. Analysts review results. They never create alerts.
- **Why it is separate:** machine learning finds "unusual", not "malicious", and must not be the only basis for a decision.
- **Main file:** `app/anomaly/service.py`. Details and limitations in `docs/detection-rules.md`.

### 2.9 AI security analyst

- **What:** optional explanations of alerts, incident summaries and answers to learning questions.
- **How:** `context.py` builds a minimized JSON summary from database fields (no raw payloads, at most five sanitized and truncated descriptions marked `_untrusted`). `deterministic.py` always produces an explanation from the same data. If a provider is configured and an administrator enabled AI, `service.py` sends the summary with a system prompt that sets the rules (facts versus assumptions, no confirmed attacks, untrusted fields are data). The reply must parse into the expected JSON shape; otherwise, or on any network error, the deterministic explanation is shown with a status message.
- **Security points:** the model has no tools and its output is never written into security records; output is displayed as text only; credentials stay on the server.
- **Tested by:** fake providers for valid, invalid, incomplete and failing responses; a test that the alert is unchanged after an explanation; a prompt-injection line in the demo dataset.

### 2.10 Dashboard, reporting, notifications and audit

- **Dashboard** (`app/services/dashboard.py`): every number is a SQL query (counts, `GROUP BY` severity and category, `date_trunc` buckets) run when the page loads. Tested by comparing the API's numbers with direct database counts.
- **Reports** (`app/reporting/service.py`): ReportLab PDFs built from the database; every value is escaped; each report is stored with its SHA-256 hash. Tested by extracting text from the generated PDFs.
- **Exports** (`app/services/export.py`): CSV with formula-injection protection, JSON with metadata.
- **Notifications** (`app/services/notifications.py`): rows in a table per user; no external sending.
- **Audit** (`app/services/audit.py`): one function used everywhere; redacts secret-looking keys; a PostgreSQL trigger blocks updates and deletes.

### 2.11 Frontend

- React with TypeScript in strict mode, Tailwind design tokens in `src/index.css`, Recharts for charts.
- `services/api.ts` is the only place that talks to the backend: it attaches the token, refreshes once on a 401 and turns error bodies into readable messages.
- `useApi` handles loading, error and reload for every page; `useAction` handles button actions.
- Navigation shows only items the user's permissions allow, and routes are guarded, but the backend is the real enforcement.
- Tested with Vitest and Testing Library (`frontend/tests`), and end to end with Playwright (`e2e/offline_acceptance.py`).

---

## Part 3: Walkthrough of one attack

Follow the synthetic compromise of `nora.b` through the system.

1. **Ingestion.** The CSV contains 14 `login_failure` rows for `nora.b` from `203.0.113.45` between 02:14 and 02:20 UTC, then a `login_success`. `normalize_record` maps the columns, parses `2026-11-11T02:14:00Z` to UTC, validates the IP and stores each event with a fingerprint based on its `event_id`.
2. **Detection.** The engine evaluates the job's time span. SEN-AUTH-001 groups failures by username; the greedy window starting at 02:14 holds 14 failures in 10 minutes (threshold 5), so it returns one finding. SEN-AUTH-002 sees the 02:21 success: outside business hours and from an IP not in nora.b's previous logins. SEN-INTEL-001 finds `203.0.113.45` in the local intelligence list as malicious. From the JSON file, SEN-PRIV-001 sees nora.b add itself to Domain Admins at 02:40, SEN-CTRL-001 sees the Security log cleared and SEN-INTEG-001 sees the password policy changed without a change ticket.
3. **Scoring.** The privilege alert gets base 60, +15 for the malicious source IP, +10 for self-assigned privileges, +10 for related open alerts on the same account, then the 75% confidence multiplier (0.90): subtotal 95 becomes 86, critical.
4. **Incident.** 86 is above the auto-incident threshold, so `INC-2026-0001` is created. Correlation links the other open alerts that involve `nora.b` or `203.0.113.45` within 24 hours: six alerts in one incident with risk 86 (the maximum, not the sum).
5. **Response.** An analyst sees the critical notification, opens the incident, reads the score factors and evidence, assigns it, writes notes as they contain the account, moves it to contained and then resolved, and generates a PDF report. Every step lands in the audit log.

---

## Part 4: Interview preparation

### A. Twenty technical questions about Sentinel

1. **Walk me through Sentinel's architecture.**
   A FastAPI modular monolith with PostgreSQL and a React frontend. Logs come in through upload, API or form; the ingestion module normalizes and stores them; the detection engine runs ten rules over stored events; findings become alerts with explainable risk scores; high-risk alerts become incidents; analysts investigate, and reports and dashboards query the database. Threat intelligence, anomaly detection and AI are optional add-ons.

2. **Why a monolith instead of microservices?**
   It has to run on a laptop, offline, and be explainable by one person. Modules have clear interfaces (for example rules are pure functions and the engine owns all I/O), so it can be split later, but today a single process avoids brokers, service discovery and distributed transactions.

3. **How does duplicate detection work in ingestion?**
   Each normalized event gets a SHA-256 fingerprint: of the source system and event ID when the source supplies an ID, otherwise of the normalized content. The column is unique; the service checks fingerprints already stored (in batches of 1,000) and within the upload, and reports duplicates in the job summary.

4. **How do you stop the detection engine from creating duplicate alerts when it runs again?**
   Evidence-based control: an event can back at most one alert per rule. The service removes already-linked events from each finding; if nothing remains, the finding is unchanged. New events for the same rule and group key within the window are merged into the existing alert. Combined with deterministic windowing, three reruns create zero alerts, which a test checks.

5. **What is "greedy windowing" and why use it?**
   Starting at the earliest unused event, take all events within the window; if there are at least threshold events they form a burst and are consumed, otherwise advance by one event. Sliding windows would produce overlapping, order-dependent bursts; greedy windows give the same answer every time.

6. **Explain the risk scoring formula.**
   Subtotal of base score, frequency (`5 × log2(count/threshold)`, max 15), affected accounts (4 each beyond the first, max 10), reputation (15 or 7, once), asset importance (10 or 5), rule context (max 15) and related activity (5 per related alert, max 10), capped at 100 and multiplied by `0.6 + 0.4 × confidence`. Each factor is stored with an explanation and shown on the alert.

7. **How do you avoid double counting?**
   Reputation counts once for the strongest IP and not at all for the reputation rule, whose base already reflects it; related alerts that share evidence are excluded; incident risk is the maximum alert score; and an event's risk is the highest alert using it.

8. **What happens when an analyst marks an alert as a false positive?**
   A reason of at least 10 characters is required; the change goes to the alert history and the audit log. It does not create a suppression. If new evidence arrives for the same rule and group, the alert is reopened as new and the security team is notified.

9. **How is the unusual-login rule built?**
   For each successful login it checks two things: is the hour outside the configured business hours (in UTC), and has the user logged in from this IP in their previous logins over the last 30 days, provided there are at least three previous logins. Either reason flags the login; both together add 10 context points.

10. **How does the frequency rule decide what is a spike?**
    It counts events per source system in 5-minute buckets and compares each bucket with the median of the previous 12 buckets. A bucket alerts when it has at least 50 events and more than three times the baseline. It only compares when at least 6 previous buckets exist after the system's first event; that rule came from a bug the tests found, where a system's first busy period looked like a spike against empty history.

11. **How are timestamps handled?**
    Everything is converted to UTC on ingestion; naive timestamps are assumed UTC with a warning. During testing I found that PostgreSQL returned timestamps in the server's local timezone (UTC+3), which shifted the hour-of-day logic. I fixed it by setting the session timezone to UTC on every connection and converting to UTC inside the rules.

12. **How does authentication work end to end?**
    Login verifies the Argon2id hash, applies lockout and rate limits, returns a 15-minute JWT and sets a rotating refresh token in an HttpOnly, SameSite=Strict cookie scoped to the auth path. The frontend keeps the access token in memory, and when a request gets a 401 it calls refresh once and retries.

13. **Why keep the access token in memory rather than localStorage?**
    Anything in localStorage can be read by injected script. Memory storage limits exposure to the page's lifetime, and the refresh cookie is not readable from JavaScript at all.

14. **How do you invalidate tokens when a password changes?**
    The access token carries a password version (the password-changed timestamp in microseconds). The dependency compares it with the database on every request, so older tokens fail. All refresh tokens are revoked as well. I first used seconds and a test failed intermittently because the change could happen within the same second.

15. **How is authorization enforced?**
    Permissions are defined per role in one file. Each route declares `Depends(require(Perm.X))`; the dependency checks the user's role from the database, returns 403 and audits the denial. A test calls 20 endpoints as each of the four roles directly, bypassing the UI.

16. **How does the AI analyst avoid prompt injection and data leakage?**
    It only receives a minimized JSON summary; log text is sanitized, truncated and placed in fields marked `_untrusted`, and the system prompt says those are data. The model has no tools and its output is only displayed, so even a successful injection cannot change anything. A deterministic explanation is always shown alongside, and the dataset includes an injection string as a test fixture.

17. **What happens with no internet and no API keys?**
    Everything core still works. The offline acceptance test ran the whole stack inside a network namespace with only loopback: upload, detection, scoring, incidents, PDF and CSV, dashboard and audit all passed (18 of 18). The AI page shows built-in explanations and intelligence uses the local dataset.

18. **How did you design the database?**
    Twenty normalized tables. Events, alerts and incidents are linked through an `alert_events` join table for evidence. Foreign keys use RESTRICT where losing history would be harmful (incidents with alerts, rules with alerts) and SET NULL for user references. Indexes match real queries such as time ranges, category plus time for detection, and status for lists. The audit table has a trigger that blocks UPDATE and DELETE.

19. **How do the dashboard numbers stay accurate?**
    There is no cached or hardcoded value. Each tile and chart is an aggregate query run on request. Tests compare the API's numbers with direct database counts and check that converting an alert to an incident immediately changes the open incident count.

20. **What would you change for a production deployment?**
    A background worker for large ingestion, a shared rate limiter, HTTPS with secure cookies, MFA or SSO, log collectors such as syslog, persisted and evaluated anomaly models, and an external security review.

### B. Ten cybersecurity questions related to the implementation

1. **What is the difference between brute force and password spraying, and how does Sentinel detect each?**
   Brute force tries many passwords on one account; spraying tries a few passwords on many accounts to avoid lockouts. SEN-AUTH-001 groups failures by username for brute force and by source IP, requiring at least three distinct accounts, for spraying.

2. **Why is IP reputation "context, not proof"?**
   Reputation lists go stale, IPs are reassigned and shared by cloud and VPN users, and vendors disagree. Sentinel uses reputation to raise priority by a bounded amount and labels it clearly; absence of data never means safe.

3. **What is a false positive and how should it be handled?**
   An alert for legitimate activity. It should be documented with evidence, not silently suppressed, because the same pattern may be malicious next time. Sentinel requires a reason, keeps history and reopens on new evidence.

4. **Why would an attacker clear the audit log or disable antivirus, and how is it covered?**
   To hide activity or let malware run. SEN-CTRL-001 flags events such as `audit_log_cleared`, `antivirus_disabled` or a disabling action on a security control.

5. **What is privilege escalation and how does SEN-PRIV-001 identify it?**
   Gaining more rights than intended. The rule flags privileged group or role grants (keywords such as Domain Admins or sudo) when the actor is not on the approved list, when it happens outside business hours, or when an account grants rights to itself.

6. **Why use Argon2id instead of SHA-256 for passwords?**
   Fast hashes let attackers test billions of guesses per second. Argon2id is deliberately slow and memory-hard, which makes GPU and ASIC cracking expensive, and it includes a per-password salt.

7. **What is CSV injection and how did you prevent it?**
   A cell beginning with `=`, `+`, `-` or `@` can run as a formula in a spreadsheet. Log content is attacker-controlled, so exports prefix such cells with an apostrophe. A test exports an event whose description is a formula.

8. **How does Sentinel protect against XSS from malicious log content?**
   React escapes all text and the code never injects raw HTML; raw records and AI output are shown as text; the nginx CSP only allows scripts from the application's own origin; PDF content is escaped before reaching ReportLab.

9. **Why does the audit log need to be tamper-resistant, and how is it?**
   An attacker or insider who can edit the trail can hide their actions. There is no update or delete API, secrets are redacted before writing, and a PostgreSQL trigger rejects UPDATE and DELETE on the table.

10. **What is defense in depth in this project?**
    Several independent layers: the UI hides actions, the API checks permissions on every request, the database enforces constraints and the audit trigger, the session layer has lockout and token rotation, and the network edge adds headers and CSP. Defeating one layer does not defeat the others.

### C. Ten software engineering questions

1. **How did you make the detection rules testable?**
   Rules are pure: they receive lists of simple event objects and return findings, with no database access. Tests build events in memory and run 40 cases quickly; the engine's database work is tested separately.

2. **How did you test against a real database?**
   The pytest suite runs against PostgreSQL. A session fixture creates the schema with the Alembic migration (so migrations are tested too) and each test truncates the tables. This exercised JSONB, constraints and the audit trigger, which SQLite would not.

3. **Tell me about a bug your tests found.**
   Three examples: the timezone bug in hour-of-day rules; the frequency rule alerting on a system's first busy period because missing history counted as zero; and the password-version precision issue that let an old token survive a password change within the same second.

4. **How do you handle errors consistently?**
   Services raise `AppError` subclasses with an HTTP status and code; global handlers turn them, validation errors and HTTP exceptions into one JSON shape. Unexpected exceptions are logged with a reference ID and return a generic 500. The frontend's API client turns that shape into readable messages.

5. **How did you keep the frontend and backend contracts aligned?**
   Pydantic response models define the API, FastAPI publishes OpenAPI, TypeScript interfaces in `types/api.ts` mirror them, and the frontend tests and the Playwright run exercise the real endpoints. The API reference is generated from the route definitions.

6. **How do you manage database schema changes?**
   With Alembic migrations generated from the models and reviewed by hand. The first migration also adds the audit trigger. Migrations were tested on an empty database: upgrade, downgrade, upgrade.

7. **What trade-offs did you make for simplicity?**
   Synchronous detection instead of a job queue, an in-memory rate limiter, PDFs stored in the database and one UTC business-hours window. Each is documented with its limitation and an upgrade path.

8. **How is configuration handled?**
   pydantic-settings reads `SENTINEL_` environment variables and validates them at startup, including refusing a placeholder signing key. Operational settings that administrators change live in the database and every change is audited.

9. **How would you scale ingestion?**
   Move detection into a worker (for example RQ or Celery with Redis), stream large files instead of loading them in one request, use bulk COPY into PostgreSQL, partition `security_events` by time and run detection incrementally per job.

10. **How did you verify the whole system works rather than just the parts?**
    An end-to-end Playwright script signs in, uploads both datasets through the UI, runs detection, inspects evidence, converts an alert, assigns it, adds notes, changes status, checks the dashboard against SQL counts, downloads and reads the PDF, exports CSV and checks the audit log. It writes the observed result of each step to a report and was run with no network access.

### D. Two-minute project presentation script

> "Sentinel is a defensive security monitoring platform I built to understand how a SIEM works from the inside.
>
> Security teams drown in logs. The hard part is not storing them but finding the few events that matter and explaining why. So I built the full pipeline: Sentinel ingests logs from CSV, JSON or an authenticated API, validates and normalizes them into one schema in UTC, and stores them in PostgreSQL with duplicate detection.
>
> The core is a deterministic detection engine with ten rules: brute force and password spraying, unusual logins, privilege escalation, restricted access, reputation matches, traffic spikes, disabled security controls and more. Each rule is documented, configurable and tested against normal, suspicious and borderline data, and re-running it never creates duplicate alerts.
>
> Every alert gets a risk score from a documented formula, and the UI shows exactly where each point came from. High-risk alerts become incidents automatically and are correlated by account and IP. In my demo dataset, six alerts about one compromised account end up in a single critical incident. Analysts can assign, annotate, mark false positives with a reason and generate PDF reports.
>
> I treated the platform itself as a security target: Argon2id passwords, rotating refresh tokens, role-based access checked on every endpoint, an append-only audit log enforced by the database, and protection against CSV injection and XSS from log content. There is an optional AI analyst, but it only explains: it receives minimized data, cannot change anything, and a built-in explanation is always available.
>
> It is tested with 180 backend tests against real PostgreSQL, frontend tests, and an end-to-end browser test that I ran with the network disabled: all 18 steps passed. What I learned most is that detection is about evidence and explanation, not just alerts."
