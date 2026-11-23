# Security design

Sentinel holds sensitive data (security logs, investigation notes, user accounts), so the platform itself has to be built defensively. This document describes the threat model and the control for each risk, with the file that implements it and the test that checks it.

## Scope and ethics

Sentinel is a defensive monitoring and educational platform. It contains no functionality for unauthorized access, exploitation, credential harvesting, malware, stealth or persistence. It processes only logs supplied by an authorized user, and the bundled data is entirely synthetic.

## Assets and threats

| Asset | Threats considered |
|-------|-------------------|
| User accounts and sessions | Password guessing, credential stuffing, token theft, session fixation, privilege escalation |
| Security events, alerts, incidents | Unauthorized reading or modification, tampering with evidence, deletion of incidents |
| Audit trail | Tampering to hide actions |
| Secrets (signing key, API keys) | Disclosure through code, logs, responses, the browser or the audit log |
| The analyst's browser | XSS from log content, CSV formula injection, clickjacking |
| AI assistant | Prompt injection through log content, data leakage to the provider, unsafe actions |
| Availability | Oversized uploads, expensive queries, brute force against the login |

## Controls

### Authentication (`app/security`, `app/services/users.py`)

- **Argon2id** password hashing with argon2-cffi defaults (RFC 9106 parameters); hashes are upgraded automatically when parameters change. Tested: hashes start with `$argon2id$`.
- **Password policy**: at least 12 characters, three character classes, must not contain the username. Enforced on create, change and reset.
- **Uniform failure response**: unknown users and wrong passwords return the same message, and a dummy hash is verified for unknown users so response time does not reveal which usernames exist.
- **Account lockout**: 5 failures lock the account for 15 minutes (stored in the database, so it works across processes).
- **Rate limiting**: login (5 per minute per username and IP, 20 per minute per IP), refresh, registration and password change.
- **Tokens**: HS256 JWT access tokens valid 15 minutes, with required `exp`, `sub` and `type` claims and a fixed algorithm list (the `none` algorithm is rejected; tested). Tokens carry a password version, so changing or resetting a password invalidates every access token issued before (tested).
- **Refresh tokens**: random 48-byte tokens stored only as SHA-256 hashes, rotated on every use, delivered as `HttpOnly`, `SameSite=Strict`, `Secure` (in production) cookies scoped to `/api/v1/auth`. Reuse of a revoked token revokes all of the user's sessions (tested).
- **Frontend storage**: the access token lives in JavaScript memory only, never in localStorage or sessionStorage.
- **No default credentials**: the first administrator is created with `python -m app.cli create-admin`, which prompts for a password (or reads it from a named environment variable for automation) and applies the policy.
- **Self-registration** is disabled by default; when enabled, new accounts are inactive viewers until an administrator activates them.

### Authorization (`app/security/permissions.py`, `deps.py`)

- Permissions are defined once per role. Every route declares the permission it needs with `Depends(require(Perm.X))`; there is no route that relies on the frontend hiding a button.
- Permissions are read from the database on each request, so a role change takes effect immediately.
- Refused requests return 403 and are audited with the permission and path.
- Safeguards: administrators cannot demote or deactivate themselves, and the last active administrator cannot be removed.
- Assignment targets are validated (only active administrators and SOC analysts).
- Users only ever see their own notifications (tested by attempting to read another user's notification).
- `tests/test_authorization.py` calls 20 endpoints directly with each of the four roles and asserts allow or deny.

### Input handling

- Pydantic validates every request body and query parameter (types, lengths, patterns, enumerations).
- All database access goes through SQLAlchemy with bound parameters. User-controlled sorting is restricted to whitelisted columns (tested with an injection attempt).
- **Uploads**: extension whitelist, size checked while reading (the request is cut at the limit plus one byte), binary content rejected, UTF-8 required, record count limit, files parsed as data with pandas (`dtype=str`) or the `json` module. Nothing is evaluated or executed.
- **Normalization**: control characters stripped, lengths limited, IPs validated with `ipaddress`, raw payloads capped at 16 KB.
- Invalid records are rejected with reasons and reported, never silently dropped.

### Output handling

- React escapes all text; the code never uses `dangerouslySetInnerHTML`. AI output and raw logs are rendered as text.
- **CSV injection**: export cells starting with `=`, `+`, `-`, `@`, tab or carriage return are prefixed with an apostrophe (tested with a malicious description).
- **PDF reports** escape every value before it reaches ReportLab's markup parser (tested with HTML in a note).
- **Errors**: handlers return a consistent JSON shape; unexpected errors return a generic message and a reference ID, and the detail goes to the server log only.
- **Headers**: API responses carry `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive CSP and `Cache-Control: no-store`. nginx adds a CSP for the SPA (`script-src 'self'`, `frame-ancestors 'none'`).
- **CORS**: an explicit origin list with credentials, never a wildcard.

### Audit logging (`app/services/audit.py`)

- Records sign-ins (success and failure with reason), sign-outs, refresh-token reuse, denied requests, user creation, role changes, activation, password changes and resets, API key creation and revocation, rule changes, settings changes, ingestion jobs, detection runs, alert and incident actions, rescoring, intelligence lookups, AI use, report generation and downloads, exports and demo load or reset.
- Details pass through a redaction filter that replaces any key containing password, token, secret, api_key, authorization, cookie or hash (tested).
- The table is append-only: no API endpoint updates or deletes it, and a PostgreSQL trigger raises on `UPDATE` or `DELETE` (tested).
- Only administrators can read it.

### Secrets management

- All secrets come from environment variables. `.env` is git-ignored; `.env.example` holds placeholders only.
- The application refuses to start if `SENTINEL_SECRET_KEY` is missing, shorter than 32 characters or still contains a placeholder (tested).
- API keys for VirusTotal and the LLM provider stay on the server; the Settings page shows only whether they are configured.
- Ingestion API keys are shown once at creation and stored as SHA-256 hashes.

### Optional external services

- **Threat intelligence** lookups are off by default. When enabled, only the single public IP being checked is sent; private and reserved addresses are never sent (tested). Results are cached; unavailable results are not cached. Missing information is never treated as "safe".
- **AI** is off by default and needs both a configured provider and an administrator toggle. The model receives a minimized JSON summary built from database fields (rule, score factors, entity lists, counts and at most five sanitized, truncated event descriptions marked `_untrusted`). Raw payloads are never sent. The system prompt states that untrusted fields are data, not instructions. Output must parse as the expected JSON shape and is sanitized and length-limited; otherwise the deterministic explanation is used. The AI has no tools and no code path from its output to any change in the database (tested: alert status is unchanged after an explanation request, and the demo dataset contains a prompt-injection line).

### Availability

- Upload and record limits, pagination limits (max 200 per page), export limit (50,000 rows).
- Database connections use `pool_pre_ping`; health endpoints (`/health`, `/health/ready`) support container health checks.
- External calls have timeouts (10 seconds for intelligence, 30 for AI) and never block detection.

## Known limitations

- The in-memory rate limiter is per process; run one worker, or put a shared limiter (such as Redis) in front for multi-worker deployments. The database lockout still applies.
- There is no multi-factor authentication or single sign-on yet.
- HTTPS termination is expected to happen in front of Sentinel (a reverse proxy or load balancer); the compose file serves plain HTTP on localhost for development.
- A database owner can still `TRUNCATE` the audit table; protecting database credentials and taking regular backups remain necessary.
- The PDF content and exports are as sensitive as the logs themselves and must be handled accordingly.
- The project has not had an independent security review or penetration test.

See [SECURITY.md](../SECURITY.md) for how to report a vulnerability.
