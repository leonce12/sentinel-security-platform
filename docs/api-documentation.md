# API documentation

Base path: `/api/v1`. Interactive OpenAPI documentation (try requests from the browser) is served at `/api/v1/docs`, and the machine-readable schema at `/api/v1/openapi.json`.

## Conventions

**Authentication.** Sign in with `POST /auth/login`. The response body contains a short-lived access token (15 minutes); send it as `Authorization: Bearer <token>`. A refresh token is set as an HttpOnly, `SameSite=Strict` cookie scoped to `/api/v1/auth`; `POST /auth/refresh` exchanges it for a new access token and rotates it. Reusing an already rotated refresh token revokes every session of that user.

**Authorization.** Every endpoint checks the caller's permission on the server (see the table below and `backend/app/security/permissions.py`). A refused request returns `403` and is written to the audit log as `authorization.denied`.

**Pagination.** List endpoints accept `page` (from 1) and `page_size` (max 200) and return `{items, total, page, page_size, pages}`.

**Sorting.** `sort` must be one of a whitelisted set of columns per resource and `order` is `asc` or `desc`. Any other value returns `422`.

**Errors.** Every error has the same shape:

```json
{"error": {"code": "validation_error", "message": "Request validation failed", "details": [{"field": "timestamp", "message": "Field required"}]}}
```

Unexpected server errors return `500` with a generic message and a reference ID that appears in the server log. Stack traces are never returned.

| Status | Meaning |
|--------|---------|
| 400 | Request understood but not allowed in this state (e.g. demoting yourself) |
| 401 | Missing, invalid or expired token; wrong credentials |
| 403 | Authenticated but missing the permission |
| 404 | Object not found |
| 409 | Conflict (duplicate, invalid status transition) |
| 413 / 415 | Upload too large / unsupported file type |
| 422 | Validation error |
| 429 | Rate limited (`Retry-After` header) |

## Event schema

Uploaded and API-submitted events are normalized to the fields below. Input names are matched case-insensitively against several aliases (for example `src_ip`, `client_ip` or `ip` all map to `source_ip`); `GET /ingest/schema` returns the full alias list. Unknown fields are kept in `raw_data`.

| Field | Required | Notes |
|-------|----------|-------|
| `event_id` | no | Source identifier. When present it is used for duplicate detection; otherwise a content fingerprint is used. |
| `timestamp` | **yes** | ISO 8601, common date formats, or Unix seconds/milliseconds. Stored in UTC. Rejected if unparseable, before 2000 or more than a day in the future. |
| `event_type` | **yes** | Lowercased, spaces and symbols become `_` (e.g. `Login Failed` becomes `login_failed`). |
| `source_system` | no | Stored as `unknown` (with a warning) when missing. |
| `source_ip`, `destination_ip` | no | Must be valid IPv4/IPv6 when present; invalid values reject the record. |
| `username` | no | Lowercased. |
| `event_category` | no | One of `authentication, access, privilege, configuration, network, system, endpoint, data, other`. Common aliases are mapped; missing categories are inferred from the event type. |
| `severity` | no | `informational, low, medium, high, critical`, common aliases (`warning`, `error`...) or a 0 to 10 number (CVSS-style bands). Defaults to informational. |
| `action`, `outcome`, `resource`, `description` | no | `outcome` normalizes to `success`, `failure` or `unknown`. Text is stripped of control characters and length-limited. |
| `raw` / `raw_data` | no | Object (or JSON string) kept for investigators, max 16 KB. |
| `synthetic` | no | `true` marks demonstration data. |

Example batch for `POST /ingest/events`:

```json
{"events": [
  {"event_id": "vpn-8812", "timestamp": "2026-11-10T10:00:00Z", "source_system": "vpn-gw-01",
   "event_category": "authentication", "event_type": "login_failure", "outcome": "failure",
   "username": "alice", "source_ip": "203.0.113.10", "description": "Invalid password"}
]}
```

The response is the ingestion job: `total_records`, `processed_records`, `rejected_records`, `duplicate_records`, `duration_ms`, per-record `errors` and `warnings`, and the `detection_summary` of the detection run that followed.

## Endpoints

The table below is generated from the route definitions, so the permission column reflects the code.

### Auth

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/auth/login` | public |  |
| POST | `/auth/refresh` | public |  |
| POST | `/auth/logout` | public |  |
| GET | `/auth/me` | any signed-in user |  |
| PATCH | `/auth/me` | any signed-in user |  |
| POST | `/auth/change-password` | any signed-in user |  |
| GET | `/auth/registration-status` | public |  |
| POST | `/auth/register` | public | Self-registration, only when an administrator enabled it. New accounts are inactive |

### Users

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/users` | `users:manage` |  |
| GET | `/users/assignable` | any signed-in user | Analysts who can receive alert or incident assignments. |
| GET | `/roles` | `users:manage` |  |
| POST | `/users` | `users:manage` |  |
| GET | `/users/{user_id}` | `users:manage` |  |
| PATCH | `/users/{user_id}` | `users:manage` |  |
| POST | `/users/{user_id}/reset-password` | `users:manage` |  |
| GET | `/api-keys` | `users:manage` |  |
| POST | `/api-keys` | `users:manage` |  |
| POST | `/api-keys/{key_id}/revoke` | `users:manage` |  |

### Events

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/events` | `events:read` |  |
| GET | `/events/facets` | `events:read` | Distinct values that populate filter dropdowns. |
| GET | `/events/export` | `events:export` |  |
| GET | `/events/{event_id}` | `events:read` |  |
| POST | `/events` | `events:ingest` |  |
| POST | `/ingest/upload` | `events:ingest` |  |
| POST | `/ingest/events` | `X-API-Key` header | Machine-to-machine ingestion. Authenticate with the X-API-Key header. |
| GET | `/ingest/jobs` | `events:read` |  |
| GET | `/ingest/jobs/{job_id}` | `events:read` |  |
| GET | `/ingest/schema` | `events:read` |  |

### Alerts

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/alerts` | `alerts:read` |  |
| GET | `/alerts/export` | `events:export` |  |
| GET | `/alerts/{alert_id}` | `alerts:read` |  |
| POST | `/alerts/{alert_id}/acknowledge` | `alerts:triage` |  |
| POST | `/alerts/{alert_id}/status` | `alerts:manage` |  |
| POST | `/alerts/{alert_id}/assign` | `alerts:manage` |  |
| POST | `/alerts/{alert_id}/notes` | `alerts:triage` |  |
| POST | `/alerts/{alert_id}/rescore` | `alerts:manage` |  |
| POST | `/alerts/{alert_id}/incident` | `incidents:manage` |  |

### Incidents

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/incidents` | `incidents:read` |  |
| GET | `/incidents/export` | `events:export` |  |
| POST | `/incidents` | `incidents:manage` |  |
| GET | `/incidents/{incident_id}` | `incidents:read` |  |
| PATCH | `/incidents/{incident_id}` | `incidents:manage` |  |
| POST | `/incidents/{incident_id}/status` | `incidents:manage` |  |
| POST | `/incidents/{incident_id}/assign` | `incidents:manage` |  |
| POST | `/incidents/{incident_id}/notes` | `incidents:manage` |  |
| POST | `/incidents/{incident_id}/alerts` | `incidents:manage` |  |

### Detection

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/rules` | `rules:read` |  |
| GET | `/rules/{rule_id}` | `rules:read` |  |
| PATCH | `/rules/{rule_id}` | `rules:manage` |  |
| POST | `/detection/run` | `detection:run` | Run the deterministic detection engine over stored events. Safe to repeat: existing |
| GET | `/anomaly/status` | `rules:read` |  |
| POST | `/anomaly/run` | `anomaly:run` |  |
| GET | `/anomaly/results` | `rules:read` |  |
| POST | `/anomaly/results/{result_id}/review` | `anomaly:run` |  |

### Threat Intelligence

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/intel/status` | `intel:lookup` |  |
| POST | `/intel/lookup` | `intel:lookup` |  |
| GET | `/intel/lookups` | `intel:lookup` |  |
| GET | `/intel/indicators` | `intel:lookup` |  |
| POST | `/intel/indicators` | `intel:manage` |  |

### Dashboard

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/dashboard/summary` | `dashboard:read` |  |
| GET | `/dashboard/analytics` | `dashboard:read` |  |

### Ai

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/ai/status` | `ai:use` |  |
| GET | `/ai/glossary` | any signed-in user |  |
| POST | `/ai/explain/alert/{alert_id}` | `ai:use` |  |
| POST | `/ai/summarize/incident/{incident_id}` | `ai:use` |  |
| POST | `/ai/ask` | `ai:use` |  |

### Reports

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/reports` | `reports:generate` |  |
| GET | `/reports` | `reports:read` |  |
| GET | `/reports/{report_id}/download` | `reports:read` |  |

### Notifications

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/notifications` | `notifications:read` |  |
| GET | `/notifications/unread-count` | `notifications:read` |  |
| POST | `/notifications/{notification_id}/read` | `notifications:read` |  |
| POST | `/notifications/read-all` | `notifications:read` |  |

### Audit

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/audit-logs` | `audit:read` |  |
| GET | `/audit-logs/export` | `audit:read` |  |

### Settings

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/settings` | `settings:manage` |  |
| PATCH | `/settings` | `settings:manage` |  |

### Demo

| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/demo/load` | `demo:manage` |  |
| POST | `/demo/reset` | `demo:manage` |  |

### Health

| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/health` | public |  |
| GET | `/health/ready` | public |  |

<!-- 81 endpoints -->
