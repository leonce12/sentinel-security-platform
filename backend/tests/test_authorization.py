"""Backend authorization is enforced on every endpoint, independent of the frontend."""

import pytest

from app.models import AuditLog
from tests.helpers import record

API = "/api/v1"

# (method, path, json body) -> roles that must be allowed
MATRIX = [
    ("GET", "/users", None, {"admin"}),
    ("POST", "/users", {"username": "x1", "email": "x1@corp.example", "password": "Strong-Pass-123", "role": "viewer"}, {"admin"}),
    ("GET", "/audit-logs", None, {"admin"}),
    ("GET", "/settings", None, {"admin"}),
    ("PATCH", "/rules/SEN-AUTH-001", {"enabled": True}, {"admin"}),
    ("POST", "/demo/reset", {"confirm": "RESET DEMO DATA"}, {"admin"}),
    ("GET", "/api-keys", None, {"admin"}),
    ("POST", "/events", record(), {"admin", "soc_analyst", "it_admin"}),
    ("GET", "/events/export", None, {"admin", "soc_analyst", "it_admin"}),
    ("POST", "/detection/run", {}, {"admin", "soc_analyst"}),
    ("POST", "/intel/lookup", {"indicator": "10.0.0.1"}, {"admin", "soc_analyst", "it_admin"}),
    ("POST", "/reports", {"report_type": "daily"}, {"admin", "soc_analyst", "it_admin"}),
    ("GET", "/ai/status", None, {"admin", "soc_analyst", "it_admin"}),
    ("POST", "/incidents", {"title": "Manual incident", "severity": "low"}, {"admin", "soc_analyst"}),
    ("GET", "/events", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
    ("GET", "/alerts", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
    ("GET", "/incidents", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
    ("GET", "/dashboard/summary", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
    ("GET", "/reports", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
    ("GET", "/rules", None, {"admin", "soc_analyst", "it_admin", "viewer"}),
]


@pytest.mark.parametrize("method,path,body,allowed", MATRIX, ids=[f"{m} {p}" for m, p, _, _ in MATRIX])
def test_role_matrix(client, headers, method, path, body, allowed):
    for role, h in headers.items():
        response = client.request(method, f"{API}{path}", headers=h, json=body)
        if role in allowed:
            assert response.status_code not in (401, 403), f"{role} should be allowed: {response.text}"
        else:
            assert response.status_code == 403, f"{role} should be denied {method} {path}"


def test_denied_requests_are_audited(client, headers, db):
    client.get(f"{API}/audit-logs", headers=headers["viewer"])
    entry = db.query(AuditLog).filter_by(action="authorization.denied").one()
    assert entry.outcome == "denied" and entry.actor_username == "viewer"
    assert entry.details["permission"] == "audit:read"


def test_alert_actions_require_manage_permission(client, headers, db):
    client.post(f"{API}/events", headers=headers["admin"], json=record(severity="critical", event_type="malware_detected"))
    alert_id = client.get(f"{API}/alerts", headers=headers["admin"]).json()["items"][0]["id"]
    # IT admins may triage (acknowledge, notes) but not change status, assign or convert.
    assert client.post(f"{API}/alerts/{alert_id}/acknowledge", headers=headers["it_admin"]).status_code == 200
    assert client.post(f"{API}/alerts/{alert_id}/notes", headers=headers["it_admin"], json={"body": "seen"}).status_code == 201
    assert client.post(f"{API}/alerts/{alert_id}/status", headers=headers["it_admin"],
                       json={"status": "investigating"}).status_code == 403
    assert client.post(f"{API}/alerts/{alert_id}/incident", headers=headers["it_admin"], json={}).status_code == 403
    assert client.post(f"{API}/alerts/{alert_id}/acknowledge", headers=headers["viewer"]).status_code == 403


def test_users_cannot_read_other_users_notifications(client, headers, users, db):
    from app.services.notifications import notify_user
    notify_user(db, users["admin"].id, "test", "Admin only")
    db.commit()
    assert client.get(f"{API}/notifications", headers=headers["viewer"]).json()["total"] == 0
    admin_items = client.get(f"{API}/notifications", headers=headers["admin"]).json()["items"]
    item_id = admin_items[0]["id"]
    assert client.post(f"{API}/notifications/{item_id}/read", headers=headers["viewer"]).status_code == 404


def test_admin_cannot_demote_or_deactivate_self(client, headers, users):
    admin_id = users["admin"].id
    assert client.patch(f"{API}/users/{admin_id}", headers=headers["admin"], json={"role": "viewer"}).status_code == 400
    assert client.patch(f"{API}/users/{admin_id}", headers=headers["admin"], json={"is_active": False}).status_code == 400


def test_role_change_is_audited_and_takes_effect(client, headers, users, db):
    viewer_id = users["viewer"].id
    r = client.patch(f"{API}/users/{viewer_id}", headers=headers["admin"], json={"role": "soc_analyst"})
    assert r.status_code == 200 and r.json()["role"] == "soc_analyst"
    assert db.query(AuditLog).filter_by(action="user.role_change").one().details == {"from": "viewer", "to": "soc_analyst"}
    # Same token now carries analyst permissions, because permissions are read from the database.
    assert client.post(f"{API}/detection/run", headers=headers["viewer"], json={}).status_code == 200


def test_sort_parameter_is_whitelisted(client, headers):
    r = client.get(f"{API}/events?sort=password_hash", headers=headers["admin"])
    assert r.status_code == 422
    r = client.get(f"{API}/events?sort=timestamp;DROP TABLE users", headers=headers["admin"])
    assert r.status_code == 422


def test_search_input_is_parameterized(client, headers):
    client.post(f"{API}/events", headers=headers["admin"], json=record(description="normal"))
    r = client.get(f"{API}/events", headers=headers["admin"], params={"q": "' OR '1'='1"})
    assert r.status_code == 200 and r.json()["total"] == 0
