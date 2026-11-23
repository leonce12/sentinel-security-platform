from app.models import Alert, AuditLog, Incident, IncidentHistory, Notification
from tests.helpers import record

API = "/api/v1"


def make_alert(client, headers, **fields):
    payload = record(event_type="malware_detected", severity="high", event_category="endpoint", **fields)
    client.post(f"{API}/events", headers=headers["admin"], json=payload)
    return client.get(f"{API}/alerts", headers=headers["admin"]).json()["items"][0]["id"]


def test_convert_alert_assign_note_and_close(client, headers, users, db):
    alert_id = make_alert(client, headers)
    h = headers["soc_analyst"]
    r = client.post(f"{API}/alerts/{alert_id}/incident", headers=h, json={})
    assert r.status_code == 201
    incident = r.json()
    assert incident["alert_count"] == 1 and incident["status"] == "open"
    assert client.post(f"{API}/alerts/{alert_id}/incident", headers=h, json={}).status_code == 409  # already linked

    iid = incident["id"]
    analyst = users["soc_analyst"]
    viewer = users["viewer"]
    assert client.post(f"{API}/incidents/{iid}/assign", headers=h, json={"user_id": viewer.id}).status_code == 422
    r = client.post(f"{API}/incidents/{iid}/assign", headers=headers["admin"], json={"user_id": analyst.id})
    assert r.json()["assigned_to"]["username"] == analyst.username
    assert db.query(Notification).filter_by(user_id=analyst.id, notification_type="incident_assigned").count() == 1

    assert client.post(f"{API}/incidents/{iid}/notes", headers=h, json={"body": "Host isolated pending review."}).status_code == 201
    assert client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "investigating"}).status_code == 200
    assert client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "contained"}).status_code == 200
    bad = client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "resolved"})
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "resolution_required"
    assert client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "closed",
                       "resolution": "Reimaged host"}).status_code == 409  # must resolve first
    client.post(f"{API}/incidents/{iid}/status", headers=h,
                json={"status": "resolved", "resolution": "Reimaged the host and reset the user's credentials."})
    closed = client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "closed"}).json()
    assert closed["status"] == "closed" and closed["closed_at"]

    detail = client.get(f"{API}/incidents/{iid}", headers=headers["viewer"]).json()
    changes = [x["change_type"] for x in detail["history"]]
    assert changes.count("status_change") == 4 and "assigned" in changes and "alert_linked" in changes
    assert detail["notes"][0]["body"] == "Host isolated pending review."
    assert db.query(AuditLog).filter_by(action="incident.status_change").count() == 4

    assert client.post(f"{API}/incidents/{iid}/alerts", headers=h, json={"alert_id": alert_id}).status_code == 409
    reopen = client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "investigating"})
    assert reopen.status_code == 422
    reopen = client.post(f"{API}/incidents/{iid}/status", headers=h, json={"status": "investigating", "note": "Recurrence"})
    assert reopen.json()["status"] == "investigating" and reopen.json()["closed_at"] is None


def test_attach_alert_to_existing_incident_and_risk_is_max_not_sum(client, headers, db):
    a1 = make_alert(client, headers)
    a2 = make_alert(client, headers, source_system="other-host", timestamp="2026-11-10T15:00:00Z")
    h = headers["soc_analyst"]
    inc = client.post(f"{API}/alerts/{a1}/incident", headers=h, json={}).json()
    r = client.post(f"{API}/alerts/{a2}/incident", headers=h, json={"incident_id": inc["id"]})
    assert r.status_code == 201 and r.json()["alert_count"] == 2
    scores = [a.risk_score for a in db.query(Alert)]
    assert r.json()["risk_score"] == max(scores)


def test_manual_incident_and_validation(client, headers):
    h = headers["soc_analyst"]
    assert client.post(f"{API}/incidents", headers=h, json={"title": "x"}).status_code == 422
    r = client.post(f"{API}/incidents", headers=h, json={"title": "Phishing report from finance", "severity": "medium",
                                                          "description": "User reported a suspicious email."})
    assert r.status_code == 201 and r.json()["reference"].startswith("INC-")
    listing = client.get(f"{API}/incidents", headers=headers["viewer"], params={"q": "phishing"}).json()
    assert listing["total"] == 1
    assert client.patch(f"{API}/incidents/{r.json()['id']}", headers=h, json={"severity": "high"}).json()["severity"] == "high"


def test_incidents_cannot_be_deleted(client, headers, db):
    r = client.post(f"{API}/incidents", headers=headers["admin"], json={"title": "Keep this record", "severity": "low"})
    iid = r.json()["id"]
    assert client.delete(f"{API}/incidents/{iid}", headers=headers["admin"]).status_code == 405
    alert_id = make_alert(client, headers)
    client.post(f"{API}/incidents/{iid}/alerts", headers=headers["admin"], json={"alert_id": alert_id})
    # Database-level protection: an incident with alerts cannot be removed.
    import pytest
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        db.query(Incident).filter_by(id=iid).delete()
        db.commit()
    db.rollback()
    assert db.query(IncidentHistory).filter_by(incident_id=iid).count() >= 2


def test_incident_export(client, headers):
    client.post(f"{API}/incidents", headers=headers["admin"], json={"title": "Exported incident", "severity": "low"})
    r = client.get(f"{API}/incidents/export?format=csv", headers=headers["soc_analyst"])
    assert r.status_code == 200 and "Exported incident" in r.text
    assert client.get(f"{API}/incidents/export", headers=headers["viewer"]).status_code == 403
