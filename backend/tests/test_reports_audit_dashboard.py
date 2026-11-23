import io
import json

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.models import AuditLog, Report, SecurityEvent
from app.services.audit import redact
from tests.helpers import failures, record

API = "/api/v1"


def upload(client, h, rows, name="x.json", synthetic=False):
    return client.post(f"{API}/ingest/upload", headers=h, data={"mark_synthetic": str(synthetic).lower()},
                       files={"file": (name, json.dumps(rows).encode(), "application/json")})


def pdf_text(content: bytes) -> str:
    from pypdf import PdfReader
    return "\n".join(page.extract_text() for page in PdfReader(io.BytesIO(content)).pages)


# ---- reports ------------------------------------------------------------------------------------
def test_daily_weekly_and_incident_pdf_reports(client, headers):
    upload(client, headers["admin"], failures(6))
    h = headers["soc_analyst"]
    daily = client.post(f"{API}/reports", headers=h, json={"report_type": "daily", "date": "2026-11-10"})
    assert daily.status_code == 201
    assert daily.json()["summary"]["events"] == 6 and daily.json()["summary"]["alerts"] == 1
    pdf = client.get(f"{API}/reports/{daily.json()['id']}/download", headers=headers["viewer"])
    assert pdf.headers["content-type"] == "application/pdf" and pdf.content.startswith(b"%PDF")
    assert "Total events" in pdf_text(pdf.content)

    weekly = client.post(f"{API}/reports", headers=h, json={"report_type": "weekly", "start_date": "2026-11-09"})
    assert "Activity trend" in pdf_text(client.get(f"{API}/reports/{weekly.json()['id']}/download", headers=h).content)

    alert_id = client.get(f"{API}/alerts", headers=h).json()["items"][0]["id"]
    inc = client.post(f"{API}/alerts/{alert_id}/incident", headers=h, json={}).json()
    client.post(f"{API}/incidents/{inc['id']}/notes", headers=h, json={"body": "Called the user <b>today</b>."})
    rep = client.post(f"{API}/reports", headers=h, json={"report_type": "incident", "incident_id": inc["id"]}).json()
    content = pdf_text(client.get(f"{API}/reports/{rep['id']}/download", headers=h).content)
    assert inc["reference"] in content and "Called the user <b>today</b>." in content  # escaped, not rendered
    assert "Repeated authentication failures" in content and "Timeline" in content
    listed = client.get(f"{API}/reports", headers=headers["viewer"]).json()
    assert listed["total"] == 3 and all(len(r["sha256"]) == 64 for r in listed["items"])


def test_report_on_empty_period_and_bad_requests(client, headers):
    h = headers["admin"]
    r = client.post(f"{API}/reports", headers=h, json={"report_type": "daily", "date": "2020-01-01"})
    assert r.status_code == 201 and r.json()["summary"]["events"] == 0
    assert client.post(f"{API}/reports", headers=h, json={"report_type": "incident"}).status_code == 422
    assert client.post(f"{API}/reports", headers=h, json={"report_type": "incident", "incident_id": 999}).status_code == 404
    assert client.post(f"{API}/reports", headers=h, json={"report_type": "yearly"}).status_code == 422


# ---- audit ---------------------------------------------------------------------------------------
def test_audit_log_is_append_only_in_the_database(db, users):
    entry = db.query(AuditLog).first()
    with pytest.raises(DBAPIError):
        db.execute(text("UPDATE audit_logs SET action='tampered' WHERE id=:id"), {"id": entry.id})
    db.rollback()
    with pytest.raises(DBAPIError):
        db.execute(text("DELETE FROM audit_logs WHERE id=:id"), {"id": entry.id})
    db.rollback()


def test_audit_never_stores_secrets(client, headers, db):
    client.post(f"{API}/auth/change-password", headers=headers["viewer"],
                json={"current_password": "wrong-pass-1", "new_password": "Another-Strong-99!"})
    client.post(f"{API}/auth/login", json={"username": "admin", "password": "My-Secret-Guess-1"})
    dump = json.dumps([e.details for e in db.query(AuditLog)])
    assert "My-Secret-Guess-1" not in dump and "Another-Strong-99!" not in dump and "argon2" not in dump
    assert redact({"password": "x", "nested": {"api_key": "y", "ok": 1}}) == \
        {"password": "[REDACTED]", "nested": {"api_key": "[REDACTED]", "ok": 1}}


def test_audit_endpoint_filters_and_export(client, headers):
    client.post(f"{API}/auth/login", json={"username": "admin", "password": "wrong-password-x"})
    failures_only = client.get(f"{API}/audit-logs", headers=headers["admin"],
                               params={"action": "auth.login", "outcome": "failure"}).json()
    assert failures_only["total"] == 1 and failures_only["items"][0]["details"]["reason"] == "bad_password"
    csv_text = client.get(f"{API}/audit-logs/export", headers=headers["admin"]).text
    assert csv_text.startswith("id,created_at,actor_username")
    assert client.put(f"{API}/audit-logs", headers=headers["admin"]).status_code == 405


# ---- dashboard -----------------------------------------------------------------------------------
def test_dashboard_empty_database(client, headers):
    s = client.get(f"{API}/dashboard/summary", headers=headers["viewer"]).json()
    assert s["total_events"] == 0 and s["total_alerts"] == 0 and s["ingestion"]["last_job"] is None
    a = client.get(f"{API}/dashboard/analytics", headers=headers["viewer"]).json()
    assert a["events_over_time"] == [] and len(a["rule_performance"]) == 10


def test_dashboard_numbers_match_database(client, headers, db):
    upload(client, headers["admin"], failures(6) + [record(30, outcome="success", event_type="login_success",
                                                          severity="informational")])
    s = client.get(f"{API}/dashboard/summary", headers=headers["viewer"]).json()
    assert s["total_events"] == db.query(SecurityEvent).count() == 7
    assert s["total_alerts"] == 1 and s["auth_failures"] == 6
    assert s["events_requiring_investigation"] == 6 and s["ingestion"]["last_job"]["processed"] == 7
    a = client.get(f"{API}/dashboard/analytics", headers=headers["viewer"]).json()
    assert sum(p["total"] for p in a["events_over_time"]) == 7
    assert sum(p["failure"] for p in a["auth_activity"]) == 6
    perf = {r["rule_id"]: r for r in a["rule_performance"]}
    assert perf["SEN-AUTH-001"]["alerts"] == 1
    # Changes in the database are reflected immediately
    alert_id = client.get(f"{API}/alerts", headers=headers["admin"]).json()["items"][0]["id"]
    client.post(f"{API}/alerts/{alert_id}/incident", headers=headers["admin"], json={})
    assert client.get(f"{API}/dashboard/summary", headers=headers["viewer"]).json()["open_incidents"] == 1


def test_dashboard_date_range_filter(client, headers):
    upload(client, headers["admin"], [record(0), record(60 * 24 * 3)])
    narrow = client.get(f"{API}/dashboard/summary", headers=headers["viewer"],
                        params={"start": "2026-11-10T00:00:00Z", "end": "2026-11-11T00:00:00Z"}).json()
    assert narrow["total_events"] == 1


# ---- demo data -----------------------------------------------------------------------------------
def test_demo_load_and_reset_keeps_user_records(client, headers, db):
    upload(client, headers["admin"], [record(event_id="mine-1", description="user record")])
    r = client.post(f"{API}/demo/load", headers=headers["admin"])
    assert r.status_code == 200
    jobs = r.json()["jobs"]
    assert jobs[0]["processed"] > 6000 and jobs[0]["rejected"] == 3 and jobs[0]["duplicates"] == 3
    rules_hit = {k for j in jobs for k, v in (j["detection"] or {})["per_rule"].items() if v["created"]}
    assert len(rules_hit) == 10  # every rule fires on its scenario
    assert client.post(f"{API}/demo/reset", headers=headers["admin"], json={"confirm": "yes"}).status_code == 422
    result = client.post(f"{API}/demo/reset", headers=headers["admin"], json={"confirm": "RESET DEMO DATA"}).json()
    assert result["events_removed"] > 6000
    remaining = db.query(SecurityEvent).all()
    assert [e.event_uid for e in remaining] == ["mine-1"]
    assert db.query(AuditLog).filter_by(action="demo.reset").count() == 1
    assert db.query(Report).count() == 0
