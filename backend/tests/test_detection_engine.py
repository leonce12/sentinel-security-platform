"""Detection engine against the real database: alerts from stored events, idempotency,
merging new evidence, false-positive handling and risk recalculation."""

import json

from app.detection.engine import run_detection
from app.ingestion.service import ingest_records
from app.models import Alert, AlertActivity, AlertEvent, AuditLog, SecurityEvent, ThreatIndicator
from tests.helpers import failures, record

API = "/api/v1"


def ingest(db, rows, actor=None, detect=True):
    return ingest_records(db, rows, source_type="json", actor=actor, run_detection=detect)


def test_alert_created_from_stored_events_with_evidence(db, users):
    ingest(db, failures(6), users["admin"])
    alert = db.query(Alert).one()
    assert alert.rule_id == "SEN-AUTH-001" and alert.event_count == 6 and alert.status == "new"
    linked = db.query(AlertEvent).filter_by(alert_id=alert.id).count()
    assert linked == 6
    assert all(e.risk_score == alert.risk_score for e in db.query(SecurityEvent))
    assert db.query(AlertActivity).filter_by(alert_id=alert.id, activity_type="created").count() == 1


def test_normal_activity_produces_no_alerts(db, users):
    rows = [record(i * 60, outcome="success", event_type="login_success") for i in range(5)]
    rows += failures(2)
    job = ingest(db, rows)
    assert db.query(Alert).count() == 0
    assert job.detection_summary["alerts_created"] == 0


def test_reprocessing_is_idempotent(db, users):
    ingest(db, failures(8))
    first = db.query(Alert).count()
    for _ in range(3):
        summary = run_detection(db)
        assert summary["alerts_created"] == 0 and summary["alerts_updated"] == 0
    assert db.query(Alert).count() == first == 1
    assert db.query(AlertEvent).count() == 8


def test_duplicate_upload_creates_no_duplicate_alerts(db, users):
    rows = failures(6)
    ingest(db, rows)
    job = ingest(db, rows)
    assert job.duplicate_records == 6 and db.query(Alert).count() == 1


def test_new_evidence_merges_into_existing_alert_and_rescores(db, users):
    ingest(db, failures(5))
    alert = db.query(Alert).one()
    old_score = alert.risk_score
    ingest(db, failures(10, start_minute=3, spacing=0.3, description="later failures"))
    db.refresh(alert)
    assert db.query(Alert).count() == 1
    assert alert.event_count == 15 and alert.risk_score > old_score
    kinds = [a.activity_type for a in db.query(AlertActivity).filter_by(alert_id=alert.id)]
    assert "evidence_added" in kinds and "rescored" in kinds
    assert db.query(AuditLog).filter_by(action="alert.rescore").count() == 1


def test_activity_outside_merge_window_creates_separate_alert(db, users):
    ingest(db, failures(5))
    ingest(db, failures(5, start_minute=180))
    assert db.query(Alert).count() == 2


def test_false_positive_is_not_auto_suppressed(client, headers, db):
    client.post(f"{API}/ingest/upload", headers=headers["admin"],
                files={"file": ("a.json", json.dumps(failures(6)).encode(), "application/json")})
    alert_id = db.query(Alert).one().id
    r = client.post(f"{API}/alerts/{alert_id}/status", headers=headers["soc_analyst"],
                    json={"status": "false_positive", "reason": "short"})
    assert r.status_code == 422  # a reason is required
    r = client.post(f"{API}/alerts/{alert_id}/status", headers=headers["soc_analyst"],
                    json={"status": "false_positive", "reason": "User confirmed a stale saved password on their phone"})
    assert r.json()["status"] == "false_positive"
    # Re-running detection over the same evidence keeps it closed...
    client.post(f"{API}/detection/run", headers=headers["soc_analyst"], json={})
    assert client.get(f"{API}/alerts/{alert_id}", headers=headers["viewer"]).json()["status"] == "false_positive"
    # ...but new evidence for the same account reopens it instead of being silently ignored.
    client.post(f"{API}/ingest/upload", headers=headers["admin"],
                files={"file": ("b.json", json.dumps(failures(4, start_minute=4)).encode(), "application/json")})
    detail = client.get(f"{API}/alerts/{alert_id}", headers=headers["viewer"]).json()
    assert detail["status"] == "new" and detail["event_count"] == 10
    fp = [a for a in detail["activity"] if a["activity_type"] == "false_positive"]
    assert fp and fp[0]["note"].startswith("User confirmed")
    assert client.get(f"{API}/alerts", headers=headers["viewer"]).json()["total"] == 1


def test_reopen_and_transition_rules(client, headers, db):
    client.post(f"{API}/events", headers=headers["admin"], json=record(event_type="malware_detected", severity="critical",
                                                                          event_category="endpoint"))
    alert_id = db.query(Alert).one().id
    h = headers["soc_analyst"]
    assert client.post(f"{API}/alerts/{alert_id}/acknowledge", headers=h).status_code == 200
    assert client.post(f"{API}/alerts/{alert_id}/acknowledge", headers=h).status_code == 409
    assert client.post(f"{API}/alerts/{alert_id}/status", headers=h,
                       json={"status": "resolved", "reason": "Test signature on a lab machine"}).status_code == 200
    assert client.post(f"{API}/alerts/{alert_id}/status", headers=h, json={"status": "investigating"}).status_code == 422
    r = client.post(f"{API}/alerts/{alert_id}/status", headers=h, json={"status": "investigating", "reason": "New info"})
    assert r.status_code == 200 and r.json()["status"] == "investigating"


def test_reputation_raises_score_and_rescore_records_change(client, headers, db):
    client.post(f"{API}/events", headers=headers["admin"], json=record(event_type="malware_detected", severity="high",
                                                                          event_category="endpoint", source_ip="203.0.113.50"))
    alert = db.query(Alert).one()
    before = alert.risk_score
    db.add(ThreatIndicator(indicator="203.0.113.50", verdict="malicious", confidence=0.9, source="test"))
    db.commit()
    r = client.post(f"{API}/alerts/{alert.id}/rescore", headers=headers["soc_analyst"])
    assert r.json()["risk_score"] > before
    detail = client.get(f"{API}/alerts/{alert.id}", headers=headers["viewer"]).json()
    assert any(f["factor"] == "Source reputation" for f in detail["score_breakdown"])
    assert any(a["activity_type"] == "rescored" for a in detail["activity"])


def test_rule_disable_and_threshold_configuration(client, headers, db):
    h = headers["admin"]
    assert client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"parameters": {"threshold": 0}}).status_code == 422
    assert client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"parameters": {"bogus": 1}}).status_code == 422
    assert client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"parameters": {"threshold": "5"}}).status_code == 422
    r = client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"parameters": {"threshold": 20}})
    assert r.json()["parameters"]["threshold"] == 20 and r.json()["parameters"]["window_minutes"] == 10
    ingest(db, failures(8))
    assert db.query(Alert).count() == 0
    client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"parameters": {"threshold": 5}, "enabled": False})
    run_detection(db)
    assert db.query(Alert).count() == 0
    client.patch(f"{API}/rules/SEN-AUTH-001", headers=h, json={"enabled": True})
    run_detection(db)
    assert db.query(Alert).count() == 1
    assert db.query(AuditLog).filter_by(action="rule.update").count() == 3


def test_auto_incident_for_high_risk_alert(db, users):
    # Privilege escalation to itself, off-hours, from a malicious IP: high-risk combination.
    db.add(ThreatIndicator(indicator="203.0.113.45", verdict="malicious", confidence=0.9, source="test"))
    db.commit()
    rows = [record(-480 + i * 0.3, source_ip="203.0.113.45", username="nora") for i in range(8)]
    rows.append(record(-470, source_ip="203.0.113.45", username="nora", event_category="privilege",
                       event_type="group_member_added", outcome="success", resource="group/Domain Admins",
                       raw={"target_user": "nora"}))
    ingest(db, rows)
    from app.models import Incident
    incident = db.query(Incident).one()
    assert incident.auto_created and incident.risk_score >= 80 and incident.reference.startswith("INC-")
    assert "not a confirmed attack" in incident.description
    linked = db.query(Alert).filter(Alert.incident_id == incident.id).all()
    assert len(linked) >= 2  # alerts about the same account are grouped into one incident
    assert "nora" in incident.affected_entities["accounts"]
