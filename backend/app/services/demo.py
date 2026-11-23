"""Reference data seeding, synthetic demo loading and demo reset."""

import csv
import os
from pathlib import Path

from sqlalchemy.orm import Session

from app.detection.definitions import default_rule_rows
from app.ingestion.parsers import parse_csv, parse_json
from app.ingestion.service import ingest_records
from app.models import Alert, AlertEvent, AnomalyResult, DetectionRule, Incident, SecurityEvent, ThreatIndicator, User
from app.services import audit, users as user_service

SAMPLE_FILES = ["sentinel_demo_events.csv", "sentinel_demo_events.json"]


def sample_dir() -> Path:
    configured = os.environ.get("SENTINEL_SAMPLE_DATA_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "sample_data"


def seed_reference_data(db: Session) -> None:
    """Idempotent: creates roles and any missing built-in rules. Never overwrites admin edits."""
    user_service.ensure_roles(db)
    existing = {r[0] for r in db.query(DetectionRule.id)}
    for row in default_rule_rows():
        if row["id"] not in existing:
            db.add(DetectionRule(**row))
    db.commit()


def load_local_intel(db: Session, path: Path) -> int:
    added = 0
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            exists = db.query(ThreatIndicator).filter_by(indicator=row["indicator"], source=row["source"]).first()
            if exists:
                continue
            db.add(ThreatIndicator(indicator=row["indicator"], indicator_type=row.get("type", "ip"),
                                   verdict=row["verdict"], confidence=float(row["confidence"]), source=row["source"],
                                   description=row.get("description", ""),
                                   is_synthetic=row.get("synthetic", "true").lower() == "true"))
            added += 1
    db.commit()
    return added


def load_demo(db: Session, actor: User | None) -> dict:
    base = sample_dir()
    intel_path = base / "datasets" / "threat_intel_local.csv"
    intel_added = load_local_intel(db, intel_path) if intel_path.exists() else 0
    jobs = []
    for name in SAMPLE_FILES:
        path = base / "logs" / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        records = parse_csv(text, 100_000) if name.endswith(".csv") else parse_json(text, 100_000)
        job = ingest_records(db, records, source_type="sample", actor=actor, filename=name, mark_synthetic=True,
                             run_detection=True)
        jobs.append({"job_id": job.id, "file": name, "processed": job.processed_records,
                     "duplicates": job.duplicate_records, "rejected": job.rejected_records,
                     "detection": job.detection_summary})
    audit.record(db, "demo.load", actor=actor, actor_username=None if actor else "system",
                 details={"files": [j["file"] for j in jobs], "intel_added": intel_added})
    db.commit()
    return {"intel_indicators_added": intel_added, "jobs": jobs}


def reset_demo(db: Session, actor: User) -> dict:
    """Remove synthetic records only. User-created records, audit logs and reports are kept.

    Alerts are removed when they are synthetic and not part of a non-synthetic incident.
    Synthetic events still used as evidence by a kept alert are kept as well.
    """
    synthetic_incidents = [i.id for i in db.query(Incident.id).filter(Incident.is_synthetic.is_(True))]
    alert_query = db.query(Alert).filter(Alert.is_synthetic.is_(True))
    removable_alerts = [a.id for a in alert_query if a.incident_id is None or a.incident_id in synthetic_incidents]
    for i in range(0, len(removable_alerts), 1000):
        db.query(Alert).filter(Alert.id.in_(removable_alerts[i:i + 1000])).delete(synchronize_session=False)
    db.flush()
    remaining_links = db.query(Alert.id).filter(Alert.incident_id.in_(synthetic_incidents)).count() if synthetic_incidents else 0
    incidents_removed = 0
    if synthetic_incidents and remaining_links == 0:
        incidents_removed = db.query(Incident).filter(Incident.id.in_(synthetic_incidents)).delete(synchronize_session=False)
    kept_evidence = db.query(AlertEvent.event_id)
    events_removed = db.query(SecurityEvent).filter(SecurityEvent.is_synthetic.is_(True),
                                                    SecurityEvent.id.not_in(kept_evidence)).delete(synchronize_session=False)
    anomalies_removed = db.query(AnomalyResult).filter(AnomalyResult.is_synthetic.is_(True)).delete(synchronize_session=False)
    intel_removed = db.query(ThreatIndicator).filter(ThreatIndicator.is_synthetic.is_(True)).delete(synchronize_session=False)
    result = {"events_removed": events_removed, "alerts_removed": len(removable_alerts),
              "incidents_removed": incidents_removed, "anomalies_removed": anomalies_removed,
              "intel_indicators_removed": intel_removed}
    audit.record(db, "demo.reset", actor=actor, details=result)
    db.commit()
    return result
