"""Build the structured, minimized context the AI analyst is allowed to see.

The AI never receives whole raw logs. It receives a summary built from database fields:
rule definition, score breakdown, counts, entity lists and a small sample of event
descriptions. Free text that came from logs is sanitized, truncated and marked as
untrusted data, so instructions hidden inside a log line are not treated as commands.
"""

import re

from sqlalchemy.orm import Session

from app.models import Alert, AlertEvent, Incident, SecurityEvent

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
SAMPLE_EVENTS = 5


def untrusted(text: str | None, limit: int = 300) -> str:
    cleaned = _CONTROL.sub(" ", text or "")
    cleaned = cleaned.replace("```", "'''")
    return cleaned[:limit]


def alert_context(db: Session, alert: Alert) -> dict:
    events = (db.query(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
              .filter(AlertEvent.alert_id == alert.id).order_by(SecurityEvent.timestamp).all())
    rule = alert.rule
    evidence = {k: v for k, v in (alert.evidence_summary or {}).items() if not k.startswith("_")}
    fields_present = {f for e in events for f in ("username", "source_ip", "destination_ip", "resource", "action", "outcome")
                      if getattr(e, f)}
    return {
        "alert": {"id": alert.id, "title": alert.title, "status": alert.status, "severity": alert.severity,
                  "risk_score": alert.risk_score, "first_seen": alert.first_seen.isoformat(),
                  "last_seen": alert.last_seen.isoformat(), "event_count": alert.event_count,
                  "synthetic_demo_data": alert.is_synthetic},
        "rule": {"id": rule.id, "name": rule.name, "description": rule.description, "parameters": rule.parameters,
                 "confidence": rule.confidence, "false_positive_notes": rule.false_positive_notes,
                 "investigation_steps": rule.investigation_steps, "required_fields": rule.required_fields},
        "score_breakdown": alert.score_breakdown,
        "evidence_summary": evidence,
        "fields_present": sorted(fields_present),
        "event_types": sorted({e.event_type for e in events}),
        "sample_events_untrusted": [
            {"timestamp": e.timestamp.isoformat(), "event_type": e.event_type, "outcome": e.outcome,
             "username": e.username, "source_ip": e.source_ip, "resource": untrusted(e.resource, 120),
             "description": untrusted(e.description)}
            for e in events[:SAMPLE_EVENTS]
        ],
    }


def incident_context(db: Session, incident: Incident) -> dict:
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.first_seen).all()
    return {
        "incident": {"reference": incident.reference, "title": untrusted(incident.title, 200), "status": incident.status,
                     "severity": incident.severity, "risk_score": incident.risk_score,
                     "detected_at": incident.detected_at.isoformat(), "affected_entities": incident.affected_entities,
                     "synthetic_demo_data": incident.is_synthetic},
        "alerts": [{"id": a.id, "rule_id": a.rule_id, "title": a.title, "risk_score": a.risk_score,
                    "status": a.status, "event_count": a.event_count, "first_seen": a.first_seen.isoformat(),
                    "last_seen": a.last_seen.isoformat()} for a in alerts],
    }
