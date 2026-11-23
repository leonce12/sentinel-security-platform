"""Incident management.

Incidents are never deleted through the application: there is no delete endpoint, the
alerts -> incidents foreign key is ON DELETE RESTRICT, and closing an incident requires
resolution details. Every change is written to incident_history and the audit log.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFound
from app.models import Alert, AlertActivity, Incident, IncidentHistory, IncidentNote, SecurityEvent, User
from app.models.detection import AlertEvent
from app.scoring.engine import severity_for_score
from app.security.permissions import ASSIGNABLE_ROLES
from app.services import audit, notifications

STATUSES = ("open", "investigating", "contained", "resolved", "closed")
ALLOWED_TRANSITIONS = {
    "open": {"investigating", "contained", "resolved"},
    "investigating": {"contained", "resolved", "open"},
    "contained": {"investigating", "resolved"},
    "resolved": {"closed", "investigating"},
    "closed": {"investigating"},  # reopen with a reason
}


def _history(db: Session, incident: Incident, change_type: str, actor: User | None, details: str = "",
             from_value: str | None = None, to_value: str | None = None) -> None:
    db.add(IncidentHistory(incident_id=incident.id, actor_id=actor.id if actor else None, change_type=change_type,
                           details=details, from_value=from_value, to_value=to_value))


def get_incident(db: Session, incident_id: int) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise NotFound("Incident")
    return incident


def _new_incident(db: Session, **fields) -> Incident:
    incident = Incident(reference=f"TMP-{uuid.uuid4().hex[:12]}", **fields)
    db.add(incident)
    db.flush()
    incident.reference = f"INC-{incident.detected_at.year}-{incident.id:04d}"
    return incident


def refresh_from_alerts(db: Session, incident: Incident) -> None:
    """Recalculate risk, severity and affected entities from linked alerts.

    Incident risk is the highest alert score, not the sum: several alerts about the same
    underlying activity must not inflate the incident's risk.
    """
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).all()
    if not alerts:
        return
    incident.risk_score = max(a.risk_score for a in alerts)
    incident.severity = severity_for_score(incident.risk_score)
    event_ids = [r[0] for r in db.query(AlertEvent.event_id).filter(AlertEvent.alert_id.in_([a.id for a in alerts]))]
    events = db.query(SecurityEvent).filter(SecurityEvent.id.in_(event_ids)).all() if event_ids else []
    incident.affected_entities = {
        "accounts": sorted({e.username for e in events if e.username}),
        "systems": sorted({e.source_system for e in events}),
        "ips": sorted({e.source_ip for e in events if e.source_ip}),
    }
    incident.is_synthetic = all(a.is_synthetic for a in alerts)
    earliest = min(a.first_seen for a in alerts)
    if earliest < incident.detected_at:
        incident.detected_at = earliest


def link_alert(db: Session, incident: Incident, alert: Alert, actor: User | None) -> None:
    if alert.incident_id == incident.id:
        return
    if alert.incident_id is not None:
        raise AppError(f"Alert #{alert.id} already belongs to another incident", 409, "conflict")
    alert.incident_id = incident.id
    if alert.status == "new":
        alert.status = "investigating"
    db.add(AlertActivity(alert_id=alert.id, actor_id=actor.id if actor else None, activity_type="incident_linked",
                         to_value=incident.reference, note=f"Linked to incident {incident.reference}"))
    _history(db, incident, "alert_linked", actor, alert.title, None, f"alert #{alert.id}")
    db.flush()
    refresh_from_alerts(db, incident)


def _entities(alert: Alert) -> tuple[set, set]:
    summary = alert.evidence_summary or {}
    return set(summary.get("accounts", [])), set(summary.get("ips", []))


def related_open_incident(db: Session, alert: Alert) -> Incident | None:
    """An open, automatically created incident that involves the same account or IP within
    24 hours of the alert, or already tracks the same group key."""
    accounts, ips = _entities(alert)
    window_start = alert.first_seen - timedelta(hours=24)
    candidates = (db.query(Incident).filter(Incident.status.in_(("open", "investigating", "contained")),
                                            Incident.auto_created.is_(True))
                  .order_by(Incident.id.desc()).all())
    for incident in candidates:
        entities = incident.affected_entities or {}
        shares = accounts & set(entities.get("accounts", [])) or ips & set(entities.get("ips", []))
        if shares and window_start <= incident.detected_at <= alert.last_seen + timedelta(hours=24):
            return incident
        if db.query(Alert.id).filter(Alert.incident_id == incident.id, Alert.group_key == alert.group_key).first():
            return incident
    return None


def attach_related_alerts(db: Session, incident: Incident) -> int:
    """Correlation: link open, unassigned-to-incident alerts that share an account or IP with
    the incident within 24 hours. They are linked as related evidence; risk stays the maximum."""
    attached = 0
    open_alerts = (db.query(Alert).filter(Alert.incident_id.is_(None), Alert.status.in_(("new", "acknowledged", "investigating")),
                                          Alert.last_seen >= incident.detected_at - timedelta(hours=24),
                                          Alert.first_seen <= incident.detected_at + timedelta(hours=24)).all())
    entities = incident.affected_entities or {}
    accounts, ips = set(entities.get("accounts", [])), set(entities.get("ips", []))
    for candidate in open_alerts:
        a, i = _entities(candidate)
        if a & accounts or i & ips:
            link_alert(db, incident, candidate, None)
            attached += 1
    return attached


def auto_incident_for_alert(db: Session, alert: Alert) -> bool:
    """Create an incident for a high-risk alert, or attach it to a related open incident.
    Returns True if a new incident was created."""
    existing = related_open_incident(db, alert)
    if existing is not None:
        link_alert(db, existing, alert, None)
        return False
    incident = _new_incident(
        db, title=f"Potential security incident: {alert.title}"[:255],
        description=f"Created automatically because alert #{alert.id} reached risk score {alert.risk_score}. "
                    "This is a potential incident that requires investigation; it is not a confirmed attack.",
        severity=alert.severity, risk_score=alert.risk_score, detected_at=alert.first_seen,
        auto_created=True, is_synthetic=alert.is_synthetic,
    )
    _history(db, incident, "created", None, "Created automatically by detection", None, "open")
    link_alert(db, incident, alert, None)
    attach_related_alerts(db, incident)
    audit.record(db, "incident.auto_create", actor_username="system", object_type="incident", object_id=incident.id,
                 details={"alert_id": alert.id, "risk_score": alert.risk_score})
    if incident.risk_score >= 60:
        notifications.notify_roles(db, notifications.SECURITY_TEAM, "high_risk_incident",
                                   f"New {incident.severity} incident {incident.reference}", incident.title,
                                   f"/incidents/{incident.id}")
    return True


def create_incident(db: Session, *, title: str, description: str, severity: str, actor: User,
                    alert_ids: list[int] | None = None, assigned_to_id: int | None = None) -> Incident:
    incident = _new_incident(db, title=title, description=description, severity=severity,
                             risk_score=0, created_by_id=actor.id)
    _history(db, incident, "created", actor, "Created manually", None, "open")
    for alert_id in alert_ids or []:
        alert = db.get(Alert, alert_id)
        if alert is None:
            raise NotFound(f"Alert #{alert_id}")
        link_alert(db, incident, alert, actor)
    audit.record(db, "incident.create", actor=actor, object_type="incident", object_id=incident.id,
                 details={"alert_ids": alert_ids or []})
    if assigned_to_id:
        db.flush()
        _assign(db, incident, assigned_to_id, actor)
    if incident.risk_score >= 60:
        notifications.notify_roles(db, notifications.SECURITY_TEAM, "high_risk_incident",
                                   f"New {incident.severity} incident {incident.reference}", incident.title,
                                   f"/incidents/{incident.id}", exclude_user_id=actor.id)
    db.commit()
    return incident


def convert_alert(db: Session, alert_id: int, actor: User, incident_id: int | None = None,
                  title: str | None = None) -> Incident:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise NotFound("Alert")
    if alert.incident_id is not None:
        raise AppError(f"Alert #{alert.id} is already part of an incident", 409, "conflict")
    if incident_id is not None:
        incident = get_incident(db, incident_id)
        if incident.status == "closed":
            raise AppError("Cannot add alerts to a closed incident", 409, "invalid_transition")
        link_alert(db, incident, alert, actor)
        audit.record(db, "incident.link_alert", actor=actor, object_type="incident", object_id=incident.id,
                     details={"alert_id": alert.id})
        db.commit()
        return incident
    return create_incident(db, title=title or f"Potential security incident: {alert.title}"[:255],
                           description=alert.description, severity=alert.severity, actor=actor, alert_ids=[alert.id])


def _assign(db: Session, incident: Incident, assignee_id: int | None, actor: User) -> None:
    assignee = None
    if assignee_id is not None:
        assignee = db.get(User, assignee_id)
        if assignee is None or not assignee.is_active or assignee.role_name not in ASSIGNABLE_ROLES:
            raise AppError("Incidents can only be assigned to active administrators or SOC analysts", 422, "invalid_assignee")
    old = db.get(User, incident.assigned_to_id) if incident.assigned_to_id else None
    incident.assigned_to_id = assignee_id
    _history(db, incident, "assigned", actor, "", old.username if old else None, assignee.username if assignee else None)
    audit.record(db, "incident.assign", actor=actor, object_type="incident", object_id=incident.id,
                 details={"from": old.id if old else None, "to": assignee_id})
    if assignee and assignee.id != actor.id:
        notifications.notify_user(db, assignee.id, "incident_assigned", f"Incident {incident.reference} assigned to you",
                                  incident.title, f"/incidents/{incident.id}")


def assign(db: Session, incident_id: int, assignee_id: int | None, actor: User) -> Incident:
    incident = get_incident(db, incident_id)
    _assign(db, incident, assignee_id, actor)
    db.commit()
    return incident


def change_status(db: Session, incident_id: int, new_status: str, actor: User, note: str = "",
                  resolution: str | None = None) -> Incident:
    incident = get_incident(db, incident_id)
    if new_status not in ALLOWED_TRANSITIONS[incident.status]:
        raise AppError(f"Cannot change status from {incident.status} to {new_status}", 409, "invalid_transition")
    if new_status in ("resolved", "closed"):
        text = (resolution or incident.resolution or "").strip()
        if len(text) < 10:
            raise AppError("Resolution details (at least 10 characters) are required to resolve or close an incident",
                           422, "resolution_required")
        incident.resolution = text
    if incident.status == "closed" and len(note.strip()) < 5:
        raise AppError("Give a reason when reopening a closed incident", 422, "reason_required")
    old = incident.status
    incident.status = new_status
    incident.closed_at = datetime.now(UTC) if new_status == "closed" else (None if old == "closed" else incident.closed_at)
    _history(db, incident, "status_change", actor, note.strip(), old, new_status)
    audit.record(db, "incident.status_change", actor=actor, object_type="incident", object_id=incident.id,
                 details={"from": old, "to": new_status})
    if incident.assigned_to_id and incident.assigned_to_id != actor.id:
        notifications.notify_user(db, incident.assigned_to_id, "incident_status",
                                  f"{incident.reference} is now {new_status}", incident.title, f"/incidents/{incident.id}")
    db.commit()
    return incident


def update_details(db: Session, incident_id: int, changes: dict, actor: User) -> Incident:
    incident = get_incident(db, incident_id)
    for key in ("title", "description", "severity", "resolution"):
        if changes.get(key) is not None and getattr(incident, key) != changes[key]:
            _history(db, incident, f"{key}_changed", actor, "", str(getattr(incident, key) or "")[:128], str(changes[key])[:128])
            setattr(incident, key, changes[key])
    audit.record(db, "incident.update", actor=actor, object_type="incident", object_id=incident.id,
                 details={"fields": sorted(k for k, v in changes.items() if v is not None)})
    db.commit()
    return incident


def add_note(db: Session, incident_id: int, body: str, actor: User) -> IncidentNote:
    incident = get_incident(db, incident_id)
    note = IncidentNote(incident_id=incident.id, author_id=actor.id, body=body.strip())
    db.add(note)
    _history(db, incident, "note_added", actor, body.strip()[:200])
    audit.record(db, "incident.note", actor=actor, object_type="incident", object_id=incident.id)
    db.commit()
    return note
