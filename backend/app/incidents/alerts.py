"""Alert lifecycle: creation and merging from findings, scoring, triage actions.

Duplicate control. A finding never produces a second alert for evidence that already
backs an alert of the same rule:
  * events already linked to an alert of the same rule are removed from the finding;
  * if nothing new remains, the finding is "unchanged";
  * if a recent alert exists for the same rule and group (same account, IP or system)
    within the rule's window, the new events are merged into it and it is rescored;
  * otherwise a new alert is created.
A merged alert that an analyst had closed is reopened, because new evidence arrived.
Closing an alert as a false positive never suppresses future, different evidence.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.core.errors import AppError, NotFound
from app.detection.rules import DetectionContext, Finding
from app.models import Alert, AlertActivity, AlertEvent, DetectionRule, SecurityEvent, User
from app.scoring.engine import ScoreInput, calculate
from app.security.permissions import ASSIGNABLE_ROLES
from app.services import app_settings, audit, notifications

OPEN_STATUSES = ("new", "acknowledged", "investigating")
CLOSED_STATUSES = ("resolved", "false_positive")
ALL_STATUSES = OPEN_STATUSES + CLOSED_STATUSES
ALLOWED_TRANSITIONS = {
    "new": {"acknowledged", "investigating", "resolved", "false_positive"},
    "acknowledged": {"investigating", "resolved", "false_positive"},
    "investigating": {"resolved", "false_positive", "acknowledged"},
    "resolved": {"investigating"},  # reopen
    "false_positive": {"investigating"},  # reopen
}


def _merge_window(rule: DetectionRule) -> timedelta:
    params = rule.parameters or {}
    return timedelta(minutes=int(params.get("window_minutes") or params.get("merge_window_minutes") or 60))


def _activity(db: Session, alert: Alert, kind: str, actor: User | None, note: str = "",
              from_value: str | None = None, to_value: str | None = None) -> None:
    db.add(AlertActivity(alert_id=alert.id, actor_id=actor.id if actor else None, activity_type=kind,
                         note=note, from_value=from_value, to_value=to_value))


def _linked_events(db: Session, alert_id: int) -> list[SecurityEvent]:
    return (db.query(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
            .filter(AlertEvent.alert_id == alert_id).all())


def _related_alert_ids(db: Session, alert: Alert, accounts: list[str], ips: list[str], event_ids: list[int]) -> list[int]:
    if not accounts and not ips:
        return []
    conditions = []
    if accounts:
        conditions.append(SecurityEvent.username.in_(accounts))
    if ips:
        conditions.append(SecurityEvent.source_ip.in_(ips))
    sharing_evidence = db.query(AlertEvent.alert_id).filter(AlertEvent.event_id.in_(event_ids))
    rows = (db.query(Alert.id).join(AlertEvent, AlertEvent.alert_id == Alert.id)
            .join(SecurityEvent, SecurityEvent.id == AlertEvent.event_id)
            .filter(Alert.id != alert.id, Alert.status.in_(OPEN_STATUSES),
                    Alert.last_seen >= alert.first_seen - timedelta(hours=24), Alert.first_seen <= alert.last_seen,
                    or_(*conditions), Alert.id.not_in(sharing_evidence))
            .distinct().order_by(Alert.id).all())
    return [r[0] for r in rows]


def score_alert(db: Session, alert: Alert, rule: DetectionRule, reputation: dict, count=None, threshold=None,
                extra_points=None, severity_hint=None) -> None:
    events = _linked_events(db, alert.id)
    accounts = sorted({e.username for e in events if e.username})
    ips = sorted({ip for e in events for ip in (e.source_ip, e.destination_ip) if ip})
    systems = sorted({e.source_system for e in events})
    stored = alert.evidence_summary.get("_score_inputs", {}) if alert.evidence_summary else {}
    inp = ScoreInput(
        rule_id=rule.id, base_score=rule.base_score, confidence=rule.confidence,
        count=count if count is not None else stored.get("count"),
        threshold=threshold if threshold is not None else stored.get("threshold"),
        accounts=accounts, ips=ips, systems=systems,
        severity_hint=severity_hint if severity_hint is not None else stored.get("severity_hint"),
        extra_points=extra_points if extra_points is not None else stored.get("extra_points", []),
        related_alert_ids=_related_alert_ids(db, alert, accounts, ips, [e.id for e in events]),
    )
    result = calculate(inp, reputation, app_settings.get(db, "asset_criticality"))
    alert.risk_score = result.score
    alert.severity = result.severity
    alert.score_breakdown = result.breakdown
    alert.evidence_summary = {**(alert.evidence_summary or {}),
                              "accounts": accounts, "ips": ips, "systems": systems,
                              "_score_inputs": {"count": inp.count, "threshold": inp.threshold,
                                                "severity_hint": inp.severity_hint, "extra_points": inp.extra_points}}
    # Event-level risk: the highest score of any alert using the event as evidence.
    for event in events:
        if event.risk_score is None or event.risk_score < result.score:
            event.risk_score = result.score


def process_finding(db: Session, rule: DetectionRule, finding: Finding, ctx: DetectionContext,
                    actor: User | None) -> tuple[str, Alert | None, bool]:
    ids = finding.event_ids
    already = {row[0] for row in db.query(AlertEvent.event_id).join(Alert, Alert.id == AlertEvent.alert_id)
               .filter(Alert.rule_id == rule.id, AlertEvent.event_id.in_(ids))}
    new_ids = [i for i in ids if i not in already]
    if not new_ids:
        return "unchanged", None, False

    synthetic = all(e.is_synthetic for e in db.query(SecurityEvent.is_synthetic).filter(SecurityEvent.id.in_(ids)))
    candidate = (db.query(Alert).filter(Alert.rule_id == rule.id, Alert.group_key == finding.group_key,
                                        Alert.last_seen >= finding.first_seen - _merge_window(rule))
                 .order_by(Alert.last_seen.desc()).first())

    if candidate is not None:
        alert = candidate
        old_score, old_status = alert.risk_score, alert.status
        db.add_all([AlertEvent(alert_id=alert.id, event_id=i) for i in new_ids])
        db.flush()
        alert.event_count = db.query(AlertEvent).filter(AlertEvent.alert_id == alert.id).count()
        alert.first_seen = min(alert.first_seen, finding.first_seen)
        alert.last_seen = max(alert.last_seen, finding.last_seen)
        alert.description = finding.description
        alert.is_synthetic = alert.is_synthetic and synthetic
        alert.evidence_summary = {**alert.evidence_summary, **finding.evidence}
        count = alert.event_count if finding.count is not None else None
        score_alert(db, alert, rule, ctx.reputation, count=count, threshold=finding.threshold,
                    extra_points=finding.extra_points, severity_hint=finding.severity_hint)
        _activity(db, alert, "evidence_added", None, f"{len(new_ids)} new event(s) linked by the detection engine")
        if alert.status in CLOSED_STATUSES:
            alert.status = "new"
            _activity(db, alert, "status_change", None, "Reopened automatically because new evidence arrived",
                      old_status, "new")
            notifications.notify_roles(db, notifications.SECURITY_TEAM, "alert_reopened",
                                       f"Alert #{alert.id} reopened: new evidence", alert.title, f"/alerts/{alert.id}")
        if alert.risk_score != old_score:
            _activity(db, alert, "rescored", None, "Risk score recalculated after new evidence",
                      str(old_score), str(alert.risk_score))
            audit.record(db, "alert.rescore", actor=actor, actor_username=None if actor else "system",
                         object_type="alert", object_id=alert.id,
                         details={"from": old_score, "to": alert.risk_score, "reason": "new evidence"})
        incident_created = _maybe_auto_incident(db, alert, actor)
        return "updated", alert, incident_created

    alert = Alert(rule_id=rule.id, group_key=finding.group_key, title=finding.title[:255],
                  description=finding.description, severity="informational", risk_score=0,
                  evidence_summary=dict(finding.evidence), status="new", event_count=len(ids),
                  first_seen=finding.first_seen, last_seen=finding.last_seen, is_synthetic=synthetic)
    db.add(alert)
    db.flush()
    db.add_all([AlertEvent(alert_id=alert.id, event_id=i) for i in ids])
    db.flush()
    score_alert(db, alert, rule, ctx.reputation, count=finding.count, threshold=finding.threshold,
                extra_points=finding.extra_points, severity_hint=finding.severity_hint)
    _activity(db, alert, "created", None, f"Created by rule {rule.id} from {len(ids)} event(s)", None, "new")
    if alert.risk_score >= 80:
        notifications.notify_roles(db, notifications.SECURITY_TEAM, "critical_alert",
                                   f"Critical alert: {alert.title}", f"Risk score {alert.risk_score}",
                                   f"/alerts/{alert.id}")
    incident_created = _maybe_auto_incident(db, alert, actor)
    return "created", alert, incident_created


def rescore_run(db: Session, alert_ids: set[int], reputation: dict, actor: User | None) -> int:
    """Second pass after a detection run.

    Rules run one after another, so an alert created early in a run cannot yet see related
    alerts created later in the same run. Rescoring every touched alert once at the end makes
    the "related activity" factor independent of rule order. Returns new incidents created.
    """
    created = 0
    for alert in db.query(Alert).filter(Alert.id.in_(alert_ids)).order_by(Alert.id).all():
        old = alert.risk_score
        score_alert(db, alert, alert.rule, reputation)
        if alert.risk_score != old:
            _activity(db, alert, "rescored", None, "Related alerts found in the same detection run", str(old),
                      str(alert.risk_score))
            if alert.risk_score >= 80 > old:
                notifications.notify_roles(db, notifications.SECURITY_TEAM, "critical_alert",
                                           f"Critical alert: {alert.title}", f"Risk score {alert.risk_score}",
                                           f"/alerts/{alert.id}")
        created += int(_maybe_auto_incident(db, alert, actor))
        if alert.incident_id is None and alert.status in OPEN_STATUSES:
            from app.incidents.incidents import link_alert, related_open_incident
            related = related_open_incident(db, alert)
            if related is not None:
                link_alert(db, related, alert, None)
        if alert.incident_id:
            from app.incidents.incidents import refresh_from_alerts
            refresh_from_alerts(db, _incident(db, alert.incident_id))
    return created


def _incident(db: Session, incident_id: int):
    from app.models import Incident
    return db.get(Incident, incident_id)


def _maybe_auto_incident(db: Session, alert: Alert, actor: User | None) -> bool:
    if alert.incident_id is not None or alert.status in CLOSED_STATUSES:
        return False
    if not app_settings.get(db, "auto_incident_enabled"):
        return False
    if alert.risk_score < app_settings.get(db, "auto_incident_min_score"):
        return False
    from app.incidents.incidents import auto_incident_for_alert

    return auto_incident_for_alert(db, alert)


# ---- analyst actions --------------------------------------------------------------------------

def get_alert(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise NotFound("Alert")
    return alert


def acknowledge(db: Session, alert_id: int, actor: User) -> Alert:
    alert = get_alert(db, alert_id)
    if alert.status != "new":
        raise AppError(f"Only new alerts can be acknowledged (current status: {alert.status})", 409, "invalid_transition")
    alert.status = "acknowledged"
    alert.acknowledged_by_id = actor.id
    alert.acknowledged_at = datetime.now(UTC)
    _activity(db, alert, "status_change", actor, "Acknowledged", "new", "acknowledged")
    audit.record(db, "alert.acknowledge", actor=actor, object_type="alert", object_id=alert.id)
    db.commit()
    return alert


def change_status(db: Session, alert_id: int, new_status: str, actor: User, reason: str = "") -> Alert:
    alert = get_alert(db, alert_id)
    if new_status not in ALLOWED_TRANSITIONS.get(alert.status, set()):
        raise AppError(f"Cannot change status from {alert.status} to {new_status}", 409, "invalid_transition")
    if new_status in ("false_positive", "resolved") and len(reason.strip()) < 10:
        raise AppError("Give a reason of at least 10 characters when closing an alert", 422, "reason_required")
    if alert.status in CLOSED_STATUSES and len(reason.strip()) < 5:
        raise AppError("Give a reason when reopening an alert", 422, "reason_required")
    old = alert.status
    alert.status = new_status
    kind = "false_positive" if new_status == "false_positive" else "status_change"
    _activity(db, alert, kind, actor, reason.strip(), old, new_status)
    audit.record(db, "alert.status_change", actor=actor, object_type="alert", object_id=alert.id,
                 details={"from": old, "to": new_status, "reason": reason.strip()[:500]})
    db.commit()
    return alert


def assign(db: Session, alert_id: int, assignee_id: int | None, actor: User) -> Alert:
    alert = get_alert(db, alert_id)
    assignee = None
    if assignee_id is not None:
        assignee = db.get(User, assignee_id)
        if assignee is None or not assignee.is_active or assignee.role_name not in ASSIGNABLE_ROLES:
            raise AppError("Alerts can only be assigned to active administrators or SOC analysts", 422, "invalid_assignee")
    old = alert.assigned_to_id
    alert.assigned_to_id = assignee_id
    _activity(db, alert, "assigned", actor, "", str(old) if old else None, assignee.username if assignee else None)
    audit.record(db, "alert.assign", actor=actor, object_type="alert", object_id=alert.id,
                 details={"from": old, "to": assignee_id})
    if assignee and assignee.id != actor.id:
        notifications.notify_user(db, assignee.id, "alert_assigned", f"Alert #{alert.id} assigned to you",
                                  alert.title, f"/alerts/{alert.id}")
    db.commit()
    return alert


def add_note(db: Session, alert_id: int, body: str, actor: User) -> AlertActivity:
    alert = get_alert(db, alert_id)
    entry = AlertActivity(alert_id=alert.id, actor_id=actor.id, activity_type="note", note=body.strip())
    db.add(entry)
    audit.record(db, "alert.note", actor=actor, object_type="alert", object_id=alert.id)
    db.commit()
    return entry


def rescore(db: Session, alert_id: int, actor: User) -> Alert:
    from app.intelligence.service import reputation_map

    alert = get_alert(db, alert_id)
    old = alert.risk_score
    score_alert(db, alert, alert.rule, reputation_map(db))
    if alert.risk_score != old:
        _activity(db, alert, "rescored", actor, "Manual recalculation", str(old), str(alert.risk_score))
        audit.record(db, "alert.rescore", actor=actor, object_type="alert", object_id=alert.id,
                     details={"from": old, "to": alert.risk_score, "reason": "manual"})
    db.commit()
    return alert
