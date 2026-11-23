"""Dashboard statistics. Every number is computed from database queries at request time."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.incidents.alerts import OPEN_STATUSES
from app.models import Alert, AlertEvent, DetectionRule, Incident, IngestionJob, SecurityEvent

OPEN_INCIDENT_STATUSES = ("open", "investigating", "contained")
SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"]


def resolve_range(db: Session, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    """Default range: the 7 days ending at the newest stored event (or now when empty).

    Anchoring on the newest event keeps synthetic datasets with historical timestamps visible.
    """
    if end is None:
        newest = db.query(func.max(SecurityEvent.timestamp)).scalar()
        end = newest or datetime.now(UTC)
    if start is None:
        start = end - timedelta(days=7)
    return start, end


def _alerts_in_range(db: Session, start, end):
    return db.query(Alert).filter(Alert.last_seen >= start, Alert.first_seen <= end)


def summary(db: Session, start: datetime | None, end: datetime | None) -> dict:
    start, end = resolve_range(db, start, end)
    events = db.query(SecurityEvent).filter(SecurityEvent.timestamp.between(start, end))
    open_alert_events = (db.query(AlertEvent.event_id).join(Alert, Alert.id == AlertEvent.alert_id)
                         .filter(Alert.status.in_(OPEN_STATUSES)))
    last_job = db.query(IngestionJob).order_by(IngestionJob.created_at.desc()).first()
    day_ago = datetime.now(UTC) - timedelta(hours=24)
    return {
        "range": {"start": start.isoformat(), "end": end.isoformat()},
        "total_events": events.count(),
        "total_alerts": _alerts_in_range(db, start, end).count(),
        "open_alerts": _alerts_in_range(db, start, end).filter(Alert.status.in_(OPEN_STATUSES)).count(),
        "open_incidents": db.query(Incident).filter(Incident.status.in_(OPEN_INCIDENT_STATUSES)).count(),
        "critical_incidents": db.query(Incident).filter(Incident.status.in_(OPEN_INCIDENT_STATUSES),
                                                        Incident.severity == "critical").count(),
        "high_risk_events": events.filter(SecurityEvent.risk_score >= 60).count(),
        "events_requiring_investigation": events.filter(SecurityEvent.id.in_(open_alert_events)).count(),
        "auth_failures": events.filter(SecurityEvent.event_category == "authentication",
                                       SecurityEvent.outcome == "failure").count(),
        "synthetic_events": events.filter(SecurityEvent.is_synthetic.is_(True)).count(),
        "ingestion": {
            "total_jobs": db.query(IngestionJob).count(),
            "failed_jobs_24h": db.query(IngestionJob).filter(IngestionJob.status == "failed",
                                                              IngestionJob.created_at >= day_ago).count(),
            "last_job": None if last_job is None else {
                "id": last_job.id, "status": last_job.status, "filename": last_job.filename,
                "created_at": last_job.created_at.isoformat(), "processed": last_job.processed_records,
                "rejected": last_job.rejected_records, "duplicates": last_job.duplicate_records},
        },
    }


def _bucket_expr(db: Session, unit: str):
    if db.bind.dialect.name == "postgresql":
        return func.date_trunc(unit, SecurityEvent.timestamp)
    fmt = "%Y-%m-%d %H:00:00" if unit == "hour" else "%Y-%m-%d 00:00:00"
    return func.strftime(fmt, SecurityEvent.timestamp)


def _iso(value) -> str:
    return value.isoformat() if isinstance(value, datetime) else str(value)


def analytics(db: Session, start: datetime | None, end: datetime | None) -> dict:
    start, end = resolve_range(db, start, end)
    unit = "hour" if end - start <= timedelta(days=8) else "day"
    bucket = _bucket_expr(db, unit).label("bucket")
    in_range = SecurityEvent.timestamp.between(start, end)

    timeline_rows = (db.query(bucket, SecurityEvent.severity, func.count()).filter(in_range)
                     .group_by(bucket, SecurityEvent.severity).order_by(bucket).all())
    timeline: dict[str, dict] = {}
    for b, severity, n in timeline_rows:
        point = timeline.setdefault(_iso(b), {"bucket": _iso(b), **{s: 0 for s in SEVERITY_ORDER}, "total": 0})
        point[severity] = n
        point["total"] += n

    auth_rows = (db.query(bucket, SecurityEvent.outcome, func.count())
                 .filter(in_range, SecurityEvent.event_category == "authentication")
                 .group_by(bucket, SecurityEvent.outcome).order_by(bucket).all())
    auth: dict[str, dict] = {}
    for b, outcome, n in auth_rows:
        point = auth.setdefault(_iso(b), {"bucket": _iso(b), "success": 0, "failure": 0, "other": 0})
        point[outcome if outcome in ("success", "failure") else "other"] += n

    alerts = _alerts_in_range(db, start, end)
    by_sev = dict(alerts.with_entities(Alert.severity, func.count()).group_by(Alert.severity).all())
    categories = (db.query(SecurityEvent.event_category, func.count()).filter(in_range)
                  .group_by(SecurityEvent.event_category).order_by(func.count().desc()).all())
    sources = (db.query(SecurityEvent.source_system, func.count()).filter(in_range)
               .group_by(SecurityEvent.source_system).order_by(func.count().desc()).limit(10).all())
    incident_status = dict(db.query(Incident.status, func.count()).group_by(Incident.status).all())

    band = case((Alert.risk_score >= 80, "80-100"), (Alert.risk_score >= 60, "60-79"), (Alert.risk_score >= 40, "40-59"),
                (Alert.risk_score >= 20, "20-39"), else_="0-19")
    risk = dict(alerts.with_entities(band, func.count()).group_by(band).all())

    perf_rows = (db.query(DetectionRule.id, DetectionRule.name, DetectionRule.enabled, func.count(Alert.id),
                          func.sum(case((Alert.status == "false_positive", 1), else_=0)),
                          func.sum(case((Alert.status.in_(OPEN_STATUSES), 1), else_=0)),
                          func.avg(Alert.risk_score))
                 .outerjoin(Alert, (Alert.rule_id == DetectionRule.id) & (Alert.last_seen >= start) & (Alert.first_seen <= end))
                 .group_by(DetectionRule.id, DetectionRule.name, DetectionRule.enabled).order_by(DetectionRule.id).all())

    return {
        "range": {"start": start.isoformat(), "end": end.isoformat(), "bucket": unit},
        "events_over_time": list(timeline.values()),
        "auth_activity": list(auth.values()),
        "alerts_by_severity": [{"severity": s, "count": by_sev.get(s, 0)} for s in SEVERITY_ORDER],
        "event_categories": [{"category": c, "count": n} for c, n in categories],
        "top_sources": [{"source": s, "count": n} for s, n in sources],
        "incident_status": [{"status": s, "count": incident_status.get(s, 0)}
                            for s in ("open", "investigating", "contained", "resolved", "closed")],
        "risk_distribution": [{"band": b, "count": risk.get(b, 0)} for b in ("0-19", "20-39", "40-59", "60-79", "80-100")],
        "rule_performance": [{"rule_id": rid, "name": name, "enabled": enabled, "alerts": int(total or 0),
                              "false_positives": int(fp or 0), "open": int(open_ or 0),
                              "avg_score": round(float(avg), 1) if avg is not None else None}
                             for rid, name, enabled, total, fp, open_, avg in perf_rows],
    }
