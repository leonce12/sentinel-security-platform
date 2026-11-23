"""Shared event filtering used by the event explorer, the dashboard table and exports."""

from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import or_
from sqlalchemy.orm import Query, Session

from app.models import AlertEvent, SecurityEvent

SORTABLE = {"timestamp", "severity", "risk_score", "source_system", "event_type", "event_category", "username", "ingested_at"}


@dataclass
class EventFilters:
    q: str | None = None
    severity: list[str] | None = None
    category: list[str] | None = None
    source_system: str | None = None
    event_type: str | None = None
    username: str | None = None
    ip: str | None = None
    start: datetime | None = None
    end: datetime | None = None
    min_risk: float | None = None
    job_id: int | None = None
    synthetic: bool | None = None
    flagged: bool | None = None  # only events used as alert evidence


def filtered_events(db: Session, f: EventFilters) -> Query:
    query = db.query(SecurityEvent)
    if f.q:
        like = f"%{f.q.strip()}%"
        query = query.filter(or_(SecurityEvent.description.ilike(like), SecurityEvent.event_type.ilike(like),
                                 SecurityEvent.username.ilike(like), SecurityEvent.source_system.ilike(like),
                                 SecurityEvent.resource.ilike(like), SecurityEvent.source_ip.ilike(like),
                                 SecurityEvent.event_uid.ilike(like)))
    if f.severity:
        query = query.filter(SecurityEvent.severity.in_(f.severity))
    if f.category:
        query = query.filter(SecurityEvent.event_category.in_(f.category))
    if f.source_system:
        query = query.filter(SecurityEvent.source_system == f.source_system)
    if f.event_type:
        query = query.filter(SecurityEvent.event_type == f.event_type)
    if f.username:
        query = query.filter(SecurityEvent.username == f.username.lower())
    if f.ip:
        query = query.filter(or_(SecurityEvent.source_ip == f.ip, SecurityEvent.destination_ip == f.ip))
    if f.start:
        query = query.filter(SecurityEvent.timestamp >= f.start)
    if f.end:
        query = query.filter(SecurityEvent.timestamp <= f.end)
    if f.min_risk is not None:
        query = query.filter(SecurityEvent.risk_score >= f.min_risk)
    if f.job_id is not None:
        query = query.filter(SecurityEvent.ingestion_job_id == f.job_id)
    if f.synthetic is not None:
        query = query.filter(SecurityEvent.is_synthetic.is_(f.synthetic))
    if f.flagged:
        query = query.filter(SecurityEvent.id.in_(db.query(AlertEvent.event_id)))
    return query
