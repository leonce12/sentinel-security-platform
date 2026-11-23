from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.serializers import UserCache, alert_out
from app.api.utils import apply_sort, paginate
from app.database.session import get_db
from app.incidents import alerts as alert_service, incidents as incident_service
from app.models import Alert, AlertActivity, AlertEvent, Incident, SecurityEvent, User
from app.schemas.common import Page
from app.schemas.domain import (
    ActivityOut, AlertDetail, AlertOut, AlertStatusChange, AssignRequest, ConvertRequest, EventOut, IncidentOut,
    NoteRequest, RuleOut,
)
from app.api.serializers import incident_out
from app.security.deps import require
from app.security.permissions import Perm
from app.services import audit, export

router = APIRouter(prefix="/alerts", tags=["alerts"])
SORTABLE = {"risk_score", "last_seen", "first_seen", "created_at", "severity", "status", "event_count"}


def _filtered(db: Session, q, severity, status, rule_id, assigned_to, start, end, synthetic, incident):
    query = db.query(Alert)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(Alert.title.ilike(like), Alert.description.ilike(like), Alert.group_key.ilike(like)))
    if severity:
        query = query.filter(Alert.severity.in_(severity))
    if status:
        query = query.filter(Alert.status.in_(status))
    if rule_id:
        query = query.filter(Alert.rule_id == rule_id)
    if assigned_to is not None:
        query = query.filter(Alert.assigned_to_id == assigned_to)
    if start:
        query = query.filter(Alert.last_seen >= start)
    if end:
        query = query.filter(Alert.first_seen <= end)
    if synthetic is not None:
        query = query.filter(Alert.is_synthetic.is_(synthetic))
    if incident is not None:
        query = query.filter(Alert.incident_id.is_not(None) if incident else Alert.incident_id.is_(None))
    return query


def common_filters(q: str | None = Query(None, max_length=200), severity: list[str] | None = Query(None),
                   status: list[str] | None = Query(None), rule_id: str | None = None, assigned_to: int | None = None,
                   start: datetime | None = None, end: datetime | None = None, synthetic: bool | None = None,
                   has_incident: bool | None = None):
    return dict(q=q, severity=severity, status=status, rule_id=rule_id, assigned_to=assigned_to, start=start, end=end,
                synthetic=synthetic, incident=has_incident)


@router.get("", response_model=Page[AlertOut])
def list_alerts(filters: dict = Depends(common_filters), sort: str | None = None,
                order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1),
                page_size: int = Query(25, ge=1, le=200), _: User = Depends(require(Perm.ALERTS_READ)),
                db: Session = Depends(get_db)):
    query = apply_sort(_filtered(db, **filters), Alert, sort, order, SORTABLE, "last_seen")
    users = UserCache(db)
    refs = dict(db.query(Incident.id, Incident.reference))
    return paginate(query, page, page_size, lambda a: alert_out(a, users, refs))


@router.get("/export")
def export_alerts(filters: dict = Depends(common_filters), format: str = Query("csv", pattern="^(csv|json)$"),
                  user: User = Depends(require(Perm.EVENTS_EXPORT)), db: Session = Depends(get_db)):
    rows = export.model_rows(_filtered(db, **filters).order_by(Alert.last_seen.desc()).limit(export.MAX_EXPORT_ROWS),
                             export.ALERT_COLUMNS)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit.record(db, "export.alerts", actor=user, details={"format": format, "rows": len(rows)}, commit=True)
    body = export.to_csv(rows, export.ALERT_COLUMNS) if format == "csv" else \
        export.to_json(rows, {"exported_at": stamp, "exported_by": user.username})
    return Response(body, media_type="text/csv" if format == "csv" else "application/json",
                    headers={"Content-Disposition": f'attachment; filename="sentinel-alerts-{stamp}.{format}"'})


@router.get("/{alert_id}", response_model=AlertDetail)
def get_alert(alert_id: int, events_page: int = Query(1, ge=1), events_page_size: int = Query(50, ge=1, le=200),
              _: User = Depends(require(Perm.ALERTS_READ)), db: Session = Depends(get_db)):
    alert = alert_service.get_alert(db, alert_id)
    users = UserCache(db)
    events_query = (db.query(SecurityEvent).join(AlertEvent, AlertEvent.event_id == SecurityEvent.id)
                    .filter(AlertEvent.alert_id == alert.id).order_by(SecurityEvent.timestamp))
    total = events_query.count()
    events = events_query.offset((events_page - 1) * events_page_size).limit(events_page_size).all()
    activity = db.query(AlertActivity).filter_by(alert_id=alert.id).order_by(AlertActivity.created_at, AlertActivity.id).all()
    base = alert_out(alert, users).model_dump()
    return AlertDetail(
        **base, score_breakdown=alert.score_breakdown,
        evidence_summary={k: v for k, v in alert.evidence_summary.items() if not k.startswith("_")},
        rule=RuleOut.model_validate(alert.rule), acknowledged_at=alert.acknowledged_at,
        activity=[ActivityOut(id=a.id, activity_type=a.activity_type, from_value=a.from_value, to_value=a.to_value,
                              note=a.note, actor=users.ref(a.actor_id), created_at=a.created_at) for a in activity],
        events=[EventOut.model_validate(e) for e in events], events_total=total,
    )


@router.post("/{alert_id}/acknowledge", response_model=AlertOut)
def acknowledge(alert_id: int, user: User = Depends(require(Perm.ALERTS_TRIAGE)), db: Session = Depends(get_db)):
    return alert_out(alert_service.acknowledge(db, alert_id, user), UserCache(db))


@router.post("/{alert_id}/status", response_model=AlertOut)
def change_status(alert_id: int, body: AlertStatusChange, user: User = Depends(require(Perm.ALERTS_MANAGE)),
                  db: Session = Depends(get_db)):
    return alert_out(alert_service.change_status(db, alert_id, body.status, user, body.reason), UserCache(db))


@router.post("/{alert_id}/assign", response_model=AlertOut)
def assign(alert_id: int, body: AssignRequest, user: User = Depends(require(Perm.ALERTS_MANAGE)),
           db: Session = Depends(get_db)):
    return alert_out(alert_service.assign(db, alert_id, body.user_id, user), UserCache(db))


@router.post("/{alert_id}/notes", response_model=ActivityOut, status_code=201)
def add_note(alert_id: int, body: NoteRequest, user: User = Depends(require(Perm.ALERTS_TRIAGE)),
             db: Session = Depends(get_db)):
    entry = alert_service.add_note(db, alert_id, body.body, user)
    return ActivityOut(id=entry.id, activity_type=entry.activity_type, from_value=None, to_value=None, note=entry.note,
                       actor=UserCache(db).ref(user.id), created_at=entry.created_at)


@router.post("/{alert_id}/rescore", response_model=AlertOut)
def rescore(alert_id: int, user: User = Depends(require(Perm.ALERTS_MANAGE)), db: Session = Depends(get_db)):
    return alert_out(alert_service.rescore(db, alert_id, user), UserCache(db))


@router.post("/{alert_id}/incident", response_model=IncidentOut, status_code=201)
def convert(alert_id: int, body: ConvertRequest, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
            db: Session = Depends(get_db)):
    incident = incident_service.convert_alert(db, alert_id, user, body.incident_id, body.title)
    return incident_out(incident, UserCache(db))
