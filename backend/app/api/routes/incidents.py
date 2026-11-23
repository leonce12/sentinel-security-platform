from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.api.serializers import UserCache, incident_out
from app.api.utils import apply_sort, paginate
from app.core.errors import AppError
from app.database.session import get_db
from app.incidents import alerts as alert_service, incidents as service
from app.models import Alert, Incident, IncidentHistory, IncidentNote, User
from app.schemas.common import Page
from app.schemas.domain import (
    AlertBrief, AssignRequest, HistoryOut, IncidentCreate, IncidentDetail, IncidentOut, IncidentStatusChange,
    IncidentUpdate, LinkAlertRequest, NoteOut, NoteRequest,
)
from app.security.deps import require
from app.security.permissions import Perm
from app.services import audit, export

router = APIRouter(prefix="/incidents", tags=["incidents"])
SORTABLE = {"detected_at", "risk_score", "severity", "status", "created_at", "updated_at"}


def _filtered(db, q, status, severity, assigned_to, synthetic):
    query = db.query(Incident)
    if q:
        like = f"%{q.strip()}%"
        query = query.filter(or_(Incident.title.ilike(like), Incident.reference.ilike(like),
                                 Incident.description.ilike(like)))
    if status:
        query = query.filter(Incident.status.in_(status))
    if severity:
        query = query.filter(Incident.severity.in_(severity))
    if assigned_to is not None:
        query = query.filter(Incident.assigned_to_id == assigned_to)
    if synthetic is not None:
        query = query.filter(Incident.is_synthetic.is_(synthetic))
    return query


def filters(q: str | None = Query(None, max_length=200), status: list[str] | None = Query(None),
            severity: list[str] | None = Query(None), assigned_to: int | None = None, synthetic: bool | None = None):
    return dict(q=q, status=status, severity=severity, assigned_to=assigned_to, synthetic=synthetic)


@router.get("", response_model=Page[IncidentOut])
def list_incidents(f: dict = Depends(filters), sort: str | None = None,
                   order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1),
                   page_size: int = Query(25, ge=1, le=200), _: User = Depends(require(Perm.INCIDENTS_READ)),
                   db: Session = Depends(get_db)):
    query = apply_sort(_filtered(db, **f), Incident, sort, order, SORTABLE, "risk_score")
    counts = dict(db.query(Alert.incident_id, func.count()).filter(Alert.incident_id.is_not(None)).group_by(Alert.incident_id))
    users = UserCache(db)
    return paginate(query, page, page_size, lambda i: incident_out(i, users, counts.get(i.id, 0)))


@router.get("/export")
def export_incidents(f: dict = Depends(filters), format: str = Query("csv", pattern="^(csv|json)$"),
                     user: User = Depends(require(Perm.EVENTS_EXPORT)), db: Session = Depends(get_db)):
    rows = export.model_rows(_filtered(db, **f).order_by(Incident.detected_at.desc()).limit(export.MAX_EXPORT_ROWS),
                             export.INCIDENT_COLUMNS)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit.record(db, "export.incidents", actor=user, details={"format": format, "rows": len(rows)}, commit=True)
    body = export.to_csv(rows, export.INCIDENT_COLUMNS) if format == "csv" else \
        export.to_json(rows, {"exported_at": stamp, "exported_by": user.username})
    return Response(body, media_type="text/csv" if format == "csv" else "application/json",
                    headers={"Content-Disposition": f'attachment; filename="sentinel-incidents-{stamp}.{format}"'})


@router.post("", response_model=IncidentOut, status_code=201)
def create(body: IncidentCreate, user: User = Depends(require(Perm.INCIDENTS_MANAGE)), db: Session = Depends(get_db)):
    incident = service.create_incident(db, title=body.title, description=body.description, severity=body.severity,
                                       actor=user, alert_ids=body.alert_ids, assigned_to_id=body.assigned_to_id)
    return incident_out(incident, UserCache(db))


@router.get("/{incident_id}", response_model=IncidentDetail)
def get(incident_id: int, _: User = Depends(require(Perm.INCIDENTS_READ)), db: Session = Depends(get_db)):
    incident = service.get_incident(db, incident_id)
    users = UserCache(db)
    alerts = db.query(Alert).filter(Alert.incident_id == incident.id).order_by(Alert.first_seen).all()
    notes = db.query(IncidentNote).filter_by(incident_id=incident.id).order_by(IncidentNote.created_at).all()
    history = db.query(IncidentHistory).filter_by(incident_id=incident.id).order_by(IncidentHistory.created_at,
                                                                                   IncidentHistory.id).all()
    return IncidentDetail(
        **incident_out(incident, users, len(alerts)).model_dump(),
        alerts=[AlertBrief.model_validate(a) for a in alerts],
        notes=[NoteOut(id=n.id, body=n.body, author=users.ref(n.author_id), created_at=n.created_at) for n in notes],
        history=[HistoryOut(id=h.id, change_type=h.change_type, from_value=h.from_value, to_value=h.to_value,
                            details=h.details, actor=users.ref(h.actor_id), created_at=h.created_at) for h in history],
    )


@router.patch("/{incident_id}", response_model=IncidentOut)
def update(incident_id: int, body: IncidentUpdate, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
           db: Session = Depends(get_db)):
    return incident_out(service.update_details(db, incident_id, body.model_dump(exclude_none=True), user), UserCache(db))


@router.post("/{incident_id}/status", response_model=IncidentOut)
def change_status(incident_id: int, body: IncidentStatusChange, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
                  db: Session = Depends(get_db)):
    incident = service.change_status(db, incident_id, body.status, user, body.note, body.resolution)
    return incident_out(incident, UserCache(db))


@router.post("/{incident_id}/assign", response_model=IncidentOut)
def assign(incident_id: int, body: AssignRequest, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
           db: Session = Depends(get_db)):
    return incident_out(service.assign(db, incident_id, body.user_id, user), UserCache(db))


@router.post("/{incident_id}/notes", response_model=NoteOut, status_code=201)
def add_note(incident_id: int, body: NoteRequest, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
             db: Session = Depends(get_db)):
    note = service.add_note(db, incident_id, body.body, user)
    return NoteOut(id=note.id, body=note.body, author=UserCache(db).ref(user.id), created_at=note.created_at)


@router.post("/{incident_id}/alerts", response_model=IncidentOut)
def link_alert(incident_id: int, body: LinkAlertRequest, user: User = Depends(require(Perm.INCIDENTS_MANAGE)),
               db: Session = Depends(get_db)):
    incident = service.get_incident(db, incident_id)
    if incident.status == "closed":
        raise AppError("Cannot add alerts to a closed incident", 409, "invalid_transition")
    alert = alert_service.get_alert(db, body.alert_id)
    service.link_alert(db, incident, alert, user)
    audit.record(db, "incident.link_alert", actor=user, object_type="incident", object_id=incident.id,
                 details={"alert_id": alert.id})
    db.commit()
    return incident_out(incident, UserCache(db))
