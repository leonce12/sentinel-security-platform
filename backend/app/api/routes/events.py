"""Security events, ingestion and exports."""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.utils import apply_sort, paginate
from app.core.config import get_settings
from app.core.errors import AppError, NotFound
from app.database.session import get_db
from app.ingestion.service import ingest_records, ingest_upload
from app.models import Alert, AlertEvent, ApiKey, Incident, IngestionJob, SecurityEvent, User
from app.schemas.common import Page
from app.schemas.domain import (
    AlertBrief, ApiIngestBatch, EventDetail, EventOut, IncidentBrief, IngestionJobOut, ManualEvent,
)
from app.security.deps import get_api_key, require
from app.security.permissions import Perm
from app.services import audit, export
from app.services.event_query import SORTABLE, EventFilters, filtered_events

router = APIRouter(tags=["events"])


def event_filters(
    q: str | None = Query(None, max_length=200), severity: list[str] | None = Query(None),
    category: list[str] | None = Query(None), source_system: str | None = None, event_type: str | None = None,
    username: str | None = None, ip: str | None = None, start: datetime | None = None, end: datetime | None = None,
    min_risk: float | None = Query(None, ge=0, le=100), job_id: int | None = None, synthetic: bool | None = None,
    flagged: bool | None = None,
) -> EventFilters:
    return EventFilters(q=q, severity=severity, category=category, source_system=source_system, event_type=event_type,
                        username=username, ip=ip, start=start, end=end, min_risk=min_risk, job_id=job_id,
                        synthetic=synthetic, flagged=flagged)


@router.get("/events", response_model=Page[EventOut])
def list_events(filters: EventFilters = Depends(event_filters), sort: str | None = None,
                order: str = Query("desc", pattern="^(asc|desc)$"), page: int = Query(1, ge=1),
                page_size: int = Query(25, ge=1, le=200), _: User = Depends(require(Perm.EVENTS_READ)),
                db: Session = Depends(get_db)):
    query = apply_sort(filtered_events(db, filters), SecurityEvent, sort, order, SORTABLE, "timestamp")
    return paginate(query, page, page_size)


@router.get("/events/facets")
def event_facets(_: User = Depends(require(Perm.EVENTS_READ)), db: Session = Depends(get_db)):
    """Distinct values that populate filter dropdowns."""
    def distinct(column, limit=200):
        return [v for (v,) in db.query(column).distinct().order_by(column).limit(limit) if v]
    return {"source_systems": distinct(SecurityEvent.source_system), "event_types": distinct(SecurityEvent.event_type),
            "categories": distinct(SecurityEvent.event_category)}


@router.get("/events/export")
def export_events(request: Request, filters: EventFilters = Depends(event_filters),
                  format: str = Query("csv", pattern="^(csv|json)$"),
                  user: User = Depends(require(Perm.EVENTS_EXPORT)), db: Session = Depends(get_db)):
    query = filtered_events(db, filters).order_by(SecurityEvent.timestamp.desc())
    total = query.count()
    if total > export.MAX_EXPORT_ROWS:
        raise AppError(f"Export is limited to {export.MAX_EXPORT_ROWS} events; narrow the filters ({total} match)",
                       422, "export_too_large")
    rows = export.model_rows(query.all(), export.EVENT_COLUMNS)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    audit.record(db, "export.events", actor=user, object_type="events",
                 details={"format": format, "rows": len(rows), "filters": {k: str(v) for k, v in vars(filters).items() if v is not None}},
                 commit=True)
    if format == "csv":
        return Response(export.to_csv(rows, export.EVENT_COLUMNS), media_type="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="sentinel-events-{stamp}.csv"'})
    body = export.to_json(rows, {"exported_at": stamp, "exported_by": user.username, "count": len(rows)})
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="sentinel-events-{stamp}.json"'})


@router.get("/events/{event_id}", response_model=EventDetail)
def get_event(event_id: int, _: User = Depends(require(Perm.EVENTS_READ)), db: Session = Depends(get_db)):
    event = db.get(SecurityEvent, event_id)
    if event is None:
        raise NotFound("Event")
    alerts = (db.query(Alert).join(AlertEvent, AlertEvent.alert_id == Alert.id)
              .filter(AlertEvent.event_id == event.id).order_by(Alert.risk_score.desc()).all())
    incident_ids = {a.incident_id for a in alerts if a.incident_id}
    incidents = db.query(Incident).filter(Incident.id.in_(incident_ids)).all() if incident_ids else []
    return EventDetail(**EventOut.model_validate(event).model_dump(), raw_data=event.raw_data,
                       alerts=[AlertBrief.model_validate(a) for a in alerts],
                       incidents=[IncidentBrief.model_validate(i) for i in incidents])


@router.post("/events", response_model=IngestionJobOut, status_code=201)
def submit_event(body: ManualEvent, run_detection: bool = True, user: User = Depends(require(Perm.EVENTS_INGEST)),
                 db: Session = Depends(get_db)):
    record = body.model_dump(exclude_none=True)
    return ingest_records(db, [record], source_type="manual", actor=user, run_detection=run_detection)


# ---- ingestion -------------------------------------------------------------------------------

@router.post("/ingest/upload", response_model=IngestionJobOut, status_code=201)
async def upload(file: UploadFile = File(...), mark_synthetic: bool = Form(False), run_detection: bool = Form(True),
                 user: User = Depends(require(Perm.EVENTS_INGEST)), db: Session = Depends(get_db)):
    settings = get_settings()
    filename = (file.filename or "upload").replace("\\", "/").split("/")[-1][:255]
    if not filename.lower().endswith((".csv", ".json", ".jsonl", ".ndjson")):
        raise AppError("Only .csv, .json, .jsonl and .ndjson files are accepted", 415, "unsupported_type")
    # Read at most limit + 1 bytes so an oversized upload is rejected without loading it all.
    content = await file.read(settings.max_upload_bytes + 1)
    return ingest_upload(db, content, filename, user, mark_synthetic=mark_synthetic, run_detection=run_detection)


@router.post("/ingest/events", response_model=IngestionJobOut, status_code=201, tags=["machine ingestion"])
def api_ingest(body: ApiIngestBatch, key: ApiKey = Depends(get_api_key), db: Session = Depends(get_db)):
    """Machine-to-machine ingestion. Authenticate with the X-API-Key header."""
    return ingest_records(db, body.events, source_type="api", actor=None, filename=f"api:{key.name}",
                          api_key_name=key.name)


@router.get("/ingest/jobs", response_model=Page[IngestionJobOut])
def list_jobs(page: int = Query(1, ge=1), page_size: int = Query(20, ge=1, le=100),
              _: User = Depends(require(Perm.EVENTS_READ)), db: Session = Depends(get_db)):
    return paginate(db.query(IngestionJob).order_by(IngestionJob.created_at.desc()), page, page_size)


@router.get("/ingest/jobs/{job_id}", response_model=IngestionJobOut)
def get_job(job_id: int, _: User = Depends(require(Perm.EVENTS_READ)), db: Session = Depends(get_db)):
    job = db.get(IngestionJob, job_id)
    if job is None:
        raise NotFound("Ingestion job")
    return job


@router.get("/ingest/schema")
def ingestion_schema(_: User = Depends(require(Perm.EVENTS_READ)), db: Session = Depends(get_db)):
    from app.ingestion.normalize import CATEGORIES, FIELD_ALIASES, SEVERITIES
    return {"fields": {k: list(v) for k, v in FIELD_ALIASES.items()}, "categories": sorted(CATEGORIES),
            "severities": SEVERITIES, "required": ["timestamp", "event_type"],
            "limits": {"max_upload_mb": get_settings().max_upload_mb,
                       "max_records": get_settings().max_records_per_upload},
            "stored_events": db.query(func.count(SecurityEvent.id)).scalar()}
