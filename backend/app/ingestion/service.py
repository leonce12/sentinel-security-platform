"""Ingestion pipeline: records -> validation -> normalization -> dedup -> storage -> detection."""

import logging
import time
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models import IngestionJob, SecurityEvent, User
from app.ingestion.normalize import NormalizedEvent, normalize_record
from app.ingestion.parsers import parse_upload
from app.services import app_settings, audit, notifications

logger = logging.getLogger("sentinel.ingestion")

MAX_STORED_ERRORS = 500
BATCH_SIZE = 1000


def _existing_fingerprints(db: Session, fingerprints: list[str]) -> set[str]:
    found: set[str] = set()
    for i in range(0, len(fingerprints), BATCH_SIZE):
        chunk = fingerprints[i : i + BATCH_SIZE]
        found.update(fp for (fp,) in db.query(SecurityEvent.fingerprint).filter(SecurityEvent.fingerprint.in_(chunk)))
    return found


def ingest_records(
    db: Session, records: list, *, source_type: str, actor: User | None, filename: str | None = None,
    mark_synthetic: bool = False, run_detection: bool | None = None, api_key_name: str | None = None,
) -> IngestionJob:
    started = time.perf_counter()
    job = IngestionJob(source_type=source_type, filename=filename, total_records=len(records),
                       is_synthetic=mark_synthetic, created_by_id=actor.id if actor else None)
    db.add(job)
    db.flush()

    errors: list[dict] = []
    warnings: list[dict] = []
    normalized: list[tuple[int, NormalizedEvent]] = []
    rejected = 0
    for index, record in enumerate(records, start=1):
        event, field_errors = normalize_record(record, default_synthetic=mark_synthetic)
        if event is None:
            rejected += 1
            if len(errors) < MAX_STORED_ERRORS:
                errors.append({"record": index, "errors": [{"field": e.field, "message": e.message} for e in field_errors]})
            continue
        if event.warnings and len(warnings) < MAX_STORED_ERRORS:
            warnings.append({"record": index, "warnings": event.warnings})
        normalized.append((index, event))

    # Duplicate detection: inside this batch and against stored events.
    existing = _existing_fingerprints(db, [e.fingerprint for _, e in normalized])
    seen: set[str] = set()
    duplicates = 0
    to_store: list[NormalizedEvent] = []
    for _, event in normalized:
        if event.fingerprint in existing or event.fingerprint in seen:
            duplicates += 1
            continue
        seen.add(event.fingerprint)
        to_store.append(event)

    for i in range(0, len(to_store), BATCH_SIZE):
        db.add_all([
            SecurityEvent(
                event_uid=e.event_uid, fingerprint=e.fingerprint, timestamp=e.timestamp,
                source_system=e.source_system, source_ip=e.source_ip, destination_ip=e.destination_ip,
                username=e.username, event_category=e.event_category, event_type=e.event_type,
                severity=e.severity, action=e.action, outcome=e.outcome, resource=e.resource,
                description=e.description, raw_data=e.raw_data, is_synthetic=e.is_synthetic,
                ingestion_job_id=job.id,
            )
            for e in to_store[i : i + BATCH_SIZE]
        ])
        db.flush()

    job.processed_records = len(to_store)
    job.rejected_records = rejected
    job.duplicate_records = duplicates
    job.errors = errors
    job.warnings = warnings
    job.status = "completed" if to_store or duplicates else "failed"
    job.duration_ms = int((time.perf_counter() - started) * 1000)
    audit.record(db, "ingestion.complete", actor=actor, actor_username=f"api-key:{api_key_name}" if api_key_name else None,
                 object_type="ingestion_job", object_id=job.id,
                 details={"source_type": source_type, "filename": filename, "total": job.total_records,
                          "processed": job.processed_records, "rejected": rejected, "duplicates": duplicates})
    if job.status == "failed":
        message = f"No valid records in {filename or source_type} ({rejected} rejected)."
        if actor:
            notifications.notify_user(db, actor.id, "ingestion_failed", "Ingestion job failed", message, f"/events?job={job.id}")
        notifications.notify_roles(db, {"admin"}, "ingestion_failed", "Ingestion job failed", message,
                                   f"/events?job={job.id}", exclude_user_id=actor.id if actor else None)
    db.commit()

    should_detect = run_detection if run_detection is not None else app_settings.get(db, "auto_detect_after_ingestion")
    if should_detect and to_store:
        from app.detection.engine import run_detection as run_engine

        summary = run_engine(db, job_id=job.id, actor=actor)
        job.detection_summary = summary
        db.commit()
    job.duration_ms = int((time.perf_counter() - started) * 1000)
    db.commit()
    db.refresh(job)
    return job


def ingest_upload(db: Session, content: bytes, filename: str | None, actor: User, *, mark_synthetic: bool,
                  run_detection: bool | None) -> IngestionJob:
    settings = get_settings()
    try:
        fmt, records = parse_upload(content, filename, settings.max_upload_bytes, settings.max_records_per_upload)
    except Exception as exc:
        # Record the failed attempt so it is visible in job history and the audit trail.
        message = getattr(exc, "message", "Upload could not be processed")
        job = IngestionJob(source_type="upload", filename=filename, status="failed",
                           errors=[{"record": None, "errors": [{"field": "file", "message": message}]}],
                           created_by_id=actor.id, created_at=datetime.now(UTC))
        db.add(job)
        db.flush()
        audit.record(db, "ingestion.complete", actor=actor, outcome="failure", object_type="ingestion_job",
                     object_id=job.id, details={"filename": filename, "error": message})
        notifications.notify_user(db, actor.id, "ingestion_failed", "Ingestion job failed",
                                  f"{filename}: {message}", "/events")
        db.commit()
        raise
    return ingest_records(db, records, source_type=fmt, actor=actor, filename=filename,
                          mark_synthetic=mark_synthetic, run_detection=run_detection)
