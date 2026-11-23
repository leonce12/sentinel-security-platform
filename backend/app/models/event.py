"""Security events and the ingestion jobs that produced them."""

from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TZDateTime, utcnow


class IngestionJob(Base):
    __tablename__ = "ingestion_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_type: Mapped[str] = mapped_column(String(16))  # csv | json | manual | api | sample
    filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | completed | failed
    total_records: Mapped[int] = mapped_column(Integer, default=0)
    processed_records: Mapped[int] = mapped_column(Integer, default=0)
    rejected_records: Mapped[int] = mapped_column(Integer, default=0)
    duplicate_records: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    errors: Mapped[list] = mapped_column(JSONType, default=list)  # [{record, field, message}]
    warnings: Mapped[list] = mapped_column(JSONType, default=list)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    detection_summary: Mapped[dict | None] = mapped_column(JSONType, nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index("ix_security_events_category_timestamp", "event_category", "timestamp"),
        Index("ix_security_events_username_timestamp", "username", "timestamp"),
        Index("ix_security_events_source_ip_timestamp", "source_ip", "timestamp"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    event_uid: Mapped[str] = mapped_column(String(128), index=True)  # ID supplied by the source, or generated
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)  # SHA-256 of normalized content
    timestamp: Mapped[datetime] = mapped_column(TZDateTime, index=True)
    source_system: Mapped[str] = mapped_column(String(128), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    event_category: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)  # informational | low | medium | high | critical
    action: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str | None] = mapped_column(String(16), nullable=True)  # success | failure | unknown
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    raw_data: Mapped[dict] = mapped_column(JSONType, default=dict)
    # Highest risk score of any alert that uses this event as evidence. Null when never flagged.
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True, index=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    ingestion_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("ingestion_jobs.id", ondelete="SET NULL"), index=True
    )
    ingested_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
