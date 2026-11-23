"""Threat intelligence, anomaly results, notifications, audit logs, settings and reports."""

from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Index, LargeBinary, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base, JSONType, TZDateTime, utcnow


class ThreatIndicator(Base):
    """Local threat intelligence dataset. Works fully offline."""

    __tablename__ = "threat_indicators"
    __table_args__ = (UniqueConstraint("indicator", "source", name="uq_threat_indicators_indicator_source"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255), index=True)
    indicator_type: Mapped[str] = mapped_column(String(16), default="ip")
    verdict: Mapped[str] = mapped_column(String(16))  # malicious | suspicious
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    source: Mapped[str] = mapped_column(String(64), default="local")
    description: Mapped[str] = mapped_column(Text, default="")
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    added_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class ThreatLookup(Base):
    """Record (and cache) of a reputation lookup against one provider."""

    __tablename__ = "threat_lookups"
    __table_args__ = (Index("ix_threat_lookups_indicator_provider", "indicator", "provider"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    indicator: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str] = mapped_column(String(32))  # local | virustotal
    verdict: Mapped[str] = mapped_column(String(20))  # malicious | suspicious | no_detections | no_information | unavailable
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    details: Mapped[dict] = mapped_column(JSONType, default=dict)
    limitations: Mapped[str] = mapped_column(Text, default="")
    looked_up_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
    expires_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    requested_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class AnomalyResult(Base):
    __tablename__ = "anomaly_results"

    id: Mapped[int] = mapped_column(primary_key=True)
    entity: Mapped[str] = mapped_column(String(255), index=True)  # username:alice
    window_start: Mapped[datetime] = mapped_column(TZDateTime, index=True)
    window_end: Mapped[datetime] = mapped_column(TZDateTime)
    features: Mapped[dict] = mapped_column(JSONType, default=dict)
    anomaly_score: Mapped[float] = mapped_column(Float)
    is_anomaly: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    contributing_features: Mapped[list] = mapped_column(JSONType, default=list)
    model_version: Mapped[str] = mapped_column(String(64))
    review_status: Mapped[str] = mapped_column(String(24), default="unreviewed")  # unreviewed | needs_follow_up | false_positive
    review_note: Mapped[str] = mapped_column(Text, default="")
    reviewed_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    notification_type: Mapped[str] = mapped_column(String(32))
    title: Mapped[str] = mapped_column(String(255))
    message: Mapped[str] = mapped_column(Text, default="")
    link: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class AuditLog(Base):
    """Append-only audit trail. A PostgreSQL trigger blocks UPDATE and DELETE (see migration)."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    actor_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")  # success | failure | denied
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    details: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)


class AppSetting(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSONType)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_type: Mapped[str] = mapped_column(String(16))  # daily | weekly | incident
    title: Mapped[str] = mapped_column(String(255))
    parameters: Mapped[dict] = mapped_column(JSONType, default=dict)
    period_start: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    period_end: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(default=0)
    content: Mapped[bytes] = mapped_column(LargeBinary, deferred=True)
    generated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    generated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)
