"""Detection rules, alerts and alert evidence."""

from datetime import datetime

from sqlalchemy import Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.base import Base, JSONType, TZDateTime, utcnow


class DetectionRule(Base):
    __tablename__ = "detection_rules"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)  # e.g. SEN-AUTH-001
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(32))
    severity: Mapped[str] = mapped_column(String(16))
    base_score: Mapped[int] = mapped_column(Integer)
    confidence: Mapped[float] = mapped_column(Float)  # 0..1, how reliable the rule usually is
    parameters: Mapped[dict] = mapped_column(JSONType, default=dict)  # thresholds, windows, lists
    required_fields: Mapped[list] = mapped_column(JSONType, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    investigation_steps: Mapped[list] = mapped_column(JSONType, default=list)
    false_positive_notes: Mapped[str] = mapped_column(Text, default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)
    updated_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(ForeignKey("detection_rules.id", ondelete="RESTRICT"), index=True)
    # Identifies what the alert is about (e.g. "username:alice"). Used to merge repeated findings.
    group_key: Mapped[str] = mapped_column(String(255), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    score_breakdown: Mapped[list] = mapped_column(JSONType, default=list)
    evidence_summary: Mapped[dict] = mapped_column(JSONType, default=dict)
    status: Mapped[str] = mapped_column(String(20), default="new", index=True)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(TZDateTime)
    last_seen: Mapped[datetime] = mapped_column(TZDateTime, index=True)
    assigned_to_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    acknowledged_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    acknowledged_at: Mapped[datetime | None] = mapped_column(TZDateTime, nullable=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="RESTRICT"), index=True)
    is_synthetic: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, index=True)
    updated_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow, onupdate=utcnow)

    rule: Mapped[DetectionRule] = relationship(lazy="joined")


class AlertEvent(Base):
    """Evidence link: which stored events caused an alert."""

    __tablename__ = "alert_events"
    __table_args__ = (UniqueConstraint("alert_id", "event_id", name="uq_alert_events_alert_event"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("security_events.id", ondelete="CASCADE"), index=True)


class AlertActivity(Base):
    """Append-only history of an alert: notes, status changes, assignments, rescoring."""

    __tablename__ = "alert_activity"

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[int] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    activity_type: Mapped[str] = mapped_column(String(32))  # created, note, status_change, assigned, ...
    from_value: Mapped[str | None] = mapped_column(String(64), nullable=True)
    to_value: Mapped[str | None] = mapped_column(String(64), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(TZDateTime, default=utcnow)
