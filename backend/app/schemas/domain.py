"""Request and response schemas for events, alerts, incidents and supporting modules."""

import datetime as dt
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.schemas.common import ORMModel, UserRef

Severity = Literal["informational", "low", "medium", "high", "critical"]


# ---- events & ingestion ----------------------------------------------------------------------
class EventOut(ORMModel):
    id: int
    event_uid: str
    timestamp: datetime
    source_system: str
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    event_category: str
    event_type: str
    severity: str
    action: str | None
    outcome: str | None
    resource: str | None
    description: str
    risk_score: float | None
    is_synthetic: bool
    ingestion_job_id: int | None
    ingested_at: datetime


class EventDetail(EventOut):
    raw_data: dict
    alerts: list["AlertBrief"]
    incidents: list["IncidentBrief"]


class ManualEvent(BaseModel):
    """One event submitted from the UI or the API. Validated again by the normalizer."""

    event_id: str | None = Field(default=None, max_length=128)
    timestamp: str = Field(min_length=1, max_length=64)
    source_system: str = Field(min_length=1, max_length=128)
    source_ip: str | None = Field(default=None, max_length=64)
    destination_ip: str | None = Field(default=None, max_length=64)
    username: str | None = Field(default=None, max_length=128)
    event_category: str = Field(min_length=1, max_length=32)
    event_type: str = Field(min_length=1, max_length=64)
    severity: str = Field(default="informational", max_length=16)
    action: str | None = Field(default=None, max_length=64)
    outcome: str | None = Field(default=None, max_length=16)
    resource: str | None = Field(default=None, max_length=512)
    description: str = Field(default="", max_length=4000)
    raw: dict[str, Any] | None = None


class ApiIngestBatch(BaseModel):
    events: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class IngestionJobOut(ORMModel):
    id: int
    source_type: str
    filename: str | None
    status: str
    total_records: int
    processed_records: int
    rejected_records: int
    duplicate_records: int
    duration_ms: int
    errors: list
    warnings: list
    is_synthetic: bool
    detection_summary: dict | None
    created_at: datetime


# ---- rules & detection ------------------------------------------------------------------------
class RuleOut(ORMModel):
    id: str
    name: str
    description: str
    category: str
    severity: str
    base_score: int
    confidence: float
    parameters: dict
    required_fields: list
    rationale: str
    investigation_steps: list
    false_positive_notes: str
    enabled: bool
    updated_at: datetime


class RuleUpdate(BaseModel):
    enabled: bool | None = None
    severity: Severity | None = None
    base_score: int | None = Field(default=None, ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0.1, le=1.0)
    parameters: dict[str, Any] | None = None


class DetectionRunRequest(BaseModel):
    job_id: int | None = None
    start: datetime | None = None
    end: datetime | None = None
    rule_ids: list[str] | None = None


# ---- alerts -----------------------------------------------------------------------------------
class AlertBrief(ORMModel):
    id: int
    rule_id: str
    title: str
    severity: str
    risk_score: int
    status: str
    incident_id: int | None


class AlertOut(ORMModel):
    id: int
    rule_id: str
    rule_name: str
    group_key: str
    title: str
    description: str
    severity: str
    risk_score: int
    status: str
    event_count: int
    first_seen: datetime
    last_seen: datetime
    assigned_to: UserRef | None
    incident_id: int | None
    incident_reference: str | None
    is_synthetic: bool
    created_at: datetime


class ActivityOut(ORMModel):
    id: int
    activity_type: str
    from_value: str | None
    to_value: str | None
    note: str
    actor: UserRef | None
    created_at: datetime


class AlertDetail(AlertOut):
    score_breakdown: list
    evidence_summary: dict
    rule: RuleOut
    acknowledged_at: datetime | None
    activity: list[ActivityOut]
    events: list[EventOut]
    events_total: int


class AlertStatusChange(BaseModel):
    status: Literal["acknowledged", "investigating", "resolved", "false_positive"]
    reason: str = Field(default="", max_length=2000)


class AssignRequest(BaseModel):
    user_id: int | None


class NoteRequest(BaseModel):
    body: str = Field(min_length=1, max_length=5000)


class ConvertRequest(BaseModel):
    incident_id: int | None = None
    title: str | None = Field(default=None, max_length=255)


# ---- incidents --------------------------------------------------------------------------------
class IncidentBrief(ORMModel):
    id: int
    reference: str
    title: str
    status: str
    severity: str


class IncidentOut(ORMModel):
    id: int
    reference: str
    title: str
    description: str
    severity: str
    risk_score: int
    status: str
    affected_entities: dict
    detected_at: datetime
    assigned_to: UserRef | None
    resolution: str | None
    closed_at: datetime | None
    auto_created: bool
    is_synthetic: bool
    alert_count: int
    created_at: datetime
    updated_at: datetime


class NoteOut(ORMModel):
    id: int
    body: str
    author: UserRef | None
    created_at: datetime


class HistoryOut(ORMModel):
    id: int
    change_type: str
    from_value: str | None
    to_value: str | None
    details: str
    actor: UserRef | None
    created_at: datetime


class IncidentDetail(IncidentOut):
    alerts: list[AlertBrief]
    notes: list[NoteOut]
    history: list[HistoryOut]


class IncidentCreate(BaseModel):
    title: str = Field(min_length=5, max_length=255)
    description: str = Field(default="", max_length=10000)
    severity: Severity = "medium"
    alert_ids: list[int] = Field(default_factory=list, max_length=100)
    assigned_to_id: int | None = None


class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=5, max_length=255)
    description: str | None = Field(default=None, max_length=10000)
    severity: Severity | None = None


class IncidentStatusChange(BaseModel):
    status: Literal["open", "investigating", "contained", "resolved", "closed"]
    note: str = Field(default="", max_length=2000)
    resolution: str | None = Field(default=None, max_length=10000)


class LinkAlertRequest(BaseModel):
    alert_id: int


# ---- intel, anomaly, ai, reports, notifications, audit -------------------------------------
class IntelLookupRequest(BaseModel):
    indicator: str = Field(min_length=2, max_length=64)


class LookupOut(ORMModel):
    id: int
    indicator: str
    provider: str
    verdict: str
    confidence: float | None
    details: dict
    limitations: str
    looked_up_at: datetime
    expires_at: datetime | None


class IndicatorOut(ORMModel):
    id: int
    indicator: str
    indicator_type: str
    verdict: str
    confidence: float
    source: str
    description: str
    is_synthetic: bool
    added_at: datetime


class IndicatorCreate(BaseModel):
    indicator: str = Field(min_length=2, max_length=64)
    verdict: Literal["malicious", "suspicious"]
    confidence: float = Field(ge=0, le=1)
    source: str = Field(default="analyst", min_length=2, max_length=64)
    description: str = Field(default="", max_length=1000)


class AnomalyOut(ORMModel):
    id: int
    entity: str
    window_start: datetime
    window_end: datetime
    features: dict
    anomaly_score: float
    is_anomaly: bool
    contributing_features: list
    model_version: str
    review_status: str
    review_note: str
    reviewed_at: datetime | None
    is_synthetic: bool


class AnomalyReview(BaseModel):
    status: Literal["needs_follow_up", "false_positive", "unreviewed"]
    note: str = Field(default="", max_length=2000)


class AskRequest(BaseModel):
    question: str = Field(min_length=3, max_length=1000)


class ReportRequest(BaseModel):
    report_type: Literal["daily", "weekly", "incident"]
    date: dt.date | None = None
    start_date: dt.date | None = None
    incident_id: int | None = None


class ReportOut(ORMModel):
    id: int
    report_type: str
    title: str
    parameters: dict
    period_start: datetime | None
    period_end: datetime | None
    summary: dict
    sha256: str
    size_bytes: int
    generated_by: UserRef | None
    generated_at: datetime


class NotificationOut(ORMModel):
    id: int
    notification_type: str
    title: str
    message: str
    link: str | None
    is_read: bool
    created_at: datetime


class AuditOut(ORMModel):
    id: int
    actor_username: str | None
    action: str
    object_type: str | None
    object_id: str | None
    outcome: str
    ip_address: str | None
    details: dict
    created_at: datetime


class ResetConfirm(BaseModel):
    confirm: Literal["RESET DEMO DATA"]


EventDetail.model_rebuild()
