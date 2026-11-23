"""Import every model so SQLAlchemy metadata (and Alembic) can see all tables."""

from app.models.detection import Alert, AlertActivity, AlertEvent, DetectionRule
from app.models.event import IngestionJob, SecurityEvent
from app.models.incident import Incident, IncidentHistory, IncidentNote
from app.models.misc import (
    AnomalyResult,
    AppSetting,
    AuditLog,
    Notification,
    Report,
    ThreatIndicator,
    ThreatLookup,
)
from app.models.user import ApiKey, RefreshToken, Role, User

__all__ = [
    "Alert",
    "AlertActivity",
    "AlertEvent",
    "AnomalyResult",
    "ApiKey",
    "AppSetting",
    "AuditLog",
    "DetectionRule",
    "Incident",
    "IncidentHistory",
    "IncidentNote",
    "IngestionJob",
    "Notification",
    "RefreshToken",
    "Report",
    "Role",
    "SecurityEvent",
    "ThreatIndicator",
    "ThreatLookup",
    "User",
]
