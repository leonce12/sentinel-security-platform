"""Convert ORM objects into response schemas, resolving user references in bulk."""

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import Alert, Incident, User
from app.schemas.common import UserRef
from app.schemas.domain import AlertOut, IncidentOut


class UserCache:
    def __init__(self, db: Session):
        self.db = db
        self._cache: dict[int, UserRef | None] = {}

    def ref(self, user_id: int | None) -> UserRef | None:
        if user_id is None:
            return None
        if user_id not in self._cache:
            user = self.db.get(User, user_id)
            self._cache[user_id] = UserRef.model_validate(user) if user else None
        return self._cache[user_id]


def alert_out(alert: Alert, users: UserCache, references: dict[int, str] | None = None) -> AlertOut:
    reference = None
    if alert.incident_id:
        reference = (references or {}).get(alert.incident_id)
        if reference is None:
            inc = users.db.get(Incident, alert.incident_id)
            reference = inc.reference if inc else None
    return AlertOut(
        id=alert.id, rule_id=alert.rule_id, rule_name=alert.rule.name, group_key=alert.group_key, title=alert.title,
        description=alert.description, severity=alert.severity, risk_score=alert.risk_score, status=alert.status,
        event_count=alert.event_count, first_seen=alert.first_seen, last_seen=alert.last_seen,
        assigned_to=users.ref(alert.assigned_to_id), incident_id=alert.incident_id, incident_reference=reference,
        is_synthetic=alert.is_synthetic, created_at=alert.created_at,
    )


def incident_out(incident: Incident, users: UserCache, alert_count: int | None = None) -> IncidentOut:
    if alert_count is None:
        alert_count = users.db.query(func.count(Alert.id)).filter(Alert.incident_id == incident.id).scalar() or 0
    return IncidentOut(
        id=incident.id, reference=incident.reference, title=incident.title, description=incident.description,
        severity=incident.severity, risk_score=incident.risk_score, status=incident.status,
        affected_entities=incident.affected_entities or {}, detected_at=incident.detected_at,
        assigned_to=users.ref(incident.assigned_to_id), resolution=incident.resolution, closed_at=incident.closed_at,
        auto_created=incident.auto_created, is_synthetic=incident.is_synthetic, alert_count=alert_count,
        created_at=incident.created_at, updated_at=incident.updated_at,
    )
