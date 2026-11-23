"""Audit logging service.

Audit records describe who did what, to which object, and with what outcome. They
must never contain secrets, so details pass through a redaction filter first.
"""

from typing import Any

from sqlalchemy.orm import Session

from app.models import AuditLog, User

_SENSITIVE_KEYS = ("password", "token", "secret", "api_key", "apikey", "authorization", "cookie", "hash")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: ("[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEYS) else redact(v)) for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    return value


def record(
    db: Session,
    action: str,
    *,
    actor: User | None = None,
    actor_username: str | None = None,
    object_type: str | None = None,
    object_id: str | int | None = None,
    outcome: str = "success",
    ip_address: str | None = None,
    details: dict | None = None,
    commit: bool = False,
) -> AuditLog:
    """Add an audit entry to the current transaction (commit with the caller's change)."""
    entry = AuditLog(
        actor_id=actor.id if actor else None,
        actor_username=actor.username if actor else actor_username,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        outcome=outcome,
        ip_address=ip_address,
        details=redact(details or {}),
    )
    db.add(entry)
    if commit:
        db.commit()
    return entry
