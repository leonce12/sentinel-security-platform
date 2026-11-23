"""Runtime application settings stored in the database (editable by administrators).

Environment variables hold secrets and deployment configuration. These settings hold
operational choices that an administrator may change from the Settings page.
"""

from typing import Any

from sqlalchemy.orm import Session

from app.models import AppSetting, User
from app.services import audit

DEFAULT_SETTINGS: dict[str, Any] = {
    # Authentication
    "allow_self_registration": False,
    # Detection
    "auto_detect_after_ingestion": True,
    "auto_incident_enabled": True,
    "auto_incident_min_score": 80,
    "business_hours_start": 7,  # UTC hour, inclusive
    "business_hours_end": 19,  # UTC hour, exclusive
    # Asset importance used by risk scoring. Keys are source_system values.
    "asset_criticality": {},  # e.g. {"dc-01.corp.example": "high"}
    # Threat intelligence
    "external_intel_enabled": False,  # explicit opt-in: sends single IPs to VirusTotal
    "intel_cache_hours": 24,
    # Machine learning
    "anomaly_detection_enabled": False,  # experimental, opt-in
    "anomaly_contamination": 0.05,
    # AI analyst
    "ai_enabled": False,  # explicit opt-in even when a provider is configured
    # Notifications
    "email_notifications_enabled": False,  # never send anything externally by default
}

_VALIDATORS = {
    "auto_incident_min_score": lambda v: isinstance(v, int) and 0 <= v <= 100,
    "business_hours_start": lambda v: isinstance(v, int) and 0 <= v <= 23,
    "business_hours_end": lambda v: isinstance(v, int) and 1 <= v <= 24,
    "intel_cache_hours": lambda v: isinstance(v, int) and 1 <= v <= 720,
    "anomaly_contamination": lambda v: isinstance(v, (int, float)) and 0.001 <= v <= 0.5,
    "asset_criticality": lambda v: isinstance(v, dict) and all(x in ("low", "medium", "high") for x in v.values()),
}


def get_all(db: Session) -> dict[str, Any]:
    stored = {row.key: row.value for row in db.query(AppSetting).all()}
    return {key: stored.get(key, default) for key, default in DEFAULT_SETTINGS.items()}


def get(db: Session, key: str) -> Any:
    row = db.get(AppSetting, key)
    return row.value if row is not None else DEFAULT_SETTINGS[key]


def update(db: Session, changes: dict[str, Any], actor: User) -> dict[str, Any]:
    from app.core.errors import AppError

    for key, value in changes.items():
        if key not in DEFAULT_SETTINGS:
            raise AppError(f"Unknown setting: {key}", 422, "validation_error")
        default = DEFAULT_SETTINGS[key]
        if isinstance(default, bool) and not isinstance(value, bool):
            raise AppError(f"Setting {key} must be true or false", 422, "validation_error")
        validator = _VALIDATORS.get(key)
        if validator and not validator(value):
            raise AppError(f"Invalid value for {key}", 422, "validation_error")
    before = get_all(db)
    for key, value in changes.items():
        row = db.get(AppSetting, key)
        if row is None:
            db.add(AppSetting(key=key, value=value, updated_by_id=actor.id))
        else:
            row.value = value
            row.updated_by_id = actor.id
    audit.record(
        db,
        "settings.update",
        actor=actor,
        object_type="settings",
        details={"changes": {k: {"from": before.get(k), "to": v} for k, v in changes.items()}},
    )
    db.commit()
    return get_all(db)
