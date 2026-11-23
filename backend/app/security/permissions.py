"""Role-based access control.

Permissions are defined in one place so the backend is the single source of truth.
The frontend receives the user's permission list from /auth/me only to decide what
to display; every endpoint still checks permissions on the server.
"""

from enum import StrEnum


class Perm(StrEnum):
    DASHBOARD_READ = "dashboard:read"
    EVENTS_READ = "events:read"
    EVENTS_INGEST = "events:ingest"
    EVENTS_EXPORT = "events:export"
    ALERTS_READ = "alerts:read"
    ALERTS_TRIAGE = "alerts:triage"  # acknowledge, add notes
    ALERTS_MANAGE = "alerts:manage"  # assign, change status, false positive, convert to incident
    INCIDENTS_READ = "incidents:read"
    INCIDENTS_MANAGE = "incidents:manage"
    RULES_READ = "rules:read"
    RULES_MANAGE = "rules:manage"
    DETECTION_RUN = "detection:run"
    INTEL_LOOKUP = "intel:lookup"
    INTEL_MANAGE = "intel:manage"
    ANOMALY_RUN = "anomaly:run"
    AI_USE = "ai:use"
    REPORTS_READ = "reports:read"
    REPORTS_GENERATE = "reports:generate"
    NOTIFICATIONS_READ = "notifications:read"
    AUDIT_READ = "audit:read"
    USERS_MANAGE = "users:manage"
    SETTINGS_MANAGE = "settings:manage"
    DEMO_MANAGE = "demo:manage"


ROLE_DEFINITIONS: dict[str, dict] = {
    "admin": {
        "display_name": "Administrator",
        "description": "Configures the platform, manages users and oversees incidents.",
        "permissions": set(Perm),
    },
    "soc_analyst": {
        "display_name": "SOC Analyst",
        "description": "Monitors alerts, investigates events and manages incidents.",
        "permissions": {
            Perm.DASHBOARD_READ, Perm.EVENTS_READ, Perm.EVENTS_INGEST, Perm.EVENTS_EXPORT,
            Perm.ALERTS_READ, Perm.ALERTS_TRIAGE, Perm.ALERTS_MANAGE,
            Perm.INCIDENTS_READ, Perm.INCIDENTS_MANAGE, Perm.RULES_READ, Perm.DETECTION_RUN,
            Perm.INTEL_LOOKUP, Perm.ANOMALY_RUN, Perm.AI_USE,
            Perm.REPORTS_READ, Perm.REPORTS_GENERATE, Perm.NOTIFICATIONS_READ,
        },
    },
    "it_admin": {
        "display_name": "IT Administrator",
        "description": "Reviews infrastructure events and system activity.",
        "permissions": {
            Perm.DASHBOARD_READ, Perm.EVENTS_READ, Perm.EVENTS_INGEST, Perm.EVENTS_EXPORT,
            Perm.ALERTS_READ, Perm.ALERTS_TRIAGE, Perm.INCIDENTS_READ, Perm.RULES_READ,
            Perm.INTEL_LOOKUP, Perm.AI_USE, Perm.REPORTS_READ, Perm.REPORTS_GENERATE,
            Perm.NOTIFICATIONS_READ,
        },
    },
    "viewer": {
        "display_name": "Read-Only Viewer",
        "description": "Views dashboards, reports and statistics without changing anything.",
        "permissions": {
            Perm.DASHBOARD_READ, Perm.EVENTS_READ, Perm.ALERTS_READ, Perm.INCIDENTS_READ,
            Perm.RULES_READ, Perm.REPORTS_READ, Perm.NOTIFICATIONS_READ,
        },
    },
}

# Roles whose members can be assigned alerts and incidents.
ASSIGNABLE_ROLES = {"admin", "soc_analyst"}


def permissions_for(role: str) -> set[str]:
    definition = ROLE_DEFINITIONS.get(role)
    return {str(p) for p in definition["permissions"]} if definition else set()


def has_permission(role: str, permission: Perm) -> bool:
    return str(permission) in permissions_for(role)
