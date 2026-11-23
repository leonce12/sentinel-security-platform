"""Event validation and normalization.

Every incoming record, whatever its source, is converted to one normalized shape.
Records are only ever treated as data: nothing in a record is evaluated or executed.

normalize_record() returns either a NormalizedEvent or a list of validation errors.
It never raises for bad input, so one malformed record cannot stop a batch.
"""

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pandas as pd

CATEGORIES = {"authentication", "access", "privilege", "configuration", "network", "system", "endpoint", "data", "other"}
CATEGORY_ALIASES = {
    "auth": "authentication", "login": "authentication", "logon": "authentication",
    "authorization": "access", "authz": "access", "access_control": "access",
    "iam": "privilege", "identity": "privilege", "privileges": "privilege",
    "config": "configuration", "change": "configuration",
    "net": "network", "firewall": "network",
    "host": "system", "os": "system", "application": "system", "app": "system",
    "malware": "endpoint", "edr": "endpoint", "antivirus": "endpoint",
    "file": "data", "database": "data", "integrity": "data",
}
SEVERITIES = ["informational", "low", "medium", "high", "critical"]
SEVERITY_ALIASES = {
    "info": "informational", "information": "informational", "notice": "informational", "debug": "informational",
    "warn": "medium", "warning": "medium", "moderate": "medium",
    "error": "high", "major": "high", "severe": "high",
    "crit": "critical", "alert": "critical", "emergency": "critical", "fatal": "critical",
}
SUCCESS_WORDS = {"success", "succeeded", "successful", "allowed", "allow", "ok", "permitted", "accepted", "true", "pass"}
FAILURE_WORDS = {"failure", "failed", "fail", "denied", "deny", "blocked", "block", "rejected", "error", "false", "invalid"}

# Accepted input names for each normalized field (first match wins).
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "event_id": ("event_id", "eventid", "id", "event_uid", "uid"),
    "timestamp": ("timestamp", "@timestamp", "time", "event_time", "datetime", "date", "ts"),
    "source_system": ("source_system", "source", "host", "hostname", "system", "device", "computer"),
    "source_ip": ("source_ip", "src_ip", "src", "client_ip", "ip", "remote_ip"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "dst", "target_ip", "server_ip"),
    "username": ("username", "user", "user_name", "account", "account_name", "principal"),
    "event_category": ("event_category", "category"),
    "event_type": ("event_type", "type", "event", "event_name", "name"),
    "severity": ("severity", "level", "priority", "sev"),
    "action": ("action", "operation", "verb"),
    "outcome": ("outcome", "result", "status"),
    "resource": ("resource", "target", "object", "path", "url", "file"),
    "description": ("description", "message", "msg", "details", "summary"),
}
KNOWN_INPUT_KEYS = {alias for aliases in FIELD_ALIASES.values() for alias in aliases} | {"raw", "raw_data", "synthetic"}

MAX_LENGTHS = {"event_id": 128, "source_system": 128, "username": 128, "event_type": 64, "action": 64,
               "resource": 512, "description": 4000}
MAX_RAW_BYTES = 16_384
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_EVENT_TYPE_CLEAN = re.compile(r"[^a-z0-9_.]+")

# Inference used only when a record has no category: the event type usually reveals it.
TYPE_TO_CATEGORY = [
    (("login", "logon", "auth", "mfa", "sso", "password"), "authentication"),
    (("privilege", "role", "group_member", "admin_granted", "sudo"), "privilege"),
    (("access", "permission_denied", "forbidden", "file_read", "unauthorized"), "access"),
    (("config", "policy", "integrity", "registry"), "configuration"),
    (("firewall", "connection", "dns", "port", "traffic", "network"), "network"),
    (("malware", "virus", "ransomware", "edr", "antivirus", "exfiltration", "intrusion"), "endpoint"),
]


@dataclass
class NormalizedEvent:
    event_uid: str
    fingerprint: str
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
    raw_data: dict
    is_synthetic: bool
    warnings: list[str] = field(default_factory=list)


@dataclass
class FieldError:
    field: str
    message: str


def sanitize_text(value: Any, max_length: int | None = None) -> str | None:
    """Convert to a clean string: strip control characters and whitespace, enforce length."""
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    text = _CONTROL_CHARS.sub("", str(value)).strip()
    if not text:
        return None
    if max_length and len(text) > max_length:
        text = text[: max_length - 3] + "..."
    return text


def _pick(record: dict, name: str) -> Any:
    lowered = {str(k).lower().strip(): v for k, v in record.items()}
    for alias in FIELD_ALIASES[name]:
        if alias in lowered and lowered[alias] not in (None, ""):
            return lowered[alias]
    return None


def parse_timestamp(value: Any) -> tuple[datetime | None, str | None]:
    """Parse ISO 8601, common date formats, or Unix epoch seconds/milliseconds. Returns (dt, warning)."""
    if value is None or value == "":
        return None, None
    warning = None
    try:
        if isinstance(value, (int, float)) or (isinstance(value, str) and re.fullmatch(r"\d{9,13}(\.\d+)?", value.strip())):
            number = float(value)
            if number > 1e11:  # milliseconds
                number /= 1000
            parsed = datetime.fromtimestamp(number, tz=UTC)
        else:
            stamp = pd.Timestamp(str(value).strip())
            if pd.isna(stamp):
                return None, None
            parsed = stamp.to_pydatetime()
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
                warning = "Timestamp had no timezone; assumed UTC"
            parsed = parsed.astimezone(UTC)
    except (ValueError, OverflowError, OSError, TypeError):
        return None, None
    return parsed, warning


def normalize_ip(value: Any) -> tuple[str | None, bool]:
    """Return (normalized_ip, valid). Missing values are valid (None)."""
    text = sanitize_text(value, 64)
    if text is None or text in ("-", "n/a", "none", "null"):
        return None, True
    try:
        return str(ipaddress.ip_address(text)), True
    except ValueError:
        return None, False


def normalize_category(value: Any, event_type: str | None) -> tuple[str, str | None]:
    text = (sanitize_text(value, 64) or "").lower().replace("-", "_").replace(" ", "_")
    if text in CATEGORIES:
        return text, None
    if text in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[text], None
    if event_type:
        for keywords, category in TYPE_TO_CATEGORY:
            if any(k in event_type for k in keywords):
                note = f"Category '{text}' not recognized; inferred" if text else "Category missing; inferred"
                return category, f"{note} '{category}' from event type"
    if text:
        return "other", f"Category '{text}' not recognized; stored as 'other'"
    return "other", "Category missing; stored as 'other'"


def normalize_severity(value: Any) -> tuple[str, str | None]:
    if value is None or value == "":
        return "informational", "Severity missing; defaulted to informational"
    text = str(value).strip().lower()
    if text in SEVERITIES:
        return text, None
    if text in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[text], None
    try:  # numeric 0-10 scales, banded like CVSS: 0 info, <4 low, <7 medium, <9 high, else critical
        number = float(text)
        if 0 <= number <= 10:
            index = 0 if number == 0 else 1 if number < 4 else 2 if number < 7 else 3 if number < 9 else 4
            return SEVERITIES[index], f"Numeric severity {text} mapped to {SEVERITIES[index]}"
    except ValueError:
        pass
    return "informational", f"Unknown severity '{text[:20]}'; defaulted to informational"


def normalize_outcome(value: Any, event_type: str) -> str | None:
    text = (sanitize_text(value, 32) or "").lower()
    if text in SUCCESS_WORDS:
        return "success"
    if text in FAILURE_WORDS:
        return "failure"
    if not text:
        if any(w in event_type for w in ("fail", "denied", "blocked", "rejected")):
            return "failure"
        if event_type.endswith("_success") or event_type.endswith("_succeeded"):
            return "success"
        return None
    return "unknown"


def _raw_payload(record: dict) -> dict:
    """Keep the original record (sanitized and size limited) for investigators."""
    raw: dict[str, Any] = {}
    nested = record.get("raw") or record.get("raw_data")
    if isinstance(nested, str):
        try:
            nested = json.loads(nested)
        except json.JSONDecodeError:
            nested = {"text": nested}
    if isinstance(nested, dict):
        raw.update(nested)
    for key, value in record.items():
        if str(key).lower() not in KNOWN_INPUT_KEYS and value not in (None, ""):
            raw[str(key)[:64]] = value
    cleaned = json.loads(json.dumps(raw, default=str))
    encoded = json.dumps(cleaned)
    if len(encoded) > MAX_RAW_BYTES:
        return {"_truncated": True, "preview": encoded[: MAX_RAW_BYTES // 2]}
    return cleaned


def compute_fingerprint(event_id: str | None, source_system: str, timestamp: datetime, parts: list[Any]) -> str:
    if event_id:
        basis = f"id|{source_system.lower()}|{event_id}"
    else:
        basis = "content|" + json.dumps([source_system.lower(), timestamp.isoformat(), *parts], default=str)
    return hashlib.sha256(basis.encode()).hexdigest()


def normalize_record(record: dict, *, default_synthetic: bool = False, now: datetime | None = None
                     ) -> tuple[NormalizedEvent | None, list[FieldError]]:
    if not isinstance(record, dict):
        return None, [FieldError("record", "Record must be an object with named fields")]
    now = now or datetime.now(UTC)
    errors: list[FieldError] = []
    warnings: list[str] = []

    timestamp, ts_warning = parse_timestamp(_pick(record, "timestamp"))
    if timestamp is None:
        errors.append(FieldError("timestamp", "Missing or unparseable timestamp"))
    else:
        if ts_warning:
            warnings.append(ts_warning)
        if timestamp > now + timedelta(days=1):
            errors.append(FieldError("timestamp", "Timestamp is more than one day in the future"))
        if timestamp.year < 2000:
            errors.append(FieldError("timestamp", "Timestamp is before the year 2000"))

    raw_type = sanitize_text(_pick(record, "event_type"), 200)
    event_type = _EVENT_TYPE_CLEAN.sub("_", raw_type.lower()).strip("_")[: MAX_LENGTHS["event_type"]] if raw_type else ""
    if not event_type:
        errors.append(FieldError("event_type", "Missing event type"))

    source_ip, ok_src = normalize_ip(_pick(record, "source_ip"))
    if not ok_src:
        errors.append(FieldError("source_ip", "Not a valid IPv4 or IPv6 address"))
    destination_ip, ok_dst = normalize_ip(_pick(record, "destination_ip"))
    if not ok_dst:
        errors.append(FieldError("destination_ip", "Not a valid IPv4 or IPv6 address"))

    if errors:
        return None, errors

    source_system = sanitize_text(_pick(record, "source_system"), MAX_LENGTHS["source_system"])
    if source_system is None:
        source_system = "unknown"
        warnings.append("Source system missing; stored as 'unknown'")

    category, cat_warning = normalize_category(_pick(record, "event_category"), event_type)
    severity, sev_warning = normalize_severity(_pick(record, "severity"))
    warnings += [w for w in (cat_warning, sev_warning) if w]

    username = sanitize_text(_pick(record, "username"), MAX_LENGTHS["username"])
    username = username.lower() if username else None
    action = sanitize_text(_pick(record, "action"), MAX_LENGTHS["action"])
    action = action.lower() if action else None
    outcome = normalize_outcome(_pick(record, "outcome"), event_type)
    resource = sanitize_text(_pick(record, "resource"), MAX_LENGTHS["resource"])
    description = sanitize_text(_pick(record, "description"), MAX_LENGTHS["description"]) or ""
    event_id = sanitize_text(_pick(record, "event_id"), MAX_LENGTHS["event_id"])

    synthetic_flag = record.get("synthetic")
    is_synthetic = default_synthetic or str(synthetic_flag).lower() in ("true", "1", "yes")

    fingerprint = compute_fingerprint(
        event_id, source_system, timestamp,
        [source_ip, destination_ip, username, category, event_type, action, outcome, resource, description],
    )
    return NormalizedEvent(
        event_uid=event_id or f"gen-{fingerprint[:16]}",
        fingerprint=fingerprint,
        timestamp=timestamp,
        source_system=source_system,
        source_ip=source_ip,
        destination_ip=destination_ip,
        username=username,
        event_category=category,
        event_type=event_type,
        severity=severity,
        action=action,
        outcome=outcome,
        resource=resource,
        description=description,
        raw_data=_raw_payload(record),
        is_synthetic=is_synthetic,
        warnings=warnings,
    ), []
