"""CSV and JSON exports.

CSV cells that start with = + - @ (or a tab/carriage return) are prefixed with an
apostrophe. Log data is attacker-controlled, and without this a spreadsheet program
could interpret a cell as a formula (CSV injection).
"""

import csv
import io
import json
from datetime import datetime

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r")
MAX_EXPORT_ROWS = 50_000


def safe_cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (dict, list)):
        value = json.dumps(value, default=str)
    text = str(value)
    return "'" + text if text.startswith(_FORMULA_START) else text


def to_csv(rows: list[dict], columns: list[str]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([safe_cell(row.get(c)) for c in columns])
    return buffer.getvalue()


def to_json(rows: list[dict], metadata: dict) -> str:
    return json.dumps({"metadata": metadata, "records": rows}, default=str, indent=2)


EVENT_COLUMNS = ["id", "event_uid", "timestamp", "source_system", "source_ip", "destination_ip", "username",
                 "event_category", "event_type", "severity", "action", "outcome", "resource", "description",
                 "risk_score", "is_synthetic", "ingested_at"]
ALERT_COLUMNS = ["id", "rule_id", "title", "severity", "risk_score", "status", "event_count", "first_seen", "last_seen",
                 "group_key", "incident_id", "is_synthetic", "created_at"]
INCIDENT_COLUMNS = ["id", "reference", "title", "severity", "risk_score", "status", "detected_at", "assigned_to_id",
                    "resolution", "closed_at", "is_synthetic", "created_at"]


def model_rows(items, columns: list[str]) -> list[dict]:
    return [{c: getattr(item, c) for c in columns} for item in items]
