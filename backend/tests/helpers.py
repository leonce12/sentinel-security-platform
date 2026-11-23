"""Builders for hand-made test events."""

from datetime import UTC, datetime, timedelta
from itertools import count

from app.detection.rules import EventView

BASE = datetime(2026, 11, 10, 10, 0, tzinfo=UTC)  # a Tuesday, inside business hours
_ids = count(1)


def view(minutes: float = 0, **fields) -> EventView:
    defaults = dict(id=next(_ids), timestamp=BASE + timedelta(minutes=minutes), source_system="vpn-gw-01",
                    event_category="authentication", event_type="login_failure", outcome="failure",
                    username="alice", source_ip="10.0.0.5")
    defaults.update(fields)
    return EventView(**defaults)


def record(minutes: float = 0, **fields) -> dict:
    """A raw input record as it would appear in an uploaded file."""
    base = {"timestamp": (BASE + timedelta(minutes=minutes)).isoformat(), "source_system": "vpn-gw-01",
            "event_category": "authentication", "event_type": "login_failure", "outcome": "failure",
            "username": "alice", "source_ip": "10.0.0.5", "severity": "low", "description": "Invalid password"}
    base.update(fields)
    return base


def failures(n: int, start_minute: float = 0, spacing: float = 0.5, **fields) -> list[dict]:
    return [record(start_minute + i * spacing, **fields) for i in range(n)]
