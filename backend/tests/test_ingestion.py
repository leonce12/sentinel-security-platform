import json
from datetime import UTC, datetime

import pytest

from app.core.errors import AppError
from app.ingestion.normalize import normalize_record, normalize_severity, parse_timestamp
from app.ingestion.parsers import ParseError, parse_csv, parse_json, parse_upload
from app.models import IngestionJob, SecurityEvent
from app.services.export import safe_cell, to_csv
from tests.helpers import record

API = "/api/v1"


# ---- normalization unit tests -----------------------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("2026-11-10T10:00:00Z", datetime(2026, 11, 10, 10, tzinfo=UTC)),
    ("2026-11-10T13:00:00+03:00", datetime(2026, 11, 10, 10, tzinfo=UTC)),
    ("2026-11-10 10:00:00", datetime(2026, 11, 10, 10, tzinfo=UTC)),
    (1794304800, datetime(2026, 11, 10, 10, tzinfo=UTC)),
    ("1794304800000", datetime(2026, 11, 10, 10, tzinfo=UTC)),
])
def test_timestamps_normalize_to_utc(value, expected):
    parsed, _ = parse_timestamp(value)
    assert parsed == expected


def test_naive_timestamp_gets_warning():
    event, errors = normalize_record(record(timestamp="2026-11-10 10:00:00"))
    assert not errors and any("assumed UTC" in w for w in event.warnings)


@pytest.mark.parametrize("bad", ["not a date", "", None, "2026-13-45"])
def test_invalid_timestamps_are_rejected(bad):
    event, errors = normalize_record(record(timestamp=bad))
    assert event is None and errors[0].field == "timestamp"


def test_future_timestamp_rejected():
    event, errors = normalize_record(record(timestamp="2099-01-01T00:00:00Z"))
    assert event is None and "future" in errors[0].message


def test_invalid_ip_rejected_and_missing_ip_allowed():
    assert normalize_record(record(source_ip="999.1.1.1"))[0] is None
    event, errors = normalize_record(record(source_ip=""))
    assert not errors and event.source_ip is None
    event, _ = normalize_record(record(source_ip="2001:DB8::1"))
    assert event.source_ip == "2001:db8::1"


def test_missing_event_type_rejected_with_all_errors_reported():
    _, errors = normalize_record(record(event_type="", source_ip="bad", timestamp="bad"))
    assert {e.field for e in errors} == {"timestamp", "event_type", "source_ip"}


@pytest.mark.parametrize("raw,expected", [("CRITICAL", "critical"), ("warning", "medium"), ("info", "informational"),
                                          ("8", "high"), ("9", "critical"), ("5.5", "medium"), ("2", "low"), ("0", "informational"), ("bogus", "informational")])
def test_severity_mapping(raw, expected):
    assert normalize_severity(raw)[0] == expected


def test_field_aliases_and_category_inference():
    event, _ = normalize_record({"time": "2026-11-10T10:00:00Z", "host": "srv1", "src_ip": "10.1.1.1",
                                 "user": "Alice", "type": "Login Failed", "level": "warn", "msg": "bad pw"})
    assert event.source_system == "srv1" and event.username == "alice" and event.event_type == "login_failed"
    assert event.event_category == "authentication" and event.outcome == "failure" and event.severity == "medium"


def test_unknown_fields_are_kept_in_raw_data_and_text_is_sanitized():
    event, _ = normalize_record(record(description="line\x00with\x07control", custom_field="kept"))
    assert event.description == "linewithcontrol"
    assert event.raw_data["custom_field"] == "kept"


def test_oversized_raw_payload_is_truncated():
    event, _ = normalize_record(record(raw={"blob": "x" * 50_000}))
    assert event.raw_data["_truncated"] is True


def test_fingerprint_uses_event_id_when_present():
    a, _ = normalize_record(record(event_id="E1", description="first"))
    b, _ = normalize_record(record(event_id="E1", description="changed"))
    c, _ = normalize_record(record(description="first"))
    d, _ = normalize_record(record(description="first"))
    assert a.fingerprint == b.fingerprint
    assert c.fingerprint == d.fingerprint != a.fingerprint


# ---- parsing -----------------------------------------------------------------------------------
def test_parse_json_variants():
    one = json.dumps(record())
    assert len(parse_json(f"[{one},{one}]", 10)) == 2
    assert len(parse_json(json.dumps({"events": [record(), record()]}), 10)) == 2
    assert len(parse_json(f"{one}\n{one}\n", 10)) == 2  # NDJSON
    with pytest.raises(ParseError):
        parse_json("[]", 10)
    with pytest.raises(ParseError):
        parse_json('{"a": 1}\n{broken', 10)


def test_parse_csv_limits_and_errors():
    assert len(parse_csv("timestamp,event_type\n2026-11-10T10:00:00Z,x\n", 10)) == 1
    with pytest.raises(ParseError):
        parse_csv("timestamp,event_type\n" + "2026-11-10T10:00:00Z,x\n" * 3, 2)
    with pytest.raises(ParseError):
        parse_csv("", 10)


def test_upload_rejects_binary_empty_and_oversized():
    with pytest.raises(ParseError):
        parse_upload(b"\x00\x01\x02binary", "x.csv", 1000, 10)
    with pytest.raises(ParseError):
        parse_upload(b"", "x.csv", 1000, 10)
    with pytest.raises(AppError) as exc:
        parse_upload(b"a" * 2000, "x.csv", 1000, 10)
    assert exc.value.status_code == 413


# ---- API ingestion -----------------------------------------------------------------------------
def _csv(rows: list[dict]) -> bytes:
    cols = sorted({k for r in rows for k in r})
    return to_csv(rows, cols).encode()


def test_csv_upload_summary_counts(client, headers, db):
    rows = [record(i) for i in range(5)] + [record(0)]  # last one is an exact duplicate
    rows.append(record(10, timestamp="garbage"))
    r = client.post(f"{API}/ingest/upload", headers=headers["soc_analyst"],
                    files={"file": ("logs.csv", _csv(rows), "text/csv")}, data={"run_detection": "false"})
    assert r.status_code == 201, r.text
    job = r.json()
    assert (job["total_records"], job["processed_records"], job["duplicate_records"], job["rejected_records"]) == (7, 5, 1, 1)
    assert job["errors"][0]["record"] == 7 and job["errors"][0]["errors"][0]["field"] == "timestamp"
    assert job["status"] == "completed" and job["duration_ms"] >= 0
    assert db.query(SecurityEvent).count() == 5


def test_json_upload_and_cross_upload_duplicates(client, headers, db):
    body = json.dumps([record(i, event_id=f"J{i}") for i in range(3)]).encode()
    first = client.post(f"{API}/ingest/upload", headers=headers["admin"], files={"file": ("a.json", body, "application/json")})
    second = client.post(f"{API}/ingest/upload", headers=headers["admin"], files={"file": ("b.json", body, "application/json")})
    assert first.json()["processed_records"] == 3
    assert second.json()["processed_records"] == 0 and second.json()["duplicate_records"] == 3
    assert db.query(SecurityEvent).count() == 3


def test_upload_rejects_wrong_extension_and_records_failures(client, headers, db):
    assert client.post(f"{API}/ingest/upload", headers=headers["admin"],
                       files={"file": ("evil.exe", b"MZ", "application/octet-stream")}).status_code == 415
    r = client.post(f"{API}/ingest/upload", headers=headers["admin"], files={"file": ("bad.json", b"{not json", "application/json")})
    assert r.status_code == 422
    job = db.query(IngestionJob).one()
    assert job.status == "failed" and job.errors


def test_all_invalid_upload_marks_job_failed_and_notifies(client, headers):
    body = json.dumps([record(timestamp="bad"), record(event_type="")]).encode()
    r = client.post(f"{API}/ingest/upload", headers=headers["soc_analyst"], files={"file": ("x.json", body, "application/json")})
    assert r.json()["status"] == "failed" and r.json()["rejected_records"] == 2
    notes = client.get(f"{API}/notifications", headers=headers["soc_analyst"]).json()["items"]
    assert notes[0]["notification_type"] == "ingestion_failed"


def test_upload_size_limit_enforced(client, headers, monkeypatch):
    from app.core.config import get_settings
    monkeypatch.setattr(get_settings(), "max_upload_mb", 1)
    big = b"timestamp,event_type\n" + b"2026-11-10T10:00:00Z,x\n" * 60_000
    assert client.post(f"{API}/ingest/upload", headers=headers["admin"],
                       files={"file": ("big.csv", big, "text/csv")}).status_code == 413


def test_manual_event_submission(client, headers):
    r = client.post(f"{API}/events", headers=headers["it_admin"], json=record(event_type="service_restart",
                                                                                event_category="system"))
    assert r.status_code == 201 and r.json()["processed_records"] == 1
    events = client.get(f"{API}/events", headers=headers["viewer"]).json()
    assert events["total"] == 1 and events["items"][0]["event_type"] == "service_restart"


def test_api_key_ingestion(client, headers, db):
    created = client.post(f"{API}/api-keys", headers=headers["admin"], json={"name": "edr-connector"}).json()
    key = created["key"]
    assert client.post(f"{API}/ingest/events", json={"events": [record()]}).status_code == 401
    assert client.post(f"{API}/ingest/events", headers={"X-API-Key": "snt_bad.key"}, json={"events": [record()]}).status_code == 401
    r = client.post(f"{API}/ingest/events", headers={"X-API-Key": key}, json={"events": [record(), record(1)]})
    assert r.status_code == 201 and r.json()["processed_records"] == 2
    client.post(f"{API}/api-keys/{created['id']}/revoke", headers=headers["admin"])
    assert client.post(f"{API}/ingest/events", headers={"X-API-Key": key}, json={"events": [record(2)]}).status_code == 401
    listed = client.get(f"{API}/api-keys", headers=headers["admin"]).json()
    assert "key" not in listed[0] and "key_hash" not in listed[0]


def test_uploaded_content_is_never_executed(client, headers, db):
    payload = record(description="=cmd|' /C calc'!A0", resource="__import__('os').system('id')")
    client.post(f"{API}/events", headers=headers["admin"], json=payload)
    stored = db.query(SecurityEvent).one()
    assert stored.description == "=cmd|' /C calc'!A0"  # stored as plain text
    export = client.get(f"{API}/events/export?format=csv", headers=headers["admin"]).text
    assert "'=cmd|" in export  # neutralized for spreadsheets


def test_csv_formula_cells_are_escaped():
    assert safe_cell("=SUM(A1)") == "'=SUM(A1)" and safe_cell("+1") == "'+1" and safe_cell("@x") == "'@x"
    assert safe_cell("normal") == "normal" and safe_cell(None) == ""


def test_event_filters_and_pagination(client, headers):
    for i in range(30):
        client.post(f"{API}/events", headers=headers["admin"], json=record(i, severity="high" if i % 3 == 0 else "low",
                                                                             event_id=f"F{i}"), params={"run_detection": False})
    page = client.get(f"{API}/events", headers=headers["viewer"], params={"page_size": 10, "page": 2}).json()
    assert page["total"] == 30 and len(page["items"]) == 10 and page["pages"] == 3
    high = client.get(f"{API}/events", headers=headers["viewer"], params={"severity": "high"}).json()
    assert high["total"] == 10
    asc = client.get(f"{API}/events", headers=headers["viewer"], params={"sort": "timestamp", "order": "asc"}).json()
    assert asc["items"][0]["event_uid"] == "F0"
    found = client.get(f"{API}/events", headers=headers["viewer"], params={"q": "F17"}).json()
    assert found["total"] == 1
