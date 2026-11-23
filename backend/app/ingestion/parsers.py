"""Parse uploaded files into a list of plain records.

Files are read as text and parsed as data. Nothing is executed. Size and record
limits are checked before and after parsing.
"""

import io
import json

import pandas as pd

from app.core.errors import AppError


class ParseError(AppError):
    def __init__(self, message: str):
        super().__init__(message, 422, "invalid_file")


def decode_upload(content: bytes) -> str:
    if b"\x00" in content[:8192]:
        raise ParseError("File appears to be binary. Upload a UTF-8 CSV or JSON file.")
    try:
        return content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ParseError("File is not valid UTF-8 text") from exc


def detect_format(filename: str | None, text: str) -> str:
    name = (filename or "").lower()
    if name.endswith(".csv"):
        return "csv"
    if name.endswith((".json", ".jsonl", ".ndjson")):
        return "json"
    stripped = text.lstrip()
    return "json" if stripped[:1] in ("[", "{") else "csv"


def parse_csv(text: str, max_records: int) -> list[dict]:
    try:
        # dtype=str: keep values exactly as written, no type guessing. keep_default_na=False:
        # an empty cell stays "" instead of becoming NaN.
        frame = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False, nrows=max_records + 1,
                            on_bad_lines="error", skipinitialspace=True)
    except (pd.errors.ParserError, pd.errors.EmptyDataError, ValueError) as exc:
        raise ParseError(f"Could not parse CSV: {str(exc).splitlines()[0][:200]}") from exc
    if frame.empty:
        raise ParseError("CSV file contains no records")
    if len(frame) > max_records:
        raise ParseError(f"File contains more than {max_records} records")
    frame.columns = [str(c).strip() for c in frame.columns]
    return frame.to_dict(orient="records")


def parse_json(text: str, max_records: int) -> list[dict]:
    stripped = text.strip()
    if not stripped:
        raise ParseError("JSON file is empty")
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        # Fall back to newline-delimited JSON (one object per line).
        data = []
        for line_no, line in enumerate(stripped.splitlines(), start=1):
            if line.strip():
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise ParseError(f"Invalid JSON on line {line_no}: {exc.msg}") from exc
    if isinstance(data, dict):
        data = data.get("events", [data])
    if not isinstance(data, list):
        raise ParseError("JSON must be an array of events, an object with an 'events' array, or NDJSON")
    if not data:
        raise ParseError("JSON file contains no records")
    if len(data) > max_records:
        raise ParseError(f"File contains more than {max_records} records")
    return data


def parse_upload(content: bytes, filename: str | None, max_bytes: int, max_records: int) -> tuple[str, list]:
    if len(content) == 0:
        raise ParseError("Uploaded file is empty")
    if len(content) > max_bytes:
        raise AppError(f"File exceeds the {max_bytes // (1024 * 1024)} MB upload limit", 413, "file_too_large")
    text = decode_upload(content)
    fmt = detect_format(filename, text)
    records = parse_csv(text, max_records) if fmt == "csv" else parse_json(text, max_records)
    return fmt, records
