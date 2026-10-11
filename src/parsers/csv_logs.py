"""Parsers for normalized CSV and Windows Security Event CSV exports."""

from __future__ import annotations

import csv
import io

from src.models import ParseResult, SecurityEvent
from src.parsers.common import normalize_ip, parse_timestamp, stable_event_id

WINDOWS_EVENT_MAP = {
    "4624": ("windows_logon", "success"),
    "4625": ("windows_logon", "failure"),
    "4740": ("account_lockout", "lockout"),
}


def _value(row: dict[str, str], *aliases: str) -> str:
    lowered = {str(key).strip().lower(): value for key, value in row.items() if key is not None}
    for alias in aliases:
        if alias.lower() in lowered:
            return str(lowered[alias.lower()] or "").strip()
    return ""


def parse_csv_content(text: str) -> ParseResult:
    result = ParseResult()
    try:
        reader = csv.DictReader(io.StringIO(text.lstrip("\ufeff")))
        if not reader.fieldnames:
            result.errors.append("CSV header row is missing.")
            return result
        field_names = {name.strip().lower() for name in reader.fieldnames if name}
        is_windows = bool(field_names & {"event id", "eventid", "id"})
        if not is_windows and "timestamp" not in field_names:
            result.errors.append("Required column 'timestamp' is missing.")
            return result

        for row_number, row in enumerate(reader, start=2):
            try:
                if is_windows:
                    event_code = _value(row, "Event ID", "EventID", "Id")
                    if event_code not in WINDOWS_EVENT_MAP:
                        result.skipped += 1
                        continue
                    event_type, status = WINDOWS_EVENT_MAP[event_code]
                    timestamp_text = _value(row, "TimeCreated", "Date and Time", "timestamp")
                    source_ip = normalize_ip(_value(row, "IpAddress", "Source Network Address", "source_ip"))
                    username = _value(row, "TargetUserName", "Account Name", "username") or "unknown"
                    message = _value(row, "Message") or f"Windows Security Event {event_code}"
                    source = "windows_security_csv"
                else:
                    timestamp_text = _value(row, "timestamp")
                    source_ip = normalize_ip(_value(row, "source_ip"))
                    username = _value(row, "username") or "unknown"
                    event_type = _value(row, "event_type") or "generic_event"
                    status = _value(row, "status").lower() or "unknown"
                    message = _value(row, "message") or event_type
                    source = "normalized_csv"
                timestamp = parse_timestamp(timestamp_text)
                event_id = stable_event_id(source, row_number, timestamp_text, source_ip, username, message)
                result.events.append(
                    SecurityEvent(
                        event_id=event_id,
                        timestamp=timestamp,
                        source_ip=source_ip,
                        username=username[:128],
                        event_type=event_type[:128],
                        status=status[:32],
                        message=message[:1000],
                        source=source,
                        raw_ref=f"row:{row_number}",
                    )
                )
            except (ValueError, TypeError) as exc:
                result.errors.append(f"Row {row_number}: {exc}")
    except csv.Error as exc:
        result.errors.append(f"Malformed CSV: {exc}")
    return result
