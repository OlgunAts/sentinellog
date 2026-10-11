"""Deterministic fictional data for immediate, safe product evaluation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from src.models import SecurityEvent
from src.parsers.common import stable_event_id


def demo_events() -> list[SecurityEvent]:
    base = datetime(2026, 1, 15, 8, 0, tzinfo=UTC)
    rows: list[tuple[int, str | None, str, str, str, str]] = []
    for minute, ip, user in [(0, "192.0.2.10", "analyst"), (12, "192.0.2.11", "operator"), (30, "198.51.100.22", "analyst"), (65, "192.0.2.10", "analyst"), (90, "203.0.113.40", "auditor")]:
        rows.append((minute, ip, user, "ssh_authentication", "success", "Accepted publickey for fictional demo user"))
    for offset, user in enumerate(["root", "admin", "guest", "service", "oracle", "backup"]):
        rows.append((120 + offset, "203.0.113.77", user, "invalid_username", "failure", "Failed password for invalid fictional user"))
    for offset in range(5):
        rows.append((180 + offset, "198.51.100.55", "analyst", "ssh_authentication", "failure", "Failed password for fictional demo user"))
    rows.append((185, "198.51.100.55", "analyst", "ssh_authentication", "success", "Accepted password after repeated fictional failures"))
    for offset in range(5):
        rows.append((240 + offset, "192.0.2.88", "locked.user", "windows_logon", "failure", "Windows demo Event 4625"))
    rows.append((245, "192.0.2.88", "locked.user", "account_lockout", "lockout", "Windows demo Event 4740 account lockout"))

    events = []
    for index, (minute, ip, username, event_type, status, message) in enumerate(rows):
        timestamp = base + timedelta(minutes=minute)
        events.append(SecurityEvent(
            event_id=stable_event_id("demo", index), timestamp=timestamp, source_ip=ip,
            username=username, event_type=event_type, status=status, message=message,
            source="demo", raw_ref=f"demo:{index + 1}",
        ))
    return sorted(events, key=lambda event: event.timestamp)
