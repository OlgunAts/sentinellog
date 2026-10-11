"""Parser for common OpenSSH auth.log records."""

from __future__ import annotations

import re
from datetime import UTC, datetime

from src.models import ParseResult, SecurityEvent
from src.parsers.common import normalize_ip, parse_timestamp, stable_event_id

SSH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+"
    r"(?P<action>Accepted|Failed)\s+(?P<method>\S+)\s+for\s+"
    r"(?:(?P<invalid>invalid user)\s+)?(?P<username>\S+)\s+from\s+"
    r"(?P<ip>[0-9a-fA-F:.]+)(?:\s+port\s+\d+)?",
)


def parse_linux_auth(text: str, *, reference_year: int | None = None) -> ParseResult:
    result = ParseResult()
    year = reference_year or datetime.now(UTC).year
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line:
            continue
        match = SSH_PATTERN.search(line)
        if not match:
            result.skipped += 1
            continue
        try:
            timestamp = parse_timestamp(match.group("timestamp"), default_year=year)
            source_ip = normalize_ip(match.group("ip"))
            if source_ip is None:
                raise ValueError("invalid source IP")
            status = "success" if match.group("action") == "Accepted" else "failure"
            event_type = "invalid_username" if match.group("invalid") else "ssh_authentication"
            event_id = stable_event_id("linux", line_number, line)
            result.events.append(
                SecurityEvent(
                    event_id=event_id,
                    timestamp=timestamp,
                    source_ip=source_ip,
                    username=match.group("username")[:128],
                    event_type=event_type,
                    status=status,
                    message=line[:1000],
                    source="linux_auth",
                    raw_ref=f"line:{line_number}",
                )
            )
        except ValueError as exc:
            result.errors.append(f"Line {line_number}: {exc}")
    return result
