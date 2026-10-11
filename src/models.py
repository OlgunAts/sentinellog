"""Core normalized data models used throughout SentinelLog."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source_ip: str | None
    username: str
    event_type: str
    status: str
    message: str
    source: str
    raw_ref: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class SecurityAlert:
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    description: str
    source_ip: str | None
    username: str
    detection_timestamp: datetime
    first_event: datetime
    last_event: datetime
    event_count: int
    supporting_event_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["supporting_event_ids"] = list(self.supporting_event_ids)
        return value


@dataclass(slots=True)
class ParseResult:
    events: list[SecurityEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    skipped: int = 0
