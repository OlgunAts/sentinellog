from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from src.models import SecurityEvent


@pytest.fixture
def event_factory():
    base = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)

    def factory(index: int, *, minutes: float = 0, ip: str | None = "203.0.113.10", username: str = "analyst", status: str = "failure", event_type: str = "ssh_authentication") -> SecurityEvent:
        return SecurityEvent(
            event_id=f"evt-{index}", timestamp=base + timedelta(minutes=minutes), source_ip=ip,
            username=username, event_type=event_type, status=status,
            message=f"deterministic test event {index}", source="test", raw_ref=f"fixture:{index}",
        )

    return factory
