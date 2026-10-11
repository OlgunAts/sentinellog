"""Shared parser validation helpers."""

from __future__ import annotations

import hashlib
import ipaddress
from datetime import UTC, datetime


def parse_timestamp(value: object, *, default_year: int | None = None) -> datetime:
    text = str(value).strip()
    if not text:
        raise ValueError("timestamp is empty")

    if len(text) >= 15 and text[3] == " " and ":" in text:
        year = default_year or datetime.now(UTC).year
        parsed = datetime.strptime(f"{year} {text[:15]}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=UTC)

    normalized = text.replace("Z", "+00:00")
    formats = ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        for fmt in formats:
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise ValueError(f"unsupported timestamp: {text!r}") from None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def normalize_ip(value: object) -> str | None:
    text = str(value or "").strip()
    if not text or text in {"-", "::1", "127.0.0.1"}:
        return None if text == "-" or not text else text
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def stable_event_id(*parts: object) -> str:
    payload = "|".join(str(part) for part in parts).encode("utf-8", errors="replace")
    return "evt-" + hashlib.sha256(payload).hexdigest()[:16]
