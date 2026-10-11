"""Transparent, deterministic security detection rules."""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Callable, Iterable

from src.models import SecurityAlert, SecurityEvent


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    brute_force_threshold: int = 5
    username_threshold: int = 3
    account_failure_threshold: int = 5
    success_after_failure_threshold: int = 3
    window_minutes: int = 5


def _alert_id(rule_id: str, events: list[SecurityEvent], key: str) -> str:
    raw = f"{rule_id}|{key}|{events[0].event_id}|{events[-1].event_id}"
    return "alt-" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def _clusters(events: Iterable[SecurityEvent], window: timedelta) -> list[list[SecurityEvent]]:
    ordered = sorted(events, key=lambda event: event.timestamp)
    clusters: list[list[SecurityEvent]] = []
    current: list[SecurityEvent] = []
    for event in ordered:
        if current and event.timestamp - current[-1].timestamp > window:
            clusters.append(current)
            current = []
        current.append(event)
    if current:
        clusters.append(current)
    return clusters


def _has_window(events: list[SecurityEvent], window: timedelta, predicate: Callable[[list[SecurityEvent]], bool]) -> bool:
    active: deque[SecurityEvent] = deque()
    for event in events:
        active.append(event)
        while active and event.timestamp - active[0].timestamp > window:
            active.popleft()
        if predicate(list(active)):
            return True
    return False


def _make_alert(
    rule_id: str,
    rule_name: str,
    severity: str,
    description: str,
    events: list[SecurityEvent],
    *,
    key: str,
    source_ip: str | None = None,
    username: str = "",
) -> SecurityAlert:
    ordered = sorted(events, key=lambda event: event.timestamp)
    return SecurityAlert(
        alert_id=_alert_id(rule_id, ordered, key),
        rule_id=rule_id,
        rule_name=rule_name,
        severity=severity,
        description=description,
        source_ip=source_ip,
        username=username,
        detection_timestamp=ordered[-1].timestamp,
        first_event=ordered[0].timestamp,
        last_event=ordered[-1].timestamp,
        event_count=len(ordered),
        supporting_event_ids=tuple(event.event_id for event in ordered),
    )


def detect_alerts(events: Iterable[SecurityEvent], config: DetectionConfig | None = None) -> list[SecurityAlert]:
    cfg = config or DetectionConfig()
    window = timedelta(minutes=max(1, cfg.window_minutes))
    ordered = sorted(events, key=lambda event: event.timestamp)
    failures = [event for event in ordered if event.status == "failure"]
    alerts: list[SecurityAlert] = []

    by_ip: dict[str, list[SecurityEvent]] = defaultdict(list)
    by_user: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in failures:
        if event.source_ip:
            by_ip[event.source_ip].append(event)
        if event.username and event.username != "unknown":
            by_user[event.username].append(event)

    for source_ip, grouped in by_ip.items():
        for cluster in _clusters(grouped, window):
            if _has_window(cluster, window, lambda active: len(active) >= cfg.brute_force_threshold):
                alerts.append(_make_alert(
                    "SL-BF-001", "Brute-force pattern", "HIGH",
                    f"At least {cfg.brute_force_threshold} failed logins occurred within {cfg.window_minutes} minutes. Related failures are grouped until the activity pauses longer than the configured window.",
                    cluster, key=source_ip, source_ip=source_ip,
                ))
            if _has_window(cluster, window, lambda active: len({e.username for e in active}) >= cfg.username_threshold):
                alerts.append(_make_alert(
                    "SL-MU-002", "Multiple username failures", "MEDIUM",
                    f"This source attempted at least {cfg.username_threshold} distinct usernames within {cfg.window_minutes} minutes.",
                    cluster, key=source_ip, source_ip=source_ip,
                ))

    for username, grouped in by_user.items():
        for cluster in _clusters(grouped, window):
            if _has_window(cluster, window, lambda active: len(active) >= cfg.account_failure_threshold):
                source_ips = {event.source_ip for event in cluster if event.source_ip}
                alerts.append(_make_alert(
                    "SL-RA-003", "Repeated account failures", "MEDIUM",
                    f"Account received at least {cfg.account_failure_threshold} failed authentication attempts within {cfg.window_minutes} minutes.",
                    cluster, key=username, source_ip=next(iter(source_ips)) if len(source_ips) == 1 else None, username=username,
                ))

    failures_by_pair: dict[tuple[str, str], list[SecurityEvent]] = defaultdict(list)
    emitted_failure_sets: set[tuple[str, str, tuple[str, ...]]] = set()
    for event in ordered:
        if not event.source_ip or not event.username:
            continue
        key = (event.source_ip, event.username)
        if event.status == "failure":
            failures_by_pair[key].append(event)
            continue
        if event.status != "success":
            continue
        recent = [failure for failure in failures_by_pair[key] if timedelta(0) <= event.timestamp - failure.timestamp <= window]
        if len(recent) >= cfg.success_after_failure_threshold:
            signature = (key[0], key[1], tuple(item.event_id for item in recent))
            if signature not in emitted_failure_sets:
                emitted_failure_sets.add(signature)
                support = recent + [event]
                alerts.append(_make_alert(
                    "SL-SF-004", "Successful login after failures", "HIGH",
                    f"A successful login followed at least {cfg.success_after_failure_threshold} recent failures. This is potentially suspicious, not proof of compromise.",
                    support, key=f"{key[0]}:{key[1]}", source_ip=key[0], username=key[1],
                ))

    for event in ordered:
        if event.event_type == "account_lockout" or event.status == "lockout":
            alerts.append(_make_alert(
                "SL-AL-005", "Windows account lockout", "CRITICAL",
                "A supported Windows Security Event 4740 account lockout was observed.",
                [event], key=event.event_id, source_ip=event.source_ip, username=event.username,
            ))

    unique = {alert.alert_id: alert for alert in alerts}
    return sorted(unique.values(), key=lambda alert: alert.detection_timestamp, reverse=True)
