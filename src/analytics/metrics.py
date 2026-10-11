"""Data-frame based analytics for dashboard presentation."""

from __future__ import annotations

import pandas as pd

from src.models import SecurityAlert, SecurityEvent

SEVERITY_POINTS = {"LOW": 10, "MEDIUM": 20, "HIGH": 30, "CRITICAL": 45}


def events_frame(events: list[SecurityEvent]) -> pd.DataFrame:
    columns = ["event_id", "timestamp", "source_ip", "username", "event_type", "status", "message", "source", "raw_ref"]
    if not events:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame([event.to_dict() for event in events])
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    return frame.sort_values("timestamp")


def alerts_frame(alerts: list[SecurityAlert]) -> pd.DataFrame:
    columns = ["alert_id", "detection_timestamp", "severity", "rule_id", "rule_name", "source_ip", "username", "event_count", "description", "supporting_event_ids"]
    if not alerts:
        return pd.DataFrame(columns=columns)
    frame = pd.DataFrame([alert.to_dict() for alert in alerts])
    frame["detection_timestamp"] = pd.to_datetime(frame["detection_timestamp"], utc=True)
    return frame.sort_values("detection_timestamp", ascending=False)


def overview_metrics(events: list[SecurityEvent], alerts: list[SecurityAlert]) -> dict[str, int]:
    return {
        "total_events": len(events),
        "failed_logins": sum(event.status == "failure" for event in events),
        "successful_logins": sum(event.status == "success" for event in events),
        "unique_ips": len({event.source_ip for event in events if event.source_ip}),
        "suspicious_ips": len({alert.source_ip for alert in alerts if alert.source_ip}),
        "high_risk": sum(alert.severity in {"HIGH", "CRITICAL"} for alert in alerts),
        "critical_alerts": sum(alert.severity == "CRITICAL" for alert in alerts),
    }


def ip_summary(events: list[SecurityEvent], alerts: list[SecurityAlert]) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    valid_ips = sorted({event.source_ip for event in events if event.source_ip})
    for source_ip in valid_ips:
        ip_events = [event for event in events if event.source_ip == source_ip]
        ip_alerts = [alert for alert in alerts if alert.source_ip == source_ip]
        failures = sum(event.status == "failure" for event in ip_events)
        successes = sum(event.status == "success" for event in ip_events)
        score = min(100, min(40, failures * 4) + min(10, successes) + sum(SEVERITY_POINTS.get(alert.severity, 0) for alert in ip_alerts))
        rows.append({
            "source_ip": source_ip,
            "total_events": len(ip_events),
            "failed_logins": failures,
            "successful_logins": successes,
            "usernames": ", ".join(sorted({event.username for event in ip_events if event.username})),
            "triggered_alerts": len(ip_alerts),
            "risk_score": score,
        })
    return pd.DataFrame(rows)
