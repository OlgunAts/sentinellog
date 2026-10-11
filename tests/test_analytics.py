from src.analytics import alerts_frame, events_frame, ip_summary, overview_metrics
from src.detection import detect_alerts


def test_overview_metrics(event_factory):
    events = [event_factory(1), event_factory(2, status="success")]
    metrics = overview_metrics(events, [])
    assert metrics["total_events"] == 2
    assert metrics["failed_logins"] == 1
    assert metrics["successful_logins"] == 1
    assert metrics["unique_ips"] == 1


def test_ip_risk_score_is_bounded_and_explained_by_inputs(event_factory):
    events = [event_factory(i, minutes=i * .5) for i in range(8)]
    alerts = detect_alerts(events)
    summary = ip_summary(events, alerts)
    assert len(summary) == 1
    assert 0 <= summary.iloc[0]["risk_score"] <= 100
    assert summary.iloc[0]["failed_logins"] == 8


def test_empty_dataframes_have_stable_schema():
    assert events_frame([]).empty
    assert alerts_frame([]).empty
    assert ip_summary([], []).empty
    assert "timestamp" in events_frame([]).columns
    assert "severity" in alerts_frame([]).columns
