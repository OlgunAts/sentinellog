from src.detection import DetectionConfig, detect_alerts


def rule_ids(alerts):
    return [alert.rule_id for alert in alerts]


def test_brute_force_threshold(event_factory):
    events = [event_factory(i, minutes=i * .5) for i in range(5)]
    alerts = detect_alerts(events)
    brute = next(alert for alert in alerts if alert.rule_id == "SL-BF-001")
    assert brute.event_count == 5
    assert brute.severity == "HIGH"


def test_events_outside_window_do_not_trigger(event_factory):
    events = [event_factory(i, minutes=i * 6) for i in range(5)]
    assert "SL-BF-001" not in rule_ids(detect_alerts(events))


def test_multiple_username_detection(event_factory):
    events = [event_factory(i, minutes=i, username=name) for i, name in enumerate(["alice", "bob", "carol"])]
    assert "SL-MU-002" in rule_ids(detect_alerts(events))


def test_repeated_account_failures(event_factory):
    events = [event_factory(i, minutes=i * .5, ip=f"192.0.2.{i + 1}", username="alice") for i in range(5)]
    assert "SL-RA-003" in rule_ids(detect_alerts(events))


def test_success_after_repeated_failures(event_factory):
    events = [event_factory(i, minutes=i, username="alice") for i in range(3)]
    events.append(event_factory(4, minutes=4, username="alice", status="success"))
    alert = next(alert for alert in detect_alerts(events) if alert.rule_id == "SL-SF-004")
    assert "not proof of compromise" in alert.description
    assert alert.event_count == 4


def test_success_after_old_failures_not_detected(event_factory):
    events = [event_factory(i, minutes=i) for i in range(3)]
    events.append(event_factory(4, minutes=20, status="success"))
    assert "SL-SF-004" not in rule_ids(detect_alerts(events))


def test_account_lockout_detection(event_factory):
    event = event_factory(1, status="lockout", event_type="account_lockout", username="alice")
    alert = next(alert for alert in detect_alerts([event]) if alert.rule_id == "SL-AL-005")
    assert alert.severity == "CRITICAL"


def test_duplicate_overlapping_windows_produce_one_alert(event_factory):
    events = [event_factory(i, minutes=i * .5) for i in range(8)]
    brute_alerts = [alert for alert in detect_alerts(events) if alert.rule_id == "SL-BF-001"]
    assert len(brute_alerts) == 1
    assert brute_alerts[0].event_count == 8


def test_custom_threshold(event_factory):
    events = [event_factory(i, minutes=i) for i in range(3)]
    config = DetectionConfig(brute_force_threshold=3)
    assert "SL-BF-001" in rule_ids(detect_alerts(events, config))


def test_empty_events():
    assert detect_alerts([]) == []
