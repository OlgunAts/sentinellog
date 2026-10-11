from datetime import UTC

from src.parsers import parse_csv_content, parse_linux_auth
from src.parsers.common import normalize_ip, parse_timestamp
from src.utils.uploads import MAX_UPLOAD_BYTES, decode_upload


def test_successful_linux_ssh_parse():
    line = "Jan 10 10:15:01 host sshd[123]: Accepted publickey for alice from 192.0.2.4 port 22 ssh2"
    result = parse_linux_auth(line, reference_year=2026)
    assert not result.errors
    assert len(result.events) == 1
    assert result.events[0].status == "success"
    assert result.events[0].timestamp.year == 2026
    assert result.events[0].timestamp.tzinfo == UTC


def test_failed_invalid_user_linux_parse():
    line = "Feb  2 08:01:02 host sshd[99]: Failed password for invalid user root from 203.0.113.9 port 5500 ssh2"
    event = parse_linux_auth(line, reference_year=2025).events[0]
    assert event.status == "failure"
    assert event.event_type == "invalid_username"
    assert event.username == "root"


def test_linux_unsupported_line_is_skipped():
    result = parse_linux_auth("kernel: unrelated message", reference_year=2026)
    assert result.events == []
    assert result.skipped == 1


def test_windows_csv_parse_supported_ids():
    csv_text = "Event ID,TimeCreated,IpAddress,TargetUserName,Message\n4624,2026-01-01T10:00:00Z,192.0.2.4,alice,OK\n4625,2026-01-01T10:01:00Z,192.0.2.5,bob,Fail\n4740,2026-01-01T10:02:00Z,192.0.2.5,bob,Locked\n"
    result = parse_csv_content(csv_text)
    assert [event.status for event in result.events] == ["success", "failure", "lockout"]
    assert result.events[-1].event_type == "account_lockout"


def test_windows_csv_skips_unprioritized_event():
    result = parse_csv_content("EventID,TimeCreated\n4634,2026-01-01T10:00:00Z\n")
    assert result.events == []
    assert result.skipped == 1


def test_normalized_csv_and_invalid_ip():
    text = "timestamp,source_ip,username,event_type,status,message\n2026-01-01 10:00:00,not-an-ip,alice,login,failure,test\n"
    event = parse_csv_content(text).events[0]
    assert event.source_ip is None
    assert event.status == "failure"


def test_missing_timestamp_column():
    result = parse_csv_content("source_ip,username\n192.0.2.2,alice\n")
    assert not result.events
    assert "timestamp" in result.errors[0]


def test_malformed_timestamp_isolated():
    text = "timestamp,source_ip,username,event_type,status,message\nnot-a-date,192.0.2.1,alice,login,failure,x\n2026-01-01T10:00:00Z,192.0.2.2,bob,login,success,y\n"
    result = parse_csv_content(text)
    assert len(result.events) == 1
    assert len(result.errors) == 1


def test_timestamp_and_ip_validation():
    assert parse_timestamp("2026-01-01T00:00:00Z").tzinfo == UTC
    assert normalize_ip("999.1.1.1") is None


def test_upload_decoder_limits_and_binary():
    assert decode_upload("hello".encode()) == "hello"
    try:
        decode_upload(b"\x00binary")
    except ValueError as exc:
        assert "Binary" in str(exc)
    else:
        raise AssertionError("binary upload was accepted")
    try:
        decode_upload(b"a" * (MAX_UPLOAD_BYTES + 1))
    except ValueError as exc:
        assert "10 MB" in str(exc)
    else:
        raise AssertionError("oversized upload was accepted")
