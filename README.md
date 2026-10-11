# SentinelLog – Security Log Analyzer

SentinelLog is a defensive, local-first security monitoring dashboard for learning, triage, and analysis of authentication logs. It normalizes supported Linux and Windows records, applies transparent detection rules, and presents analyst-friendly dashboards without sending log data to external services.

> SentinelLog is an educational analysis aid. Its alerts and risk scores are not proof of compromise and are not scientifically validated probabilities.

## Features

- Professional dark SOC-style Streamlit interface with responsive metrics and interactive Plotly charts
- Linux OpenSSH `auth.log`, Windows Security Event CSV, and normalized CSV parsing
- Configurable sliding-window detection for brute force, username spraying, repeated account failures, post-failure success, and account lockout
- Alert search, filters, supporting-event inspection, and CSV/JSON export
- Per-IP timelines and transparent 0–100 triage scores
- Deterministic fictional demo mode using RFC 5737 documentation IP ranges
- In-memory uploads with a 10 MB limit, bounded fields, safe decoding, and malformed-record isolation
- No external APIs, telemetry, active scanning, firewall changes, or privileged Event Log access

## Technology stack

- Python 3.11+
- Streamlit
- Pandas
- Plotly
- Pytest
- Python standard library parsing, IP validation, timestamps, hashing, and CSV handling

## Installation on Windows 11

```powershell
cd C:\Users\ateso\Projects\sentinellog
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Run the application

```powershell
streamlit run app.py
```

Open <http://localhost:8501>. If port 8501 is occupied, Streamlit selects another available port and prints its URL in the terminal.

The app starts with clearly marked **DEMO DATA**. Use **Log Upload** to analyze a local export, or **Reset to demo data** to restore the fictional sample.

## Supported log formats

### Linux OpenSSH

TXT files containing common `sshd` records such as:

```text
Jan 15 10:05:01 host sshd[1002]: Failed password for invalid user admin from 203.0.113.77 port 51101 ssh2
Jan 15 10:10:01 host sshd[1003]: Accepted publickey for analyst from 192.0.2.10 port 51102 ssh2
```

The current parser supports `Accepted` and `Failed` authentication records, including `invalid user` entries. Syslog records without a year use the current year.

### Windows Security Event CSV

Export Windows Security events manually to CSV. SentinelLog never accesses privileged Event Logs. Supported IDs:

| Event ID | Meaning |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4740 | Account lockout |

Recognized column aliases:

- Event ID: `Event ID`, `EventID`, or `Id`
- Timestamp: `TimeCreated`, `Date and Time`, or `timestamp`
- Source IP: `IpAddress`, `Source Network Address`, or `source_ip`
- Account: `TargetUserName`, `Account Name`, or `username`
- Optional text: `Message`

### Normalized CSV

```text
timestamp,source_ip,username,event_type,status,message
2026-01-15T08:00:00Z,192.0.2.10,analyst,ssh_authentication,success,Accepted publickey
```

`timestamp` is required. Missing or invalid IPs remain unassigned instead of crashing analysis. Malformed rows are isolated and reported.

## Detection rules

| Rule ID | Rule | Default severity | Logic |
|---|---|---|---|
| SL-BF-001 | Brute-force pattern | HIGH | At least 5 failures from one IP inside 5 minutes |
| SL-MU-002 | Multiple username failures | MEDIUM | One IP targets at least 3 usernames inside 5 minutes |
| SL-RA-003 | Repeated account failures | MEDIUM | At least 5 failures for one username inside 5 minutes |
| SL-SF-004 | Successful login after failures | HIGH | A success follows at least 3 failures from the same IP and username inside 5 minutes |
| SL-AL-005 | Account lockout | CRITICAL | Windows Security Event 4740 is observed |

Thresholds and the time window are configurable in the sidebar. Events are sorted before evaluation. Failed events are grouped into activity clusters; a cluster ends when the gap between consecutive related failures exceeds the configured window. A sliding window must still meet the threshold. SentinelLog emits one alert per rule and cluster, preventing duplicate alerts from overlapping windows.

## Risk scoring

Per-IP risk is a bounded triage score:

- 4 points per failed event, up to 40
- 1 point per successful event, up to 10
- Alert points: LOW 10, MEDIUM 20, HIGH 30, CRITICAL 45
- Final result capped at 100

This intentionally simple score is explainable; it is not a probability or formal risk model.

## Testing

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Tests cover Linux and Windows parsing, malformed inputs, all detection rules, sliding-window boundaries, duplicate suppression, empty datasets, analytics, and upload safety.

## Screenshots

No screenshot is committed by default. Add verified captures here only after reviewing the running dashboard; never substitute mock images for the real interface.

## Limitations

- Initial parsers intentionally cover common OpenSSH layouts and selected Windows CSV column aliases, not every vendor variant.
- Syslog timestamps without a year use the current year and do not infer year rollover.
- Data is held in the Streamlit session; there is no persistence or cross-user storage.
- Large-but-valid 10 MB files may still require meaningful memory after normalization.
- No enrichment, geolocation, threat intelligence, external IP lookup, or active response is performed.

## Security notes

Treat logs as sensitive and untrusted. SentinelLog does not execute uploaded content, invoke shell commands from it, upload it externally, or permanently store it. Avoid sharing exports containing credentials or private data. Review detections with appropriate organizational context before taking action.

## Future improvements

- Additional Linux distributions and structured JSON log formats
- EVTX parsing via an optional offline dependency
- Saved local investigations with explicit encryption and retention controls
- Rule-level unit explanations and MITRE ATT&CK mapping
- Optional offline threat-intelligence imports controlled by the analyst
