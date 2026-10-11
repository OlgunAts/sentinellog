"""SentinelLog Streamlit dashboard."""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from src.analytics import alerts_frame, events_frame, ip_summary, overview_metrics
from src.demo import demo_events
from src.detection import DetectionConfig, detect_alerts
from src.parsers import parse_csv_content, parse_linux_auth
from src.utils import decode_upload

st.set_page_config(page_title="SentinelLog", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

COLORS = {"LOW": "#38bdf8", "MEDIUM": "#facc15", "HIGH": "#fb923c", "CRITICAL": "#fb4d68"}
PLOT_COLORS = ["#22d3ee", "#3b82f6", "#8b5cf6", "#fb923c", "#fb4d68"]

st.markdown("""
<style>
  .stApp { background: radial-gradient(circle at 82% 3%, #102d46 0, #07111f 32%, #07111f 100%); }
  [data-testid="stSidebar"] { background: #0a1625; border-right: 1px solid #1f3449; }
  [data-testid="stMetric"] { background: linear-gradient(145deg, #101f31, #0c1929); border: 1px solid #1b3850; padding: 18px; border-radius: 14px; }
  [data-testid="stMetricLabel"] { color: #88a7bf; }
  [data-testid="stMetricValue"] { color: #eefaff; font-family: ui-monospace, SFMono-Regular, Consolas, monospace; }
  .sentinel-brand { padding: 4px 0 22px; }
  .sentinel-brand h1 { margin: 0; color: #e9fbff; font-size: 1.55rem; letter-spacing: -.04em; }
  .sentinel-brand h1 span { color: #22d3ee; }
  .sentinel-brand p { margin: 5px 0 0; color: #6f91aa; font-size: .72rem; letter-spacing: .08em; text-transform: uppercase; }
  .demo-badge { display:inline-flex; align-items:center; gap:7px; padding:6px 10px; border:1px solid #155e75; border-radius:999px; background:#083344; color:#67e8f9; font:700 .72rem ui-monospace,monospace; }
  .demo-dot { width:7px; height:7px; border-radius:50%; background:#22d3ee; box-shadow:0 0 10px #22d3ee; }
  .page-title { margin-bottom: 1.5rem; }
  .page-title h1 { margin: 0; color:#effbff; font-size:2.25rem; letter-spacing:-.045em; }
  .page-title p { margin:.35rem 0 0; color:#7998af; }
  .info-panel { padding:18px 20px; border:1px solid #1c3a50; border-radius:14px; background:#0d1b2b; color:#a8bfd0; }
  .rule-id { color:#22d3ee; font-family:ui-monospace,monospace; }
  div[data-testid="stDataFrame"] { border:1px solid #18344a; border-radius:12px; overflow:hidden; }
  .stDownloadButton button, .stButton button { border-radius:10px; border-color:#1f6078; }
</style>
""", unsafe_allow_html=True)


def title(name: str, subtitle: str) -> None:
    st.markdown(f'<div class="page-title"><h1>{name}</h1><p>{subtitle}</p></div>', unsafe_allow_html=True)


def chart_layout(fig: go.Figure, height: int = 340) -> go.Figure:
    fig.update_layout(
        height=height, margin=dict(l=10, r=10, t=42, b=10), paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(10,22,37,.65)", font=dict(color="#9db5c8"),
        title_font=dict(color="#e7f7ff", size=15), legend_title_text="",
    )
    fig.update_xaxes(gridcolor="#193148", zerolinecolor="#193148")
    fig.update_yaxes(gridcolor="#193148", zerolinecolor="#193148")
    return fig


if "events" not in st.session_state:
    st.session_state.events = demo_events()
    st.session_state.data_mode = "DEMO DATA"
    st.session_state.parse_messages = []

with st.sidebar:
    st.markdown('<div class="sentinel-brand"><h1>Sentinel<span>Log</span></h1><p>Security Event Monitoring</p></div>', unsafe_allow_html=True)
    page = st.radio("Navigation", ["Dashboard", "Security Alerts", "IP Analysis", "Log Upload", "Detection Rules"], label_visibility="collapsed")
    st.divider()
    st.caption("DETECTION SETTINGS")
    brute_threshold = st.number_input("Brute-force threshold", 3, 50, 5)
    user_threshold = st.number_input("Distinct usernames", 2, 25, 3)
    account_threshold = st.number_input("Account failure threshold", 3, 50, 5)
    success_threshold = st.number_input("Failures before success", 2, 25, 3)
    window_minutes = st.number_input("Time window (minutes)", 1, 60, 5)
    st.divider()
    if st.session_state.data_mode == "DEMO DATA":
        st.markdown('<span class="demo-badge"><span class="demo-dot"></span>DEMO DATA</span>', unsafe_allow_html=True)
    else:
        st.success("Uploaded data active", icon="✓")
    if st.button("Reset to demo data", width="stretch"):
        st.session_state.events = demo_events()
        st.session_state.data_mode = "DEMO DATA"
        st.session_state.parse_messages = []
        st.rerun()

config = DetectionConfig(
    brute_force_threshold=int(brute_threshold), username_threshold=int(user_threshold),
    account_failure_threshold=int(account_threshold), success_after_failure_threshold=int(success_threshold),
    window_minutes=int(window_minutes),
)
events = st.session_state.events
alerts = detect_alerts(events, config)
event_df = events_frame(events)
alert_df = alerts_frame(alerts)

if page == "Dashboard":
    title("Security Overview", "Security Event Monitoring & Log Analysis")
    if st.session_state.data_mode == "DEMO DATA":
        st.info("You are viewing deterministic fictional demo data. No real security incidents are represented.", icon="🧪")
    metrics = overview_metrics(events, alerts)
    first = st.columns(4)
    first[0].metric("Total security events", metrics["total_events"])
    first[1].metric("Failed login attempts", metrics["failed_logins"])
    first[2].metric("Successful logins", metrics["successful_logins"])
    first[3].metric("Unique source IPs", metrics["unique_ips"])
    second = st.columns(3)
    second[0].metric("Suspicious IPs", metrics["suspicious_ips"])
    second[1].metric("High-risk events", metrics["high_risk"])
    second[2].metric("Critical alerts", metrics["critical_alerts"])

    if event_df.empty:
        st.info("No events are available. Upload a supported file or restore demo data.")
    else:
        left, right = st.columns([1.6, 1])
        with left:
            timeline = event_df.set_index("timestamp").resample("15min").size().rename("events").reset_index()
            fig = px.area(timeline, x="timestamp", y="events", title="Security events over time", color_discrete_sequence=["#22d3ee"])
            st.plotly_chart(chart_layout(fig), width="stretch")
        with right:
            auth = event_df[event_df["status"].isin(["success", "failure"])]["status"].value_counts().reset_index()
            fig = px.pie(auth, names="status", values="count", hole=.62, title="Authentication outcomes", color="status", color_discrete_map={"success": "#22d3ee", "failure": "#fb4d68"})
            st.plotly_chart(chart_layout(fig), width="stretch")
        left, right = st.columns(2)
        with left:
            top_ips = event_df.dropna(subset=["source_ip"])["source_ip"].value_counts().head(8).sort_values().reset_index()
            fig = px.bar(top_ips, x="count", y="source_ip", orientation="h", title="Top source IP addresses", color_discrete_sequence=["#3b82f6"])
            st.plotly_chart(chart_layout(fig), width="stretch")
        with right:
            if alert_df.empty:
                st.markdown('<div class="info-panel"><strong>No alert severity data</strong><br>Current events did not trigger configured rules.</div>', unsafe_allow_html=True)
            else:
                severity = alert_df["severity"].value_counts().rename_axis("severity").reset_index(name="count")
                fig = px.bar(severity, x="severity", y="count", title="Security alert severity distribution", color="severity", color_discrete_map=COLORS)
                st.plotly_chart(chart_layout(fig), width="stretch")
        if not alert_df.empty:
            fig = px.scatter(alert_df, x="detection_timestamp", y="source_ip", size="event_count", color="severity", hover_data=["rule_name", "rule_id"], title="Suspicious activity timeline", color_discrete_map=COLORS)
            st.plotly_chart(chart_layout(fig), width="stretch")

elif page == "Security Alerts":
    title("Security Alerts", "Investigate rule-based detections and their supporting events")
    if alert_df.empty:
        st.info("No security alerts match the current dataset and detection settings.", icon="✅")
    else:
        c1, c2, c3, c4 = st.columns(4)
        search = c1.text_input("Search alerts", placeholder="Rule, IP, user...")
        severity_filter = c2.multiselect("Severity", list(COLORS), default=list(COLORS))
        ip_options = sorted(alert_df["source_ip"].dropna().unique().tolist())
        ip_filter = c3.multiselect("Source IP", ip_options)
        rule_options = sorted(alert_df["rule_name"].unique().tolist())
        rule_filter = c4.multiselect("Detection rule", rule_options)
        filtered = alert_df[alert_df["severity"].isin(severity_filter)]
        if ip_filter:
            filtered = filtered[filtered["source_ip"].isin(ip_filter)]
        if rule_filter:
            filtered = filtered[filtered["rule_name"].isin(rule_filter)]
        if search:
            searchable = filtered.astype(str).agg(" ".join, axis=1)
            filtered = filtered[searchable.str.contains(search, case=False, regex=False)]
        sort_order = st.selectbox("Sort", ["Newest first", "Oldest first"])
        filtered = filtered.sort_values("detection_timestamp", ascending=sort_order == "Oldest first")
        display_columns = ["detection_timestamp", "severity", "rule_id", "rule_name", "source_ip", "username", "event_count", "description"]
        st.dataframe(filtered[display_columns], width="stretch", hide_index=True)
        export_json = json.dumps(filtered.to_dict(orient="records"), default=str, indent=2)
        d1, d2 = st.columns(2)
        d1.download_button("Export filtered alerts as CSV", filtered.to_csv(index=False).encode(), "sentinellog-alerts.csv", "text/csv", width="stretch")
        d2.download_button("Export filtered alerts as JSON", export_json, "sentinellog-alerts.json", "application/json", width="stretch")
        selected_id = st.selectbox("Inspect supporting events", filtered["alert_id"].tolist(), format_func=lambda item: f"{item} · {filtered.loc[filtered['alert_id'] == item, 'rule_name'].iloc[0]}") if not filtered.empty else None
        if selected_id:
            ids = set(filtered.loc[filtered["alert_id"] == selected_id, "supporting_event_ids"].iloc[0])
            support = event_df[event_df["event_id"].isin(ids)][["timestamp", "source_ip", "username", "event_type", "status", "message", "raw_ref"]]
            st.dataframe(support, width="stretch", hide_index=True)

elif page == "IP Analysis":
    title("IP Analysis", "Review source activity without external lookups or active scanning")
    summary = ip_summary(events, alerts)
    if summary.empty:
        st.info("No valid source IP addresses are available for analysis.")
    else:
        st.caption("Risk score = up to 40 points from failed attempts + up to 10 from successful activity + alert severity points (LOW 10, MEDIUM 20, HIGH 30, CRITICAL 45), capped at 100. It is a triage aid, not a probability.")
        st.dataframe(summary.sort_values("risk_score", ascending=False), width="stretch", hide_index=True)
        selected_ip = st.selectbox("Select a source IP", summary["source_ip"].tolist())
        row = summary[summary["source_ip"] == selected_ip].iloc[0]
        cols = st.columns(4)
        cols[0].metric("Risk score", f"{row['risk_score']}/100")
        cols[1].metric("Total events", row["total_events"])
        cols[2].metric("Failed", row["failed_logins"])
        cols[3].metric("Triggered alerts", row["triggered_alerts"])
        timeline = event_df[event_df["source_ip"] == selected_ip][["timestamp", "username", "event_type", "status", "message", "raw_ref"]]
        st.dataframe(timeline.sort_values("timestamp", ascending=False), width="stretch", hide_index=True)

elif page == "Log Upload":
    title("Log Upload", "Analyze local text exports safely in memory")
    st.markdown("""
<div class="info-panel"><strong>Supported formats</strong><br>
Linux OpenSSH <code>auth.log</code> lines in TXT files; Windows Security CSV exports containing Event ID, TimeCreated/Date and Time, IpAddress/Source Network Address, TargetUserName/Account Name and Message; or normalized CSV with <code>timestamp, source_ip, username, event_type, status, message</code>.<br><br>
Maximum size: 10 MB. Files are processed in memory and are not permanently stored.</div>
""", unsafe_allow_html=True)
    uploaded = st.file_uploader("Choose a CSV or TXT log file", type=["csv", "txt"], accept_multiple_files=False)
    if uploaded:
        if uploaded.size > 10 * 1024 * 1024:
            st.error("File exceeds the 10 MB upload limit.")
        elif st.button("Analyze uploaded log", type="primary"):
            try:
                text = decode_upload(uploaded.getvalue())
                result = parse_csv_content(text) if Path(uploaded.name).suffix.lower() == ".csv" else parse_linux_auth(text)
                if not result.events:
                    st.error("No supported security events were found. Review the format description and timestamps.")
                    for error in result.errors[:10]:
                        st.warning(error)
                else:
                    st.session_state.events = result.events
                    st.session_state.data_mode = "UPLOADED DATA"
                    st.session_state.parse_messages = result.errors
                    st.success(f"Loaded {len(result.events)} events. Skipped {result.skipped} unsupported lines; {len(result.errors)} malformed records were isolated.")
                    st.rerun()
            except ValueError as exc:
                st.error(str(exc))
    if st.session_state.parse_messages:
        with st.expander("Parser warnings"):
            for message in st.session_state.parse_messages[:100]:
                st.warning(message)

else:
    title("Detection Rules", "Human-readable logic for transparent security monitoring")
    rules = [
        ("SL-BF-001", "Brute-force pattern", "HIGH", "Failed attempts from one IP reach the configured threshold inside a sliding window."),
        ("SL-MU-002", "Multiple username failures", "MEDIUM", "One IP targets the configured number of distinct usernames inside the window."),
        ("SL-RA-003", "Repeated account failures", "MEDIUM", "One username receives repeated failed authentications inside the window."),
        ("SL-SF-004", "Successful login after failures", "HIGH", "A success follows repeated failures for the same IP and username; this is potentially suspicious, not proof of compromise."),
        ("SL-AL-005", "Windows account lockout", "CRITICAL", "A supported Windows Security Event 4740 is present."),
    ]
    for rule_id, name, severity, description in rules:
        st.markdown(f"**{name}** · <span class='rule-id'>{rule_id}</span> · :{COLORS[severity]}[{severity}]", unsafe_allow_html=True)
        st.write(description)
        st.divider()
    st.warning("SentinelLog scores are transparent rule-based triage indicators, not scientifically validated probabilities. Alerts require analyst review. The application never blocks IPs or changes firewall settings.")
