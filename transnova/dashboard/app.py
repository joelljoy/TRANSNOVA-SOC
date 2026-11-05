"""SOC dashboard. Every number comes from the collector API; nothing here is hardcoded.

Event fields hold raw attacker strings (docs/INTEGRATOR_NOTES.md §3), so they are only ever
shown with st.dataframe, st.code, st.json or st.text, and never as Markdown or HTML.
"""

from __future__ import annotations

import os
from typing import Any

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st

API = os.environ.get("COLLECTOR_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
SEVERITY_COLORS = {"LOW": "#4c9f70", "MEDIUM": "#e0a526", "HIGH": "#dd6b20", "CRITICAL": "#c53030"}

st.set_page_config(page_title="SOC Dashboard", layout="wide")


def read_headers() -> dict[str, str]:
    """The read token, sent if configured. A problem here shows as the normal collector error."""
    path = os.environ.get("SOC_READ_TOKEN_FILE")
    if not path:
        return {}
    try:
        with open(path, encoding="ascii") as fh:
            token = fh.read(4097).strip()
    except (OSError, ValueError):
        return {}
    return {"Authorization": f"Bearer {token}"} if token else {}


def get(path: str, **params: Any) -> Any:
    response = httpx.get(f"{API}{path}", params=params, headers=read_headers(), timeout=5, trust_env=False)
    response.raise_for_status()
    return response.json()


def bar(pairs: dict[str, int] | list, x: str, y: str, color_map: dict[str, str] | None = None):
    frame = pd.DataFrame(list(pairs.items()) if isinstance(pairs, dict) else pairs, columns=[x, y])
    fig = px.bar(frame, x=y, y=x, orientation="h", color=x if color_map else None, color_discrete_map=color_map)
    fig.update_layout(height=280, margin={"l": 0, "r": 0, "t": 10, "b": 0}, showlegend=False,
                      yaxis={"categoryorder": "total ascending", "title": None}, xaxis={"title": None})
    return fig


def event_rows(events: list[dict[str, Any]]) -> pd.DataFrame:
    return pd.DataFrame([{
        "time": e["timestamp"], "service": e["service"], "source": e["source_ip"], "user": e["username"],
        "type": e["event_type"], "action": e["action"], "outcome": e["outcome"],
        "severity": (e["raw_evidence_redacted"] or {}).get("severity"),
        "risk": (e["raw_evidence_redacted"] or {}).get("risk_score"),
        "query / path": e["command"] or e["request_path"], "tables": ", ".join(e["table_names"]),
        "session": e["session_id"],
    } for e in events])


def overview() -> None:
    health, sensors, alerts, events = get("/health"), get("/api/sensors"), get("/api/alerts"), get("/api/events", limit=15)
    attackers = get("/api/attackers")
    if health.get("read_capped_at"):
        st.warning("Some lists and summaries may be incomplete: stored events are too large to load in one read. "
                   f"Last happened at {health['read_capped_at']}. Nothing was deleted.")
    a, b, c, d = st.columns(4)
    a.metric("Events stored", health["events_stored"])
    b.metric("Open alerts", sum(x["status"] == "open" for x in alerts))
    c.metric("Critical / high", sum(x["severity"] in ("critical", "high") for x in alerts))
    d.metric("Observed sources", len(attackers))
    st.subheader("Sensors")
    if sensors:
        st.dataframe(pd.DataFrame([{"sensor": s["sensor_id"], "service": s["service"],
                                    "status": "stale" if s["stale"] else s["status"],
                                    "last heartbeat (s ago)": s["age_seconds"]} for s in sensors]),
                     hide_index=True, width="stretch")
    else:
        st.info("No sensor has checked in yet.")
    st.subheader("Recent events")
    if events:
        st.dataframe(event_rows(events), hide_index=True, width="stretch")
    else:
        st.info("No events captured yet. Connect to a decoy to generate some.")


def live_events() -> None:
    service = st.selectbox("Service", ["all", "database", "web", "ssh"])
    events = get("/api/events", limit=300, **({} if service == "all" else {"service": service}))
    if not events:
        st.info("No events captured yet.")
        return
    st.dataframe(event_rows(events), hide_index=True, width="stretch", height=430)
    st.caption("Evidence for the selected event")
    labels = {f"{e['timestamp']}  {e['action']}  {e['event_id']}": e for e in events[:100]}
    chosen = st.selectbox("Event", list(labels))
    st.json(labels[chosen])


def show_alerts() -> None:
    alerts = get("/api/alerts")
    if not alerts:
        st.info("No alerts yet.")
        return
    st.dataframe(pd.DataFrame([{
        "severity": a["severity"], "title": a["title"], "rule": a["rule"], "source": a["source_ip"], "service": a["service"],
        "events": a["event_count"], "ATT&CK": ", ".join(a["attack_ids"]), "first seen": a["first_seen"],
        "last seen": a["last_seen"], "status": a["status"]} for a in alerts]), hide_index=True, width="stretch")
    labels = {f"{a['severity'].upper()}  {a['title']}  ({a['source_ip']})": a for a in alerts}
    alert = labels[st.selectbox("Alert details", list(labels))]
    st.text(f"Why: {alert['rationale']}")
    st.text(f"Recommended action: {alert['recommended_action']}")
    if alert["attack"]:
        st.dataframe(pd.DataFrame(alert["attack"]), hide_index=True, width="stretch")


def attackers() -> None:
    sources = get("/api/attackers")
    if not sources:
        st.info("No sources observed yet.")
        return
    st.caption("Observed sources, not identified people. An IP address does not prove a single actor.")
    st.dataframe(pd.DataFrame(sources).drop(columns=["note"]), hide_index=True, width="stretch")
    chosen = st.selectbox("Timeline for source", [s["source_ip"] for s in sources])
    st.dataframe(event_rows(get(f"/api/attackers/{chosen}")["timeline"]), hide_index=True, width="stretch")


def database() -> None:
    sensors = {s["sensor_id"]: s for s in get("/api/sensors")}
    summary = get("/api/database/summary")
    db = sensors.get("db-01")
    if db is None:
        st.warning("Database sensor has not checked in.")
    else:
        state = "stale" if db["stale"] else db["status"]
        st.text(f"db-01: {state}. Database reachable: {db['details'].get('database_reachable')}. "
                f"Spool backlog: {db['details'].get('spool_pending')}. "
                f"Internal statements excluded: {db['details'].get('internal_ignored')}.")
    a, b, c, d, e = st.columns(5)
    a.metric("Logins OK / failed", f"{summary['connections_succeeded']} / {summary['connections_failed']}")
    b.metric("SQL statements", summary["queries_captured"])
    c.metric("Unique sources", summary["unique_sources"])
    d.metric("Sensitive reads", summary["sensitive_access"])
    e.metric("Denied statements", summary["denied_statements"])
    if not summary["queries_captured"]:
        st.info("No SQL captured yet. Connect as decoy_user from the attacker client.")
        return
    left, mid, right = st.columns(3)
    left.caption("Most targeted tables")
    if summary["top_tables"]:
        left.plotly_chart(bar(summary["top_tables"], "table", "statements"), width="stretch")
    mid.caption("Statement categories")
    mid.plotly_chart(bar(summary["categories"], "category", "statements"), width="stretch")
    right.caption("Severity")
    right.plotly_chart(bar(summary["severity"], "severity", "events", SEVERITY_COLORS), width="stretch")
    st.subheader("ATT&CK techniques with evidence")
    if summary["mitre"]:
        st.dataframe(pd.DataFrame(summary["mitre"], columns=["technique", "events"]), hide_index=True, width="stretch")
    else:
        st.info("No activity has supported an ATT&CK mapping yet.")
    st.subheader("Sessions")
    if db and db["details"].get("sessions"):
        st.dataframe(pd.DataFrame([{
            "session": s["session_id"], "source": s["source_ip"], "user": s["username"], "queries": s["query_count"],
            "tables": len(s["tables"]), "sensitive tables": ", ".join(s["sensitive_tables"]),
            "denied": s["restricted_attempts"], "reveals": ", ".join(s["reveal_rules"]), "risk": s["risk_score"],
            "first seen": s["first_seen"], "last seen": s["last_seen"]} for s in reversed(db["details"]["sessions"])]),
            hide_index=True, width="stretch")
    st.subheader("Recent database alerts")
    db_alerts = [x for x in get("/api/alerts") if x["service"] == "database"]
    if db_alerts:
        st.dataframe(pd.DataFrame([{"severity": x["severity"], "title": x["title"], "source": x["source_ip"],
                                    "events": x["event_count"], "ATT&CK": ", ".join(x["attack_ids"]),
                                    "why": x["rationale"]} for x in db_alerts]), hide_index=True, width="stretch")


def deception() -> None:
    records = get("/api/adaptations")
    if not records:
        st.info("No adaptive reveal has happened yet. Decoy tables stay hidden until behaviour triggers a rule.")
        return
    a, b, c = st.columns(3)
    a.metric("Assets revealed", len({r["asset_revealed"] for r in records if r["status"] != "failed"}))
    b.metric("Rules triggered", len({r["rule_id"] for r in records}))
    c.metric("Assets with attacker follow-up", len({r["asset_revealed"] for r in records if r["followup_event_ids"]}))
    st.dataframe(pd.DataFrame([{
        "time": r["timestamp"], "rule": r["rule_id"], "stage": r["stage"], "revealed": r["asset_revealed"],
        "status": r["status"], "before": r["privilege_before"], "after": r["privilege_after"],
        "follow-ups": len(r["followup_event_ids"]), "trigger source": r["source_ip"]} for r in records]),
        hide_index=True, width="stretch")
    labels = {f"{r['rule_id']} → {r['asset_revealed']}": r for r in records}
    chosen = labels[st.selectbox("Trigger → change → follow-up", list(labels))]
    st.text(f"Trigger: {chosen['trigger_reason']}")
    st.text(f"Trigger event: {chosen['trigger_event_id']}")
    st.code(chosen["statement"] or "(no statement: grant already present)", language="sql")
    if chosen["followups"]:
        st.dataframe(pd.DataFrame(chosen["followups"]), hide_index=True, width="stretch")
    else:
        st.info("The attacker has not read this asset yet.")


st.title("SOC Dashboard")
auto_refresh = st.toggle("Auto-refresh every 5 s", value=True)


@st.fragment(run_every="5s" if auto_refresh else None)
def render() -> None:
    # A fragment refreshes in place: a full script rerun would dim the page every cycle.
    try:
        views = st.tabs(["Overview", "Live Events", "Alerts", "Attackers", "Database Honeypot", "Adaptive Deception"])
        for tab, view in zip(views, (overview, live_events, show_alerts, attackers, database, deception)):
            with tab:
                view()
    except httpx.HTTPError as exc:
        st.error(f"Collector unavailable at {API} ({type(exc).__name__}).")


render()
