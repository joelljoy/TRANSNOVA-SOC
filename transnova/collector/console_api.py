"""The SOC console's API: filtered, paginated reads (v2) and the analyst's write actions.

Three privileges stay apart:
- ingest: POST /api/events and friends, unchanged (ssh_ingest guards SSH identity);
- read: every GET here, behind ReadGate's read token;
- analyst: the POST routes below, which need the console token (SOC_CONSOLE_TOKEN_FILE). That
  token must differ from the read and SSH tokens, so a leaked read token cannot change state.

Nothing here edits an event. Classification changes, alert status, notes and AI explanations are
stored beside the evidence with the actor and the time (storage.py).
"""

from __future__ import annotations

import ipaddress
import json
import os
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator

from . import engage, guards, rules_catalog
from .auth import bearer, load_token, same
from .detections import auto_block_rules, block_ttl_s, process_event
from .read_auth import token as read_token
from .schema import ConsoleEvent
from .storage import Store, now_iso

SENSOR_STALE_S = 45
MAX_PAGE = 200
ATTACK = json.loads((Path(__file__).parent / "attack_index" / "enterprise_index.json").read_text(encoding="utf-8"))
TECHNIQUES: dict[str, dict[str, Any]] = ATTACK["techniques"]
# Techniques these decoys could plausibly observe but that no rule detects. Shown as gaps.
KNOWN_GAPS = {
    "T1046": "Network Service Discovery: port scans stop at the network layer and never reach an application decoy.",
    "T1595.002": "Vulnerability Scanning: scanner fingerprints are not classified apart from route scans (W-ENUM-02).",
    "T1059.006": "Python: commands nested in python -c are not analysed by the SSH command parser.",
    "T1027": "Obfuscated Files or Information: base64-encoded or globbed shell commands are a known SSH miss.",
    "T1136.001": "Local Account: useradd in the emulated shell is recorded as a command but has no rule.",
    "T1098.004": "SSH Authorized Keys: writes to authorized_keys are recorded but not detected.",
    "T1053.003": "Cron: crontab edits are recorded but not detected.",
}
STATUSES = ("open", "investigating", "confirmed_malicious", "false_positive", "resolved")
TRANSITIONS = {
    "investigate": ({"open"}, "investigating"),
    "confirm": ({"open", "investigating"}, "confirmed_malicious"),
    "false_positive": ({"open", "investigating"}, "false_positive"),
    "resolve": ({"open", "investigating", "confirmed_malicious"}, "resolved"),
    "reopen": ({"resolved", "false_positive", "confirmed_malicious"}, "open"),
}
EVENT_CLASSES = ("benign", "suspicious", "confirmed_malicious", "false_positive", "unclassified")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _ago(**kw: float) -> str:
    return _iso(datetime.now(timezone.utc) - timedelta(**kw))


def console_token() -> bytes | None:
    return load_token(os.environ.get("SOC_CONSOLE_TOKEN_FILE"))


def require_console(request: Request) -> None:
    """The console token, distinct from every other token, or nothing changes."""
    expected = console_token()
    others = [read_token(), load_token(os.environ.get("SSH_INGEST_TOKEN_FILE"))]
    if expected is None or any(o is not None and same(o, expected) for o in others):
        guards.note_refusal("console token unavailable", "analyst")
        raise HTTPException(status_code=503, detail="analyst actions unavailable")
    if not same(bearer(request.scope["headers"]), expected):
        guards.note_refusal("analyst action without a valid token", "analyst")
        raise HTTPException(status_code=401, detail="not authorized")


class StatusChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str = Field(max_length=64)
    action: Literal["investigate", "confirm", "false_positive", "resolve", "reopen"]
    actor: str = Field(min_length=1, max_length=64)
    note: str | None = Field(None, max_length=4000)

class Note(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str = Field(max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    note: str = Field(min_length=1, max_length=4000)

class Classification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    classification: Literal["benign", "suspicious", "confirmed_malicious", "false_positive", "unclassified"]
    reason: str = Field(min_length=1, max_length=2000)

class Explanation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str = Field(max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    model: str = Field(max_length=100)
    evidence_digest: str = Field(max_length=128)
    explanation: dict[str, Any]

class AuthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["login", "logout", "session_expired", "login_rate_limited", "password_check"]
    outcome: Literal["succeeded", "failed", "blocked", "observed"]
    source_ip: str = Field(max_length=64)
    source_port: int | None = None
    username: str | None = Field(None, max_length=64)
    user_agent: str | None = Field(None, max_length=256)
    reason: str | None = Field(None, max_length=64)
    session_ref: str | None = Field(None, max_length=64)


def _valid_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as exc:
        raise ValueError("not an IP address") from exc


class BlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    alert_id: str | None = Field(None, max_length=64)
    ttl_s: int | None = Field(None, ge=60, le=30 * 86400)
    _ip = field_validator("ip")(_valid_ip)


class UnblockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(max_length=64)
    actor: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=1, max_length=500)
    _ip = field_validator("ip")(_valid_ip)


def register(r: FastAPI, store: Store) -> None:
    """Routes go straight onto the app, so the route-limit test sees every POST route."""

    # ---- derived fields ----------------------------------------------------------------------

    def decorate(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ids = [e["event_id"] for e in events]
        alerts = store.alert_ids_for_events(ids)
        classes = store.classifications_for(ids)
        out = []
        for e in events:
            dets = (e.get("raw_evidence_redacted") or {}).get("detections") or []
            linked = alerts.get(e["event_id"], [])
            status = "alerted" if linked else ("matched" if dets else "observed")
            out.append({**e, "detection_status": status, "alert_ids": linked,
                        "rules": sorted({str(d.get("rule")) for d in dets if isinstance(d, dict) and d.get("rule")}),
                        "classification": classes.get(e["event_id"], "unclassified")})
        return out

    def event_filters(service: str | None, source_ip: str | None, session_id: str | None, event_type: str | None,
                      action: str | None, outcome: str | None, sensor_id: str | None, rule: str | None,
                      technique: str | None, owasp: str | None, detection: str | None, since: str | None,
                      until: str | None, q: str | None, campaign_id: str | None) -> tuple[list[str], list[Any]]:
        where: list[str] = []
        args: list[Any] = []
        for col, val in (("service", service), ("source_ip", source_ip), ("session_id", session_id),
                         ("event_type", event_type), ("action", action), ("outcome", outcome),
                         ("sensor_id", sensor_id), ("campaign_id", campaign_id)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        if since:
            where.append("ts >= ?")
            args.append(since)
        if until:
            where.append("ts <= ?")
            args.append(until)
        if rule:
            where.append("EXISTS (SELECT 1 FROM json_each(events.doc, '$.raw_evidence_redacted.detections') d "
                         "WHERE json_extract(d.value, '$.rule') = ?)")
            args.append(rule)
        if technique:
            where.append("(EXISTS (SELECT 1 FROM json_each(events.doc, '$.raw_evidence_redacted.detections') d, "
                         "json_each(d.value, '$.attack') a WHERE json_extract(a.value, '$.technique') = ?) OR "
                         "EXISTS (SELECT 1 FROM json_each(events.doc, '$.raw_evidence_redacted.mitre') m "
                         "WHERE json_extract(m.value, '$.technique') = ?))")
            args += [technique, technique]
        if owasp:
            labels = [k for k, v in rules_catalog.OWASP_2025.items() if v.startswith(owasp)] or [owasp]
            marks = ",".join("?" * len(labels))
            where.append("EXISTS (SELECT 1 FROM json_each(events.doc, '$.raw_evidence_redacted.detections') d "
                         f"WHERE json_extract(d.value, '$.owasp') IN ({marks}))")
            args += labels
        if detection == "alerted":
            where.append("EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = events.event_id)")
        elif detection == "matched":
            where.append("n_detections > 0 AND NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = events.event_id)")
        elif detection == "observed":
            where.append("n_detections = 0 AND NOT EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = events.event_id)")
        if q:
            like = f"%{q.replace('%', '').replace('_', '')[:100]}%"
            where.append("(source_ip LIKE ? OR action LIKE ? OR request_path LIKE ? OR command LIKE ? OR username LIKE ? "
                         "OR event_id LIKE ?)")
            args += [like] * 6
        return where, args

    # ---- summary / cursor ----------------------------------------------------------------------

    @r.get("/api/v2/cursor")
    def cursor() -> dict[str, Any]:
        last_alert, history = store.alert_change_marker()
        return {"events": store.latest_rowid(), "alerts_last_seen": last_alert, "alert_history": history,
                "at": now_iso()}

    @r.get("/api/v2/summary")
    def summary() -> dict[str, Any]:
        since_24h = _ago(hours=24)
        by_hour = store.rows("SELECT substr(ts, 1, 13) AS h, service, count(*) FROM events WHERE ts >= ? "
                             "GROUP BY h, service ORDER BY h", (since_24h,))
        by_service = store.rows("SELECT service, count(*), max(ts) FROM events GROUP BY service")
        alert_rows = store.rows("SELECT severity, coalesce(alert_state.status, 'open'), count(*) FROM alerts "
                                "LEFT JOIN alert_state USING (alert_id) GROUP BY 1, 2")
        last = store.rows("SELECT max(ts) FROM events")[0][0]
        sources = store.rows("SELECT count(DISTINCT source_ip) FROM events WHERE service != 'soc'")[0][0]
        open_by_sev: Counter[str] = Counter()
        status_counts: Counter[str] = Counter()
        for sev, status, n in alert_rows:
            status_counts[status] += n
            if status in ("open", "investigating"):
                open_by_sev[sev] += n
        return {
            "events_total": store.count_events(), "last_event_at": last, "sources_observed": sources,
            "events_by_service": [{"service": s, "count": n, "last_event_at": t} for s, n, t in by_service],
            "activity_24h": [{"hour": h + ":00Z", "service": s, "count": n} for h, s, n in by_hour],
            "alerts_needing_attention": dict(open_by_sev), "alert_status_counts": dict(status_counts),
            "sensors": sensors(), "ingestion": ingestion(), "read_capped_at": store.read_capped_at,
        }

    # ---- events --------------------------------------------------------------------------------

    @r.get("/api/v2/events")
    def list_events(limit: int = Query(50, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0, le=10_000_000),
                    order: Literal["desc", "asc"] = "desc", service: str | None = None, source_ip: str | None = None,
                    session_id: str | None = None, event_type: str | None = None, action: str | None = None,
                    outcome: str | None = None, sensor_id: str | None = None, rule: str | None = None,
                    technique: str | None = None, owasp: str | None = None,
                    detection: Literal["observed", "matched", "alerted"] | None = None, since: str | None = None,
                    until: str | None = None, q: str | None = Query(None, max_length=100),
                    campaign_id: str | None = None) -> dict[str, Any]:
        where, args = event_filters(service, source_ip, session_id, event_type, action, outcome, sensor_id, rule,
                                    technique, owasp, detection, since, until, q, campaign_id)
        items, total = store.query_events(where, args, limit, offset, ascending=order == "asc")
        stamps = [e["timestamp"] for e in items]
        return {"items": decorate(items), "total": total, "limit": limit, "offset": offset,
                "span": {"first": min(stamps), "last": max(stamps)} if stamps else None}

    @r.get("/api/v2/events/facets")
    def event_facets() -> dict[str, Any]:
        def col(name: str) -> list[dict[str, Any]]:
            return [{"value": v, "count": n} for v, n in
                    store.rows(f"SELECT {name}, count(*) FROM events WHERE {name} IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT 50")]
        rules = store.rows("SELECT json_extract(d.value, '$.rule') AS rl, count(*) FROM events, "
                           "json_each(events.doc, '$.raw_evidence_redacted.detections') d GROUP BY rl ORDER BY 2 DESC LIMIT 100")
        return {"service": col("service"), "event_type": col("event_type"), "outcome": col("outcome"),
                "action": col("action"), "sensor_id": col("sensor_id"),
                "rule": [{"value": v, "count": n} for v, n in rules if v]}

    @r.get("/api/v2/events/{event_id}")
    def event_detail(event_id: str) -> dict[str, Any]:
        event = store.event(event_id)
        if event is None:
            raise HTTPException(status_code=404, detail="no such event")
        [decorated] = decorate([event])
        session = []
        if event.get("session_id"):
            session, _ = store.query_events(["session_id = ?"], [event["session_id"]], 100, 0, ascending=True)
        nearby, _ = store.query_events(["source_ip = ?", "event_id != ?"], [event["source_ip"], event_id], 20, 0)
        alerts = [a for a in (store.alert_by_id(i) for i in decorated["alert_ids"]) if a]
        return {"event": decorated, "annotations": store.event_annotations(event_id),
                "alerts": [_alert_summary(a, store.alert_status(a["alert_id"])) for a in alerts],
                "session_events": decorate(session), "source_recent": decorate(nearby),
                "detections": [_explain_detection(d) for d in (event.get("raw_evidence_redacted") or {}).get("detections") or []
                               if isinstance(d, dict)]}

    # ---- alerts --------------------------------------------------------------------------------

    @r.get("/api/v2/alerts")
    def list_alerts(limit: int = Query(50, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0),
                    sort: Literal["recent", "severity"] = "severity", severity: str | None = None,
                    status: str | None = None, rule: str | None = None, source_ip: str | None = None,
                    service: str | None = None, technique: str | None = None, tactic: str | None = None,
                    owasp: str | None = None, since: str | None = None, until: str | None = None) -> dict[str, Any]:
        where: list[str] = []
        args: list[Any] = []
        for col, val in (("severity", severity), ("rule", rule), ("a_source_ip", source_ip), ("a_service", service)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        if status:
            where.append("coalesce(alert_state.status, 'open') = ?")
            args.append(status)
        if since:
            where.append("last_seen >= ?")
            args.append(since)
        if until:
            where.append("first_seen <= ?")
            args.append(until)
        if technique:
            where.append("EXISTS (SELECT 1 FROM json_each(alerts.doc, '$.attack_ids') t WHERE t.value = ?)")
            args.append(technique)
        if tactic:
            ids = [tid for tid, t in TECHNIQUES.items() if tactic in t["tactics"]]
            marks = ",".join("?" * len(ids)) or "''"
            where.append(f"EXISTS (SELECT 1 FROM json_each(alerts.doc, '$.attack_ids') t WHERE t.value IN ({marks}))")
            args += ids
        if owasp:
            rules = [rid for rid, e in rules_catalog.RULES.items() if (e["owasp_2025"] or "").startswith(owasp)]
            marks = ",".join("?" * len(rules)) or "''"
            where.append(f"rule IN ({marks})")
            args += rules
        items, total = store.query_alerts(where, args, limit, offset, sort)
        states = store.statuses_for([a["alert_id"] for a in items])
        return {"items": [_alert_summary(a, states.get(a["alert_id"])) for a in items], "total": total,
                "limit": limit, "offset": offset}

    @r.get("/api/v2/alerts/{alert_id}")
    def alert_detail(alert_id: str) -> dict[str, Any]:
        alert = store.alert_by_id(alert_id)
        if alert is None:
            raise HTTPException(status_code=404, detail="no such alert")
        ids = store.alert_event_ids(alert_id) or alert.get("related_event_ids") or []
        events = decorate(store.events_by_ids(ids[:200]))
        matched = []
        for e in events:
            for d in (e.get("raw_evidence_redacted") or {}).get("detections") or []:
                if isinstance(d, dict) and str(d.get("rule")) == alert["rule"]:
                    matched.append({"event_id": e["event_id"], "timestamp": e["timestamp"], **_explain_detection(d)})
        stamps = [e["timestamp"] for e in events]
        return {
            "alert": _alert_summary(alert, store.alert_status(alert_id)),
            "rationale": alert.get("rationale"), "recommended_action": alert.get("recommended_action"),
            "attack": [{**a, **_technique_info(a.get("technique"))} for a in alert.get("attack") or []],
            "rule": rules_catalog.rule(alert["rule"]),
            "engage": engage.for_rule(alert["rule"]), "engage_matrix": engage.MATRIX_URL,
            "block": next((b for b in store.active_blocks() if b["ip"] == alert["source_ip"]), None),
            "events": events, "matched_detections": matched,
            "evidence_window": {"first": min(stamps), "last": max(stamps)} if stamps else None,
            "events_truncated": len(ids) > 200 or alert.get("event_count", 0) > len(ids),
            "history": store.alert_history(alert_id), "explanations": store.explanations(alert_id),
            "source": _source_brief(alert["source_ip"]),
        }

    # ---- sources -------------------------------------------------------------------------------

    @r.get("/api/v2/sources")
    def list_sources(limit: int = Query(50, ge=1, le=MAX_PAGE), offset: int = Query(0, ge=0),
                     q: str | None = Query(None, max_length=64),
                     sort: Literal["recent", "events", "alerts"] = "recent") -> dict[str, Any]:
        where = "WHERE service != 'soc'"
        args: list[Any] = []
        if q:
            where += " AND source_ip LIKE ?"
            args.append(f"%{q.replace('%', '')}%")
        order = {"recent": "last_seen DESC", "events": "n DESC", "alerts": "alerts DESC, last_seen DESC"}[sort]
        rows = store.rows(f"""
            SELECT source_ip, min(ts), max(ts) AS last_seen, count(*) AS n, group_concat(DISTINCT service),
                   count(DISTINCT session_id),
                   (SELECT count(*) FROM alerts WHERE a_source_ip = events.source_ip) AS alerts
            FROM events {where} GROUP BY source_ip ORDER BY {order} LIMIT ? OFFSET ?""", (*args, limit, offset))
        total = store.rows(f"SELECT count(DISTINCT source_ip) FROM events {where}", args)[0][0]
        return {"items": [{"source_ip": ip, "first_seen": f, "last_seen": l, "event_count": n,
                           "services": sorted((svc or "").split(",")), "sessions": sess, "alert_count": al,
                           "kind": _source_kind(ip)} for ip, f, l, n, svc, sess, al in rows],
                "total": total, "limit": limit, "offset": offset}

    @r.get("/api/v2/sources/{source_ip}")
    def source_profile(source_ip: str) -> dict[str, Any]:
        brief = _source_brief(source_ip)
        if brief is None:
            raise HTTPException(status_code=404, detail="no events for that source")
        rows = store.rows("SELECT service, event_type, outcome, count(*) FROM events WHERE source_ip = ? GROUP BY 1, 2, 3",
                          (source_ip,))
        sessions = store.rows("SELECT session_id, service, min(ts), max(ts), count(*), group_concat(DISTINCT username) "
                              "FROM events WHERE source_ip = ? AND session_id IS NOT NULL GROUP BY 1, 2 ORDER BY 3 DESC "
                              "LIMIT 100", (source_ip,))
        commands = store.rows("SELECT event_id, ts, command, session_id FROM events WHERE source_ip = ? AND "
                              "event_type = 'command' AND command IS NOT NULL ORDER BY ts DESC LIMIT 50", (source_ip,))
        requests = store.rows("SELECT json_extract(doc, '$.http_method'), request_path, count(*), max(ts) FROM events "
                              "WHERE source_ip = ? AND event_type = 'http_request' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 50",
                              (source_ip,))
        queries = store.rows("SELECT event_id, ts, command, outcome FROM events WHERE source_ip = ? AND "
                             "event_type = 'sql_query' ORDER BY ts DESC LIMIT 50", (source_ip,))
        usernames = store.rows("SELECT service, username, outcome, count(*) FROM events WHERE source_ip = ? AND "
                               "event_type = 'authentication' AND username IS NOT NULL GROUP BY 1, 2, 3 ORDER BY 4 DESC "
                               "LIMIT 50", (source_ip,))
        alerts, _ = store.query_alerts(["a_source_ip = ?"], [source_ip], 100, 0, "severity")
        states = store.statuses_for([a["alert_id"] for a in alerts])
        return {
            **brief,
            "breakdown": [{"service": s, "event_type": t, "outcome": o, "count": n} for s, t, o, n in rows],
            "sessions": [{"session_id": sid, "service": svc, "first_seen": f, "last_seen": l, "event_count": n,
                          "duration_s": _seconds(f, l), "usernames": [u for u in (users or "").split(",") if u]}
                         for sid, svc, f, l, n, users in sessions],
            "commands": [{"event_id": i, "timestamp": t, "command": c, "session_id": s} for i, t, c, s in commands],
            "http_requests": [{"method": m, "path": p, "count": n, "last_seen": t} for m, p, n, t in requests],
            "sql_queries": [{"event_id": i, "timestamp": t, "command": c, "outcome": o} for i, t, c, o in queries],
            "authentication": [{"service": s, "username": u, "outcome": o, "count": n} for s, u, o, n in usernames],
            "techniques": _source_techniques(source_ip),
            "alerts": [_alert_summary(a, states.get(a["alert_id"])) for a in alerts],
            "correlations": _correlations(source_ip),
        }

    # ---- sensors and ingestion -----------------------------------------------------------------

    @r.get("/api/v2/sensors")
    def sensors() -> list[dict[str, Any]]:
        now = datetime.now(timezone.utc)
        stats = store.sensor_event_stats(_ago(minutes=5), _ago(hours=1))
        beats = {s["sensor_id"]: s for s in store.sensors()}
        out = []
        for sensor_id in sorted(set(stats) | set(beats)):
            beat, stat = beats.get(sensor_id), stats.get(sensor_id, {})
            age = None
            if beat:
                age = round((now - datetime.fromisoformat(beat["last_seen"].replace("Z", "+00:00"))).total_seconds())
            if sensor_id == "soc-auth":
                health, reason = "internal", "The console's own authentication audit trail; it sends no heartbeat."
            elif beat is None:
                health, reason = "unknown", "This sensor sends no heartbeat, so only its last event is known."
            elif age is not None and age > SENSOR_STALE_S:
                health, reason = "stale", f"No heartbeat for {age} s (expected every few seconds)."
            elif beat.get("status") == "degraded":
                health, reason = "degraded", "The sensor reports itself degraded."
            else:
                health, reason = "healthy", "Heartbeat is current and reports ok."
            details = (beat or {}).get("details") or {}
            out.append({"sensor_id": sensor_id, "service": (beat or {}).get("service") or stat.get("service"),
                        "health": health, "health_reason": reason,
                        "last_heartbeat_at": (beat or {}).get("last_seen"), "heartbeat_age_s": age,
                        "reported_status": (beat or {}).get("status"),
                        "last_event_at": stat.get("last_event_at"), "events_total": stat.get("events_total", 0),
                        "events_5m": stat.get("events_5m", 0), "events_1h": stat.get("events_1h", 0),
                        "details": {k: v for k, v in details.items() if k != "sessions"},
                        "sessions": details.get("sessions") if isinstance(details.get("sessions"), list) else None})
        return out

    @r.get("/api/v2/ingestion")
    def ingestion() -> dict[str, Any]:
        return guards.refusal_report()

    # ---- framework coverage --------------------------------------------------------------------

    @r.get("/api/v2/rules")
    def rules() -> dict[str, Any]:
        counts = dict(store.rows("SELECT json_extract(d.value, '$.rule'), count(*) FROM events, "
                                 "json_each(events.doc, '$.raw_evidence_redacted.detections') d GROUP BY 1"))
        alerts = dict(store.rows("SELECT rule, count(*) FROM alerts GROUP BY rule"))
        return {"owasp_edition": rules_catalog.OWASP_EDITION, "attack_version": ATTACK["attack_version"],
                "rules": [{**e, "matches": counts.get(rid, 0), "alerts": alerts.get(rid, 0),
                           "attack_detail": [_technique_info(t) | {"technique": t} for t in e["attack"]]}
                          for rid, e in rules_catalog.RULES.items()]}

    @r.get("/api/v2/mitre")
    def mitre() -> dict[str, Any]:
        observed: dict[str, Counter[str]] = {}
        for tech, status, n in store.rows("""
            SELECT json_extract(a.value, '$.technique'), coalesce(json_extract(a.value, '$.status'), 'candidate'), count(*)
            FROM events, json_each(events.doc, '$.raw_evidence_redacted.detections') d, json_each(d.value, '$.attack') a
            GROUP BY 1, 2
            UNION ALL
            SELECT json_extract(m.value, '$.technique'), coalesce(json_extract(m.value, '$.status'), 'observed'), count(*)
            FROM events, json_each(events.doc, '$.raw_evidence_redacted.mitre') m GROUP BY 1, 2"""):
            if tech:
                observed.setdefault(tech, Counter())[status] += n
        alert_counts = Counter(t for (doc,) in store.rows("SELECT doc FROM alerts") for t in json.loads(doc).get("attack_ids") or [])
        by_rule: dict[str, list[str]] = {}
        for rid, e in rules_catalog.RULES.items():
            for t in e["attack"]:
                by_rule.setdefault(t, []).append(rid)
        rows = []
        for tid in sorted(set(by_rule) | set(observed) | set(KNOWN_GAPS)):
            info = _technique_info(tid)
            ev = observed.get(tid, Counter())
            rules_for = by_rule.get(tid, [])
            tested = [rid for rid in rules_for if rules_catalog.RULES[rid]["tested_by"]]
            if tid in KNOWN_GAPS and not rules_for:
                status = "gap"
            elif ev.get("observed"):
                status = "evidence"
            elif ev:
                status = "rule_inferred"
            else:
                status = "implemented_not_observed"
            rows.append({"technique": tid, **info, "rules": rules_for, "rules_tested": tested,
                         "evidence_observed": ev.get("observed", 0),
                         "evidence_candidate": sum(n for s, n in ev.items() if s != "observed"),
                         "alerts": alert_counts.get(tid, 0), "status": status, "gap_reason": KNOWN_GAPS.get(tid),
                         "services": sorted({rules_catalog.RULES[r]["service"] for r in rules_for})})
        return {"attack_version": ATTACK["attack_version"], "source": ATTACK["source"], "modified": ATTACK["modified"],
                "tactics": ATTACK["tactics"], "total_techniques": len(TECHNIQUES), "techniques": rows}

    @r.get("/api/v2/owasp")
    def owasp() -> dict[str, Any]:
        counts = store.rows("""
            SELECT json_extract(d.value, '$.owasp'), json_extract(d.value, '$.rule'), count(*), max(events.ts),
                   count(DISTINCT events.source_ip)
            FROM events, json_each(events.doc, '$.raw_evidence_redacted.detections') d
            WHERE events.service = 'web' GROUP BY 1, 2""")
        web_total = store.rows("SELECT count(*) FROM events WHERE service = 'web'")[0][0]
        cats = []
        for code, name in rules_catalog.OWASP_2025_CATEGORIES:
            rules_here = [rid for rid, e in rules_catalog.RULES.items() if (e["owasp_2025"] or "").startswith(code)]
            hits = [(label, rule, n, last, srcs) for label, rule, n, last, srcs in counts
                    if (rules_catalog.owasp_2025(label) or "").startswith(code)]
            cats.append({"code": code, "name": name, "rules": rules_here,
                         "observable": code not in rules_catalog.OWASP_NOT_OBSERVABLE,
                         "not_observable_reason": rules_catalog.OWASP_NOT_OBSERVABLE.get(code),
                         "matches": sum(h[2] for h in hits), "last_seen": max((h[3] for h in hits), default=None),
                         "by_rule": [{"rule": h[1], "label_2021": h[0], "matches": h[2], "sources": h[4]} for h in hits]})
        return {"edition": rules_catalog.OWASP_EDITION, "source": rules_catalog.OWASP_SOURCE,
                "sensor_edition": "OWASP Top 10:2021 (labels as emitted by web-01)", "web_events": web_total,
                "categories": cats}

    # ---- ATT&CK Navigator layer (USP 5) ----------------------------------------------------------
    @r.get("/api/v2/navigator")
    def navigator() -> dict[str, Any]:
        """Observed techniques as an ATT&CK Navigator layer (layer format 4.5), openable in MITRE's own
        tool at https://mitre-attack.github.io/attack-navigator/. Scores are event counts."""
        data = mitre()
        seen = [t for t in data["techniques"] if t["evidence_observed"] + t["evidence_candidate"] > 0 and t["valid"]]
        top = max([t["evidence_observed"] + t["evidence_candidate"] for t in seen] or [1])
        techniques = []
        for t in seen:
            n = t["evidence_observed"] + t["evidence_candidate"]
            for tactic in t["tactics"] or [None]:
                item = {"techniqueID": t["technique"], "score": n, "enabled": True,
                        "comment": (f"{n} events; rules {', '.join(t['rules']) or 'none'}; "
                                    f"{'observed' if t['evidence_observed'] else 'rule candidate'}")[:500],
                        "metadata": [{"name": "alerts", "value": str(t["alerts"])}]}
                if tactic:
                    item["tactic"] = tactic
                techniques.append(item)
        return {
            "name": "TransNova SOC: observed techniques", "versions": {"attack": str(data["attack_version"]).split(".")[0],
                                                                       "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": f"Exported {_iso(datetime.now(timezone.utc))} from the TransNova SOC honeypot network. "
                           "Scores are event counts. Web detections are rule candidates, not proof of success.",
            "techniques": techniques,
            "gradient": {"colors": ["#e2ebf1", "#24506f"], "minValue": 0, "maxValue": top},
            "legendItems": [], "showTacticRowBackground": True, "selectTechniquesAcrossTactics": True,
            "hideDisabled": False, "layout": {"layout": "side", "showName": True, "showID": True},
        }

    # ---- response: main-site blocklist (USP 1) ----------------------------------------------------
    @r.get("/api/v2/blocklist")
    def blocklist() -> dict[str, Any]:
        return {"active": store.active_blocks(), "history": store.block_history(50),
                "auto_rules": sorted(auto_block_rules()), "ttl_s": block_ttl_s(),
                "engage": [{"activity": a, "goal": g, "approach": ap, "description": engage.ACTIVITIES[a]}
                           for a, g, ap in engage.BLOCK_ACTIVITY]}

    @r.post("/api/blocklist/feed")
    def blocklist_feed(request: Request) -> dict[str, Any]:
        """For the main site on the honeypot laptop. Authenticated with the web ingest token (the same
        trust as sending events); a POST so it never needs the read token, which would expose all data."""
        expected = load_token(os.environ.get("WEB_INGEST_TOKEN_FILE"))
        if expected is None:
            raise HTTPException(status_code=503, detail="blocklist feed unavailable")
        if not same(bearer(request.scope["headers"]), expected):
            guards.note_refusal("blocklist feed without a valid token", "ingest")
            raise HTTPException(status_code=401, detail="not authorized")
        active = store.active_blocks()
        return {"ips": [b["ip"] for b in active], "count": len(active), "generated_at": _iso(datetime.now(timezone.utc))}

    # ---- analyst actions (console token) -------------------------------------------------------

    @r.post("/api/v2/analyst/alert-status", dependencies=[Depends(require_console)])
    def change_status(body: StatusChange) -> dict[str, Any]:
        if store.alert_by_id(body.alert_id) is None:
            raise HTTPException(status_code=404, detail="no such alert")
        current = (store.alert_status(body.alert_id) or {}).get("status", "open")
        allowed, target = TRANSITIONS[body.action]
        if current not in allowed:
            raise HTTPException(status_code=409, detail=f"cannot {body.action} an alert that is {current}")
        if body.action in ("false_positive", "confirm") and not (body.note and body.note.strip()):
            raise HTTPException(status_code=422, detail="a reason is required for this disposition")
        return store.set_alert_status(body.alert_id, body.actor, body.action, current, target, body.note)

    @r.post("/api/v2/analyst/alert-note", dependencies=[Depends(require_console)])
    def add_note(body: Note) -> dict[str, Any]:
        if store.alert_by_id(body.alert_id) is None:
            raise HTTPException(status_code=404, detail="no such alert")
        return store.add_alert_note(body.alert_id, body.actor, body.note)

    @r.post("/api/v2/analyst/event-classification", dependencies=[Depends(require_console)])
    def classify_event(body: Classification) -> dict[str, Any]:
        if store.event(body.event_id) is None:
            raise HTTPException(status_code=404, detail="no such event")
        return store.annotate_event(body.event_id, body.actor, body.classification, body.reason)

    @r.post("/api/v2/analyst/explanation", dependencies=[Depends(require_console)])
    def save_explanation(body: Explanation) -> dict[str, Any]:
        if store.alert_by_id(body.alert_id) is None:
            raise HTTPException(status_code=404, detail="no such alert")
        if len(json.dumps(body.explanation)) > 32_000:
            raise HTTPException(status_code=413, detail="explanation too large")
        return store.add_explanation(body.alert_id, body.actor, body.model, body.evidence_digest, body.explanation)

    @r.post("/api/v2/analyst/block", dependencies=[Depends(require_console)])
    def block_ip(body: BlockRequest) -> dict[str, Any]:
        if body.alert_id and store.alert_by_id(body.alert_id) is None:
            raise HTTPException(status_code=404, detail="no such alert")
        return store.add_block(body.ip, actor=body.actor, reason=body.reason, ttl_s=body.ttl_s or block_ttl_s(),
                               alert_id=body.alert_id, rule=(store.alert_by_id(body.alert_id) or {}).get("rule")
                               if body.alert_id else None)

    @r.post("/api/v2/analyst/unblock", dependencies=[Depends(require_console)])
    def unblock_ip(body: UnblockRequest) -> dict[str, Any]:
        if not store.remove_block(body.ip, actor=body.actor, reason=body.reason):
            raise HTTPException(status_code=404, detail="that address is not blocked")
        return {"ip": body.ip, "unblocked": True}

    @r.post("/api/v2/console/auth-event", dependencies=[Depends(require_console)])
    def console_auth_event(body: AuthEvent) -> dict[str, Any]:
        """The console's authentication audit trail. Built here, never accepted from /api/events."""
        try:
            ipaddress.ip_address(body.source_ip)
        except ValueError:
            raise HTTPException(status_code=422, detail="source_ip must be an address") from None
        event = ConsoleEvent(
            event_id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc), sensor_id="soc-auth", service="soc",
            source_ip=body.source_ip, source_port=body.source_port, destination_service="soc-console",
            event_type="authentication", action=body.action, outcome=body.outcome, username=body.username,
            session_id=body.session_ref, user_agent=body.user_agent,
            raw_evidence_redacted={"source": "soc-console", "reason": body.reason,
                                   "detections": [{"rule": "SOC-AUTH-00", "category": "behavior_detected",
                                                   "label": "soc:auth_failed", "confidence": "low",
                                                   "rationale": "one failed console login; an event, not an attack",
                                                   "attack": []}] if body.action == "login" and body.outcome == "failed" else []},
            tags=["soc:auth"])
        doc = event.model_dump(mode="json")
        store.insert_event(doc)
        process_event(store, doc)
        return {"event_id": doc["event_id"], "timestamp": doc["timestamp"]}

    # ---- helpers that need the store -----------------------------------------------------------

    def _source_brief(source_ip: str) -> dict[str, Any] | None:
        row = store.rows("SELECT min(ts), max(ts), count(*), group_concat(DISTINCT service), count(DISTINCT session_id) "
                         "FROM events WHERE source_ip = ?", (source_ip,))[0]
        if not row[2]:
            return None
        alerts = store.rows("SELECT severity, count(*) FROM alerts WHERE a_source_ip = ? GROUP BY 1", (source_ip,))
        return {"source_ip": source_ip, "kind": _source_kind(source_ip), "first_seen": row[0], "last_seen": row[1],
                "event_count": row[2], "services": sorted((row[3] or "").split(",")), "sessions": row[4],
                "alerts_by_severity": dict(alerts), "alert_count": sum(n for _, n in alerts),
                "attribution": "Observed network source. An address can be shared, reassigned or translated, "
                               "so it is not an identified person or a single actor."}

    def _source_techniques(source_ip: str) -> list[dict[str, Any]]:
        rows = store.rows("""
            SELECT json_extract(a.value, '$.technique'), coalesce(json_extract(a.value, '$.status'), 'candidate'),
                   json_extract(d.value, '$.rule'), events.event_id
            FROM events, json_each(events.doc, '$.raw_evidence_redacted.detections') d, json_each(d.value, '$.attack') a
            WHERE events.source_ip = ?
            UNION ALL
            SELECT json_extract(m.value, '$.technique'), coalesce(json_extract(m.value, '$.status'), 'observed'),
                   NULL, events.event_id
            FROM events, json_each(events.doc, '$.raw_evidence_redacted.mitre') m WHERE events.source_ip = ?""",
                          (source_ip, source_ip))
        grouped: dict[str, dict[str, Any]] = {}
        for tech, status, rule, event_id in rows:
            if not tech:
                continue
            g = grouped.setdefault(tech, {"technique": tech, **_technique_info(tech), "statuses": Counter(),
                                          "rules": set(), "event_ids": []})
            g["statuses"][status] += 1
            if rule:
                g["rules"].add(rule)
            if len(g["event_ids"]) < 20 and event_id not in g["event_ids"]:
                g["event_ids"].append(event_id)
        return [{**g, "statuses": dict(g["statuses"]), "rules": sorted(g["rules"]),
                 "basis": "evidence" if g["statuses"].get("observed") else "rule_inferred"}
                for g in sorted(grouped.values(), key=lambda g: g["technique"])]

    def _correlations(source_ip: str) -> list[dict[str, Any]]:
        """Explainable links only. Each says which rule made it, from which events, and how sure it is."""
        out: list[dict[str, Any]] = []
        if source_ip.startswith("unknown-ssh-"):
            return out
        rows = store.rows("SELECT event_id, ts, service FROM events WHERE source_ip = ? AND service != 'soc' "
                          "ORDER BY ts LIMIT 5000", (source_ip,))
        # C-XSVC-01: the same address on two decoys within 30 minutes.
        last_by_service: dict[str, tuple[str, str]] = {}
        pairs: dict[tuple[str, str], tuple[str, str, str, str]] = {}
        for event_id, ts, service in rows:
            t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            for other, (oid, ots) in last_by_service.items():
                if other != service and t - datetime.fromisoformat(ots.replace("Z", "+00:00")) <= timedelta(minutes=30):
                    key = tuple(sorted((other, service)))
                    pairs.setdefault(key, (oid, ots, event_id, ts))
            last_by_service[service] = (event_id, ts)
        for (a, b), (e1, t1, e2, t2) in pairs.items():
            out.append({"correlation_id": f"C-XSVC-01:{source_ip}:{a}+{b}", "rule": "C-XSVC-01",
                        "title": f"Same address on the {a} and {b} decoys within 30 minutes",
                        "related_event_ids": [e1, e2], "window": {"first": t1, "last": t2}, "confidence": "low",
                        "reason": "Shared source IP only. NAT, shared lab hosts or the Docker gateway produce the "
                                  "same link, so this is a lead, not proof of one actor."})
        # C-SESS-01: events tied together by the sensor's own session identifier.
        for sid, svc, first, last, n in store.rows(
                "SELECT session_id, service, min(ts), max(ts), count(*) FROM events WHERE source_ip = ? AND "
                "session_id IS NOT NULL GROUP BY 1, 2 HAVING count(*) > 1 ORDER BY 3 DESC LIMIT 20", (source_ip,)):
            out.append({"correlation_id": f"C-SESS-01:{svc}:{sid}", "rule": "C-SESS-01",
                        "title": f"{n} events in one {svc} session", "session_id": sid,
                        "related_event_ids": [r[0] for r in store.rows(
                            "SELECT event_id FROM events WHERE session_id = ? ORDER BY ts LIMIT 50", (sid,))],
                        "window": {"first": first, "last": last}, "confidence": "high",
                        "reason": "The decoy assigned one session identifier to all of these events."})
        # C-CAMP-01: a campaign ID, trusted by the web decoy only from the lab simulator's address.
        for camp, others in store.rows(
                "SELECT campaign_id, group_concat(DISTINCT source_ip) FROM events WHERE campaign_id IN "
                "(SELECT DISTINCT campaign_id FROM events WHERE source_ip = ? AND campaign_id IS NOT NULL) GROUP BY 1",
                (source_ip,)):
            out.append({"correlation_id": f"C-CAMP-01:{camp}", "rule": "C-CAMP-01",
                        "title": "Declared lab campaign", "campaign_id": camp,
                        "related_sources": sorted((others or "").split(",")), "related_event_ids": [],
                        "window": None, "confidence": "high",
                        "reason": "The lab simulator labelled this traffic. The web decoy accepts the label only from "
                                  "the simulator's fixed address."})
        return out


def _seconds(first: str, last: str) -> float:
    a = datetime.fromisoformat(first.replace("Z", "+00:00"))
    b = datetime.fromisoformat(last.replace("Z", "+00:00"))
    return round((b - a).total_seconds(), 3)


def _source_kind(source_ip: str) -> str:
    if source_ip.startswith("unknown-ssh-"):
        return "unresolved"
    try:
        ip = ipaddress.ip_address(source_ip)
    except ValueError:
        return "label"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private:
        return "private"
    return "public"


def _technique_info(tid: str | None) -> dict[str, Any]:
    t = TECHNIQUES.get(tid or "")
    if t is None:
        return {"name": None, "tactics": [], "valid": False, "url": None}
    return {"name": t["name"], "tactics": t["tactics"], "valid": True, "url": t["url"], "subtechnique": t["subtechnique"]}


def _explain_detection(d: dict[str, Any]) -> dict[str, Any]:
    rule = str(d.get("rule"))
    entry = rules_catalog.rule(rule)
    return {"rule": rule, "name": (entry or {}).get("name") or d.get("label") or rule, "field": d.get("field"),
            "confidence": d.get("confidence"), "severity": d.get("severity"), "rationale": d.get("rationale"),
            "owasp_2021": d.get("owasp"), "owasp_2025": rules_catalog.owasp_2025(d.get("owasp")),
            "alerting": rules_catalog.alerting(rule), "engage": engage.for_rule(rule),
            "attack": [{**a, **_technique_info(a.get("technique"))} for a in d.get("attack") or [] if isinstance(a, dict)]}


def _alert_summary(alert: dict[str, Any], state: dict[str, Any] | None) -> dict[str, Any]:
    entry = rules_catalog.rule(alert["rule"]) or {}
    return {
        "alert_id": alert["alert_id"], "rule": alert["rule"], "title": entry.get("name") or alert["title"],
        "severity": alert["severity"],
        "confidence": alert.get("confidence"), "status": (state or {}).get("status", "open"),
        "status_updated_at": (state or {}).get("updated_at"), "status_updated_by": (state or {}).get("updated_by"),
        "first_seen": alert["first_seen"], "last_seen": alert["last_seen"], "source_ip": alert["source_ip"],
        "service": alert["service"], "event_count": alert["event_count"], "attack_ids": alert.get("attack_ids") or [],
        "kill_chain_stage": alert.get("kill_chain_stage"), "owasp_2025": entry.get("owasp_2025"),
        "activity_after_status": bool(state and state["status"] in ("resolved", "false_positive")
                                      and alert["last_seen"] > state["updated_at"]),
    }
