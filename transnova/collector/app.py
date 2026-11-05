"""Central collector: the smallest API that satisfies HANDOFF_FINAL.md §7 for live events,
alerts, profiles and adaptation history. Response actions, coverage and IOC export are the
integrator's and are not implemented here.
"""

from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from pydantic import TypeAdapter, ValidationError

from . import ssh_ingest
from .auth import bearer, load_token, same
from .console_api import register
from .detections import process_event
from .guards import BodyGuard, note_refusal
from .read_auth import ReadGate
from .schema import AdaptationRecord, CanonicalEvent, Heartbeat
from .storage import Store

MAX_BATCH = 50
SENSOR_STALE_S = 45

api = FastAPI(title="SOC Collector", docs_url=None, redoc_url=None, openapi_url=None)
store = Store(os.environ.get("COLLECTOR_DB_PATH", "data/collector.db"))
_events = TypeAdapter(list[CanonicalEvent])
_adaptations = TypeAdapter(list[AdaptationRecord])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _as_list(body: Any) -> list[Any]:
    items = body if isinstance(body, list) else [body]
    if len(items) > MAX_BATCH:
        raise HTTPException(status_code=413, detail=f"batch larger than {MAX_BATCH}")
    return items


def _peer(request: Request) -> str | None:
    return request.client.host if request.client else None


WEB_TOKEN_ENV = "WEB_INGEST_TOKEN_FILE"


def _web_gate(items: list[Any], headers: list[tuple[bytes, bytes]]) -> None:
    """Optional web-sensor authentication (two-laptop setup, owner request 2026-11-01).

    Off unless WEB_INGEST_TOKEN_FILE is set, so existing senders keep working. When set, any
    batch containing a web event needs `Authorization: Bearer <web token>`; an unreadable token
    file refuses all web events (fail closed) rather than silently accepting anyone."""
    path = os.environ.get(WEB_TOKEN_ENV)
    if not path or not any(isinstance(i, dict) and i.get("service") == "web" for i in items):
        return
    expected = load_token(path)
    if expected is None:
        note_refusal("web ingest token not configured correctly")
        raise HTTPException(status_code=503, detail="web ingest unavailable")
    if not same(bearer(headers), expected):
        note_refusal("web batch without a valid ingest token")
        raise HTTPException(status_code=401, detail="web ingest token required")


@api.post("/api/events")
def ingest_events(request: Request, body: Any = Body(...)) -> dict[str, int]:
    items = _as_list(body)
    _web_gate(items, request.scope["headers"])
    from_ssh = ssh_ingest.admit_events(items, request.scope["headers"], _peer(request))
    try:
        events = _events.validate_python(items)
    except ValidationError as exc:
        note_refusal("event batch failed validation")
        if from_ssh:
            raise HTTPException(status_code=422, detail=ssh_ingest.REJECTED) from None
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False, include_url=False)) from exc
    if from_ssh:
        ssh_ingest.check_events(items)
    stored = 0
    for event in events:
        doc = event.model_dump(mode="json")
        if store.insert_event(doc):
            stored += 1
            process_event(store, doc)
    return {"received": len(events), "stored": stored, "duplicates": len(events) - stored}


@api.post("/api/adaptations")
def ingest_adaptations(request: Request, body: Any = Body(...)) -> dict[str, int]:
    items = _as_list(body)
    ssh_ingest.admit_adaptations(items, request.scope["headers"], _peer(request))
    try:
        records = _adaptations.validate_python(items)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors(include_input=False, include_url=False)) from exc
    return {"stored": sum(store.put_adaptation(r.model_dump(mode="json")) for r in records)}


async def _heartbeat_identity(request: Request) -> None:
    """Runs before the Heartbeat model is checked, so a malformed claim of SSH cannot skip it."""
    try:
        body = await request.json()
    except ValueError:
        return
    if ssh_ingest.admit_heartbeat(body, request.scope["headers"], _peer(request)):
        ssh_ingest.check_heartbeat(body)


@api.post("/api/sensors/heartbeat", dependencies=[Depends(_heartbeat_identity)])
def sensor_heartbeat(beat: Heartbeat) -> dict[str, str]:
    store.put_sensor(beat.sensor_id, _now(), {**beat.model_dump(mode="json"), "last_seen": _now()})
    return {"status": "ok"}


@api.get("/api/events")
def list_events(limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0), service: str | None = None,
                source_ip: str | None = None, session_id: str | None = None) -> list[dict[str, Any]]:
    return store.events(limit, offset, service, source_ip, session_id)


@api.get("/api/alerts")
def list_alerts(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(store.alerts(limit), key=lambda a: order.get(a["severity"], 9))


def _profile(source_ip: str, events: list[dict[str, Any]], alerts: list[dict[str, Any]]) -> dict[str, Any]:
    stamps = [e["timestamp"] for e in events]
    return {
        "source_ip": source_ip, "first_seen": min(stamps), "last_seen": max(stamps), "event_count": len(events),
        "services": sorted({e["service"] for e in events}),
        "sessions": len({e["session_id"] for e in events if e["session_id"]}),
        "alert_count": len(alerts),
        "highest_severity": next((a["severity"] for a in sorted(
            alerts, key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}[a["severity"]])), None),
        "note": "Observed source, not an identified person.",
    }


@api.get("/api/attackers")
def list_attackers() -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in store.events(5000):
        grouped.setdefault(event["source_ip"], []).append(event)
    alerts = store.alerts(1000)
    return [_profile(ip, evs, [a for a in alerts if a["source_ip"] == ip]) for ip, evs in grouped.items()]


@api.get("/api/attackers/{source_ip}")
def attacker_detail(source_ip: str) -> dict[str, Any]:
    events = store.events(1000, source_ip=source_ip)
    if not events:
        raise HTTPException(status_code=404, detail="no events for that source")
    alerts = [a for a in store.alerts(1000) if a["source_ip"] == source_ip]
    return {**_profile(source_ip, events, alerts), "alerts": alerts, "timeline": list(reversed(events))}


@api.get("/api/adaptations")
def list_adaptations(limit: int = Query(200, ge=1, le=1000)) -> list[dict[str, Any]]:
    """Follow-ups come from genuine service events: a successful read of the asset. Only a
    successful read counts, since that is impossible before the grant."""
    db_events = store.events(5000, service="database")
    out = []
    for record in store.adaptations(limit):
        followups = [e for e in db_events if record["asset_revealed"] in e["table_names"] and e["outcome"] == "succeeded"]
        out.append({**record, "followup_event_ids": [e["event_id"] for e in followups],
                    "followups": [{"event_id": e["event_id"], "timestamp": e["timestamp"], "command": e["command"],
                                   "source_ip": e["source_ip"], "session_id": e["session_id"]} for e in followups[:20]]})
    return out


@api.get("/api/database/summary")
def database_summary() -> dict[str, Any]:
    events = store.events(5000, service="database")
    queries = [e for e in events if e["event_type"] == "sql_query"]
    auth = [e for e in events if e["event_type"] == "authentication"]
    evidence = [e["raw_evidence_redacted"] for e in queries]
    tables: Counter[str] = Counter(t for e in queries for t in e["table_names"])
    mitre: Counter[str] = Counter()
    for item in evidence:
        for m in item.get("mitre") or []:
            mitre[f"{m['technique']} {m['name']} ({m['status']})"] += 1
    return {
        "connections_succeeded": sum(e["outcome"] == "succeeded" for e in auth),
        "connections_failed": sum(e["outcome"] == "failed" for e in auth),
        "queries_captured": len(queries),
        "unique_sources": len({e["source_ip"] for e in events}),
        "sensitive_access": sum(e["action"] in ("sensitive_access", "adaptive_decoy_access") for e in queries),
        "denied_statements": sum(e["outcome"] == "blocked" for e in queries),
        "categories": Counter(e["action"] for e in queries),
        "severity": Counter(item.get("severity", "LOW") for item in evidence),
        "top_tables": tables.most_common(10),
        "mitre": mitre.most_common(),
    }


@api.get("/api/sensors")
def list_sensors() -> list[dict[str, Any]]:
    now = datetime.now(timezone.utc)
    out = []
    for sensor in store.sensors():
        seen = datetime.fromisoformat(sensor["last_seen"].replace("Z", "+00:00"))
        age = (now - seen).total_seconds()
        out.append({**sensor, "age_seconds": round(age), "stale": age > SENSOR_STALE_S})
    return out


@api.get("/health")
def health(request: Request) -> dict[str, Any]:
    if not request.scope.get("read_access", True):
        return {"status": "ok"}
    return {"status": "ok", "events_stored": store.count_events(), "read_capped_at": store.read_capped_at,
            "sensors": {s["sensor_id"]: ("stale" if s["stale"] else s["status"]) for s in list_sensors()}}


register(api, store)
app = BodyGuard(ReadGate(api))
