"""v2 read API and analyst actions: pagination, filters, workflow, audit trail, and privilege split."""

from __future__ import annotations

import json

from conftest import ROOT, console_headers, failed_web_login, read_headers, web_event


def load_campaign(client):
    lines = (ROOT / "services/web/samples/web-attack-campaign.sample.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(ln) for ln in lines if ln.strip()]
    assert client.post("/api/events", json=events).status_code == 200
    return events


def test_reads_need_the_read_token(client):
    assert client.get("/api/v2/events").status_code == 401
    assert client.get("/api/v2/events", headers=console_headers()).status_code == 401
    assert client.get("/api/v2/events", headers=read_headers()).status_code == 200


def test_pagination_and_totals(client):
    client.post("/api/events", json=[web_event() for _ in range(7)])
    page = client.get("/api/v2/events?limit=3&offset=0", headers=read_headers()).json()
    assert page["total"] == 7 and len(page["items"]) == 3 and page["span"]["first"] <= page["span"]["last"]
    last = client.get("/api/v2/events?limit=3&offset=6", headers=read_headers()).json()
    assert len(last["items"]) == 1


def test_page_size_is_bounded(client):
    assert client.get("/api/v2/events?limit=5000", headers=read_headers()).status_code == 422


def test_filters(client):
    events = load_campaign(client)
    h = read_headers()
    sqli = client.get("/api/v2/events?rule=W-SQLI-01", headers=h).json()
    assert sqli["total"] >= 1 and all("W-SQLI-01" in e["rules"] for e in sqli["items"])
    t = client.get("/api/v2/events?technique=T1190", headers=h).json()
    assert t["total"] == sqli["total"]
    inj = client.get("/api/v2/events?owasp=A05:2025", headers=h).json()
    assert inj["total"] >= sqli["total"]
    failed = client.get("/api/v2/events?event_type=authentication&outcome=failed", headers=h).json()
    assert failed["total"] == sum(e["event_type"] == "authentication" and e["outcome"] == "failed" for e in events)
    assert client.get("/api/v2/events?q=%2Fadmin", headers=h).json()["total"] >= 1
    alerted = client.get("/api/v2/events?detection=alerted", headers=h).json()
    observed = client.get("/api/v2/events?detection=observed", headers=h).json()
    matched = client.get("/api/v2/events?detection=matched", headers=h).json()
    assert alerted["total"] + observed["total"] + matched["total"] == len(events)


def test_owasp_2025_mapping_and_edition(client):
    load_campaign(client)
    data = client.get("/api/v2/owasp", headers=read_headers()).json()
    assert data["edition"] == "OWASP Top 10:2025"
    by_code = {c["code"]: c for c in data["categories"]}
    assert by_code["A05:2025"]["name"] == "Injection" and by_code["A05:2025"]["matches"] >= 1
    assert by_code["A01:2025"]["matches"] >= 1  # traversal, IDOR and SSRF (folded into A01 in 2025)
    assert by_code["A03:2025"]["observable"] is False


def test_mitre_coverage_is_derived_not_declared(client):
    data = client.get("/api/v2/mitre", headers=read_headers()).json()
    assert data["attack_version"] and data["total_techniques"] > 500
    rows = {r["technique"]: r for r in data["techniques"]}
    assert all(r["valid"] for r in rows.values())
    assert rows["T1190"]["status"] == "implemented_not_observed"
    load_campaign(client)
    rows = {r["technique"]: r for r in client.get("/api/v2/mitre", headers=read_headers()).json()["techniques"]}
    assert rows["T1190"]["status"] == "rule_inferred"  # web marks every mapping a candidate
    assert rows["T1046"]["status"] == "gap"


def test_alert_workflow_is_persisted_with_history(client):
    event = failed_web_login()
    event["raw_evidence_redacted"]["detections"][0]["rule"] = "W-AUTH-02"
    client.post("/api/events", json=[event])
    [alert] = client.get("/api/v2/alerts", headers=read_headers()).json()["items"]
    aid = alert["alert_id"]

    def act(action, note=None, expect=200):
        r = client.post("/api/v2/analyst/alert-status", headers=console_headers(),
                        json={"alert_id": aid, "action": action, "actor": "analyst", "note": note})
        assert r.status_code == expect, r.text

    act("investigate")
    act("false_positive", expect=422)  # a reason is required
    act("false_positive", note="Owner mistyped their password while testing.")
    act("investigate", expect=409)
    act("reopen")
    client.post("/api/v2/analyst/alert-note", headers=console_headers(),
                json={"alert_id": aid, "actor": "analyst", "note": "Checked with owner."})
    detail = client.get(f"/api/v2/alerts/{aid}", headers=read_headers()).json()
    assert detail["alert"]["status"] == "open"
    assert [h["action"] for h in detail["history"]] == ["investigate", "false_positive", "reopen", "note"]
    assert detail["history"][1]["from_status"] == "investigating" and detail["history"][1]["to_status"] == "false_positive"
    assert all(h["actor"] == "analyst" and h["ts"] for h in detail["history"])
    assert client.get("/api/v2/alerts?status=open", headers=read_headers()).json()["total"] == 1


def test_analyst_actions_need_console_token(client):
    body = {"alert_id": "x", "action": "investigate", "actor": "a"}
    assert client.post("/api/v2/analyst/alert-status", json=body).status_code == 401
    assert client.post("/api/v2/analyst/alert-status", json=body, headers=read_headers()).status_code == 401


def test_console_token_equal_to_read_token_is_refused(client, tokens):
    tokens["console"].write_text("read-token-for-tests", encoding="ascii")
    r = client.post("/api/v2/analyst/alert-status", headers=read_headers(),
                    json={"alert_id": "x", "action": "investigate", "actor": "a"})
    assert r.status_code == 503


def test_reclassification_keeps_the_original_event(client):
    event = web_event()
    client.post("/api/events", json=[event])
    r = client.post("/api/v2/analyst/event-classification", headers=console_headers(),
                    json={"event_id": event["event_id"], "actor": "analyst", "classification": "benign",
                          "reason": "my own browser"})
    assert r.status_code == 200 and r.json()["previous"] is None
    detail = client.get(f"/api/v2/events/{event['event_id']}", headers=read_headers()).json()
    assert detail["event"]["classification"] == "benign"
    assert {k: detail["event"][k] for k in event} == event
    assert detail["annotations"][0]["reason"] == "my own browser"


def test_source_profile_and_correlations(client):
    sid = "sess-1"
    client.post("/api/events", json=[
        web_event(session_id=sid), web_event(session_id=sid, request_path="/portal"),
        web_event(service="database", sensor_id="db-01", destination_service="database-honeypot", event_type="sql_query",
                  action="reconnaissance", command="SHOW TABLES", request_path=None, http_method=None, http_status=None)])
    profile = client.get("/api/v2/sources/172.28.0.50", headers=read_headers()).json()
    assert profile["event_count"] == 3 and profile["services"] == ["database", "web"]
    rules = {c["rule"]: c for c in profile["correlations"]}
    assert rules["C-XSVC-01"]["confidence"] == "low" and len(rules["C-XSVC-01"]["related_event_ids"]) == 2
    assert rules["C-SESS-01"]["confidence"] == "high"
    assert profile["sessions"][0]["duration_s"] >= 0
    assert "not an identified person" in profile["attribution"]
    assert client.get("/api/v2/sources/10.9.9.9", headers=read_headers()).status_code == 404
    listing = client.get("/api/v2/sources", headers=read_headers()).json()
    assert listing["total"] == 1 and listing["items"][0]["kind"] == "private"


def test_sensors_are_not_assumed_healthy(client):
    client.post("/api/events", json=[web_event()])
    [web] = client.get("/api/v2/sensors", headers=read_headers()).json()
    assert web["sensor_id"] == "web-01" and web["health"] == "unknown" and web["last_event_at"]
    client.post("/api/sensors/heartbeat", json={"sensor_id": "db-01", "service": "database", "status": "ok"})
    by_id = {s["sensor_id"]: s for s in client.get("/api/v2/sensors", headers=read_headers()).json()}
    assert by_id["db-01"]["health"] == "healthy" and by_id["db-01"]["events_total"] == 0


def test_ingestion_failures_are_counted(client):
    client.post("/api/events", json=[{"event_id": "bad"}])
    report = client.get("/api/v2/ingestion", headers=read_headers()).json()
    assert any(r["reason"] == "event batch failed validation" for r in report["reasons"])


def test_summary_counts_only_stored_data(client):
    empty = client.get("/api/v2/summary", headers=read_headers()).json()
    assert empty["events_total"] == 0 and empty["alerts_needing_attention"] == {} and empty["sensors"] == []
    load_campaign(client)
    full = client.get("/api/v2/summary", headers=read_headers()).json()
    assert full["events_total"] == 24 and sum(a["count"] for a in full["activity_24h"]) <= 24


def test_cursor_moves_only_on_new_data(client):
    a = client.get("/api/v2/cursor", headers=read_headers()).json()
    b = client.get("/api/v2/cursor", headers=read_headers()).json()
    assert a["events"] == b["events"] == 0
    client.post("/api/events", json=[web_event()])
    assert client.get("/api/v2/cursor", headers=read_headers()).json()["events"] == 1


def test_legacy_routes_still_work(client):
    load_campaign(client)
    h = read_headers()
    assert len(client.get("/api/events", headers=h).json()) == 24
    assert client.get("/api/alerts", headers=h).status_code == 200
    assert client.get("/api/attackers", headers=h).status_code == 200
