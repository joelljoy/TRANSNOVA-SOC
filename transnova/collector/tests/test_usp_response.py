"""USP 1 (blocklist response), USP 2 (MITRE Engage) and USP 5 (ATT&CK Navigator layer)."""

from __future__ import annotations

import pytest

from conftest import console_headers, read_headers, web_event

WEB = "web-token-for-tests"
ATTACKER = "192.168.43.77"


@pytest.fixture
def web_token(tmp_path, monkeypatch):
    f = tmp_path / "web.token"
    f.write_text(WEB, encoding="ascii")
    monkeypatch.setenv("WEB_INGEST_TOKEN_FILE", str(f))
    return f


def det(rule, technique=None, confidence="high", category="decoy_interaction"):
    return {"rule": rule, "category": category, "label": rule.lower(), "confidence": confidence, "field": "path",
            "rationale": "test", "owasp": "A07:2021-Identification and Authentication Failures",
            "attack": [{"technique": technique, "status": "candidate", "confidence": confidence}] if technique else []}


def decoy_login(**kw):
    return web_event(source_ip=ATTACKER, event_type="authentication", action="login_attempt", outcome="succeeded",
                     request_path="/login", http_method="POST", http_status=302, username="j.miller",
                     raw_evidence_redacted={"detections": [det("W-AUTH-04", "T1078")]}, **kw)


def post(client, events):
    r = client.post("/api/events", json=events, headers={"Authorization": f"Bearer {WEB}"})
    assert r.status_code == 200, r.text


# ---- USP 1 ------------------------------------------------------------------------------------

def test_decoy_login_auto_blocks_the_source(client, web_token):
    post(client, [decoy_login()])
    b = client.get("/api/v2/blocklist", headers=read_headers()).json()
    assert [x["ip"] for x in b["active"]] == [ATTACKER]
    assert b["active"][0]["actor"] == "auto" and b["active"][0]["rule"] == "W-AUTH-04" and b["active"][0]["alert_id"]
    assert b["history"][0]["action"] == "block"
    assert b["engage"][0]["activity"] == "Security Controls" and b["engage"][0]["goal"] == "Affect"


def test_ordinary_detections_do_not_auto_block(client, web_token):
    post(client, [web_event(source_ip="192.168.43.80", raw_evidence_redacted={"detections": [det("W-SQLI-01", "T1190", "medium", "probe_detected")]})])
    assert client.get("/api/v2/blocklist", headers=read_headers()).json()["active"] == []


def test_auto_block_rules_are_configurable(client, web_token, monkeypatch):
    monkeypatch.setenv("AUTO_BLOCK_RULES", "W-SQLI-01")
    post(client, [decoy_login()])
    assert client.get("/api/v2/blocklist", headers=read_headers()).json()["active"] == []
    post(client, [web_event(source_ip="192.168.43.81", raw_evidence_redacted={"detections": [det("W-SQLI-01", "T1190", "medium", "probe_detected")]})])
    assert [x["ip"] for x in client.get("/api/v2/blocklist", headers=read_headers()).json()["active"]] == ["192.168.43.81"]


def test_feed_requires_the_web_token_and_lists_ips(client, web_token):
    post(client, [decoy_login()])
    assert client.post("/api/blocklist/feed").status_code == 401
    assert client.post("/api/blocklist/feed", headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/api/blocklist/feed", headers=read_headers()).status_code == 401  # read token is not enough
    feed = client.post("/api/blocklist/feed", headers={"Authorization": f"Bearer {WEB}"}).json()
    assert feed["ips"] == [ATTACKER] and feed["count"] == 1


def test_feed_unavailable_without_web_token_configured(client, monkeypatch):
    monkeypatch.delenv("WEB_INGEST_TOKEN_FILE", raising=False)
    assert client.post("/api/blocklist/feed", headers={"Authorization": f"Bearer {WEB}"}).status_code == 503


def test_blocklist_read_needs_read_token(client, web_token):
    assert client.get("/api/v2/blocklist").status_code == 401


def test_analyst_block_and_unblock(client, web_token):
    body = {"ip": "192.168.43.90", "actor": "analyst", "reason": "manual"}
    assert client.post("/api/v2/analyst/block", json=body).status_code == 401                 # no console token
    assert client.post("/api/v2/analyst/block", json=body, headers=read_headers()).status_code == 401
    r = client.post("/api/v2/analyst/block", json=body, headers=console_headers())
    assert r.status_code == 200 and r.json()["actor"] == "analyst"
    assert "192.168.43.90" in client.post("/api/blocklist/feed", headers={"Authorization": f"Bearer {WEB}"}).json()["ips"]
    r = client.post("/api/v2/analyst/unblock", json=body, headers=console_headers())
    assert r.status_code == 200
    assert client.post("/api/v2/analyst/unblock", json=body, headers=console_headers()).status_code == 404
    hist = client.get("/api/v2/blocklist", headers=read_headers()).json()["history"]
    assert [h["action"] for h in hist][:2] == ["unblock", "block"]


@pytest.mark.parametrize("ip", ["not-an-ip", "1.2.3.4; DROP TABLE", "", "999.1.1.1"])
def test_block_rejects_garbage(client, web_token, ip):
    r = client.post("/api/v2/analyst/block", json={"ip": ip, "actor": "a", "reason": "r"}, headers=console_headers())
    assert r.status_code == 422


def test_blocks_expire(client, web_token, monkeypatch):
    import collector.app as module
    module.store.add_block("192.168.43.91", actor="t", reason="r", ttl_s=60)
    with module.store.lock, module.store.db:
        module.store.db.execute("UPDATE blocklist SET expires_at = '2000-01-01T00:00:00Z' WHERE ip = '192.168.43.91'")
    assert "192.168.43.91" not in client.post("/api/blocklist/feed", headers={"Authorization": f"Bearer {WEB}"}).json()["ips"]


def test_alert_detail_shows_block_state_and_engage(client, web_token):
    post(client, [decoy_login()])
    alerts = client.get("/api/v2/alerts", headers=read_headers()).json()["items"]
    aid = next(a["alert_id"] for a in alerts if a["rule"] == "W-AUTH-04")
    d = client.get(f"/api/v2/alerts/{aid}", headers=read_headers()).json()
    assert d["block"]["ip"] == ATTACKER
    assert {e["activity"] for e in d["engage"]} == {"Decoy Credential", "Decoy Account"}
    assert d["engage_matrix"].startswith("https://engage.mitre.org")


# ---- USP 2 ------------------------------------------------------------------------------------

def test_event_detections_carry_engage(client, web_token):
    ev = decoy_login()
    post(client, [ev])
    d = client.get(f"/api/v2/events/{ev['event_id']}", headers=read_headers()).json()
    eng = d["detections"][0]["engage"]
    assert eng[0]["activity"] == "Decoy Credential" and eng[0]["goal"] == "Expose" and eng[0]["description"]


def test_every_web_rule_has_an_engage_activity():
    from collector import engage, rules_catalog
    for rid, entry in rules_catalog.RULES.items():
        if entry["service"] == "web":
            assert engage.for_rule(rid), rid
    for acts in engage.RULE_ACTIVITIES.values():
        for a, goal, approach in acts:
            assert a in engage.ACTIVITIES and goal in ("Expose", "Affect", "Elicit")
            assert approach in ("Collect", "Detect", "Prevent", "Direct", "Disrupt", "Reassure", "Motivate")


# ---- USP 5 ------------------------------------------------------------------------------------

def test_navigator_layer_format(client, web_token):
    post(client, [decoy_login(), web_event(source_ip="192.168.43.82", raw_evidence_redacted={"detections": [det("W-SQLI-01", "T1190", "medium", "probe_detected")]})])
    layer = client.get("/api/v2/navigator", headers=read_headers()).json()
    assert layer["domain"] == "enterprise-attack" and layer["versions"]["layer"] == "4.5"
    assert layer["versions"]["attack"] == "20"
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert {"T1078", "T1190"} <= ids
    t1078 = [t for t in layer["techniques"] if t["techniqueID"] == "T1078"]
    assert {t["tactic"] for t in t1078} >= {"initial-access"} and all(t["score"] == 1 for t in t1078)
    assert layer["gradient"]["maxValue"] >= 1


def test_navigator_needs_read_token(client):
    assert client.get("/api/v2/navigator").status_code == 401
