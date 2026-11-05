"""Console backend against a real collector app: sign-in auditing, sessions, CSRF, proxying, XAI fallback."""

from __future__ import annotations

import importlib
import uuid
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from console import config, users
from console.app import create_app

PASSWORD = "correct horse battery"


@pytest.fixture
def stack(tmp_path, monkeypatch):
    for name, value in (("read", "read-token-xyz"), ("console", "console-token-xyz"), ("ssh", "ssh-token-xyz")):
        (tmp_path / f"{name}.token").write_text(value, encoding="ascii")
    monkeypatch.setenv("SOC_READ_TOKEN_FILE", str(tmp_path / "read.token"))
    monkeypatch.setenv("SOC_CONSOLE_TOKEN_FILE", str(tmp_path / "console.token"))
    monkeypatch.setenv("SSH_INGEST_TOKEN_FILE", str(tmp_path / "ssh.token"))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    import collector.app as collector
    importlib.reload(collector)
    users_file = tmp_path / "users.txt"
    users_file.write_text(f"analyst:analyst:{users.hash_password(PASSWORD)}\nwatcher:viewer:{users.hash_password(PASSWORD)}\n",
                          encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>TransNova SOC</title>", encoding="utf-8")
    monkeypatch.setenv("COLLECTOR_BASE_URL", "http://collector")
    monkeypatch.setenv("SOC_USERS_FILE", str(users_file))
    monkeypatch.setenv("SOC_FRONTEND_DIR", str(dist))
    app = create_app(config.load(), transport=httpx.ASGITransport(app=collector.app, client=("172.30.0.30", 1234)))
    client = TestClient(app, client=("127.0.0.1", 50123))
    return client, collector


def login(client, username="analyst", password=PASSWORD):
    return client.post("/api/auth/login", json={"username": username, "password": password})


def auth_events(client):
    r = client.get("/api/data/events", params={"service": "soc", "order": "asc"})
    assert r.status_code == 200, r.text
    return r.json()["items"]


def test_missing_config_fails_by_name_only(monkeypatch):
    monkeypatch.setenv("COLLECTOR_BASE_URL", "http://x")
    monkeypatch.setenv("SOC_READ_TOKEN_FILE", "/nope")
    with pytest.raises(config.ConfigError) as err:
        config.load()
    assert "SOC_READ_TOKEN_FILE" in str(err.value) and "/nope" not in str(err.value)


def test_successful_login_is_recorded_and_visible(stack):
    client, _ = stack
    r = login(client)
    assert r.status_code == 200 and r.json()["role"] == "analyst" and r.json()["csrf"]
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    [event] = auth_events(client)
    assert (event["service"], event["action"], event["outcome"], event["username"]) == ("soc", "login", "succeeded", "analyst")
    assert event["source_ip"] == "127.0.0.1" and event["timestamp"].endswith("Z")
    assert event["detection_status"] == "observed"


def test_wrong_password_is_recorded_not_alerted_and_never_stored(stack):
    client, collector = stack
    assert login(client, password="wrong-password-123").status_code == 401
    assert login(client).status_code == 200
    failed = [e for e in auth_events(client) if e["outcome"] == "failed"]
    assert len(failed) == 1 and failed[0]["detection_status"] == "matched" and failed[0]["rules"] == ["SOC-AUTH-00"]
    assert client.get("/api/data/alerts").json()["total"] == 0
    raw = Path(collector.store.db.execute("PRAGMA database_list").fetchone()[2]).read_bytes()
    assert b"wrong-password-123" not in raw and PASSWORD.encode() not in raw
    assert b"scrypt$" not in raw


def test_repeated_failures_raise_the_documented_alert_only_at_threshold(stack):
    client, _ = stack
    for i in range(4):
        login(client, password=f"bad-{i}-password")
    login(client)
    assert client.get("/api/data/alerts").json()["total"] == 0
    client.post("/api/auth/logout", headers={"x-csrf-token": client.get("/api/auth/me").json()["csrf"]})
    login(client, password="bad-5-password")
    login(client)
    [alert] = client.get("/api/data/alerts").json()["items"]
    assert alert["rule"] == "SOC-AUTH-01" and alert["severity"] == "medium" and alert["source_ip"] == "127.0.0.1"
    detail = client.get(f"/api/data/alerts/{alert['alert_id']}").json()
    assert len([e for e in detail["events"] if e["outcome"] == "failed"]) == 5


def test_unknown_user_and_wrong_password_look_the_same(stack):
    client, _ = stack
    a, b = login(client, "nobody"), login(client, password="wrong-password")
    assert a.status_code == b.status_code == 401 and a.json() == b.json()


def test_rate_limit_after_ten_failures_is_audited(stack):
    client, _ = stack
    for i in range(10):
        login(client, password=f"bad{i}xxxxxxx")
    assert login(client).status_code == 429  # even the right password, until the window passes
    other = TestClient(client.app, client=("127.0.0.2", 1))
    assert login(other).status_code == 200  # another source is unaffected
    blocked = [e for e in auth_events(other) if e["action"] == "login_rate_limited"]
    assert len(blocked) == 1 and blocked[0]["outcome"] == "blocked" and blocked[0]["source_ip"] == "127.0.0.1"


def test_logout_and_reads_need_a_session(stack):
    client, _ = stack
    assert client.get("/api/data/summary").status_code == 401
    login(client)
    me = client.get("/api/auth/me").json()
    assert client.post("/api/auth/logout").status_code == 403  # no CSRF header
    assert client.post("/api/auth/logout", headers={"x-csrf-token": me["csrf"]}).status_code == 200
    assert client.get("/api/data/summary").status_code == 401
    login(client)
    assert [e["action"] for e in auth_events(client)] == ["login", "logout", "login"]


def test_session_expiry_is_recorded(stack):
    client, _ = stack
    login(client)
    for sess in client.app.state.sessions.values():
        sess.seen -= 3600
    assert client.get("/api/data/summary").status_code == 401
    login(client)
    assert "session_expired" in [e["action"] for e in auth_events(client)]


def test_only_allowlisted_reads_are_proxied(stack):
    client, _ = stack
    login(client)
    assert client.get("/api/data/summary").status_code == 200
    assert client.get("/api/data/../health").status_code in (404, 200) and client.get("/api/data/health").status_code == 404
    assert client.get("/api/data/analyst/alert-status").status_code == 404


def test_writes_need_csrf_and_a_writing_role(stack):
    client, collector = stack
    event = {"event_id": str(uuid.uuid4()), "timestamp": "2026-11-01T10:00:00.000Z", "sensor_id": "web-01", "service": "web",
             "source_ip": "172.28.0.50", "destination_service": "web-decoy", "event_type": "http_request",
             "action": "page_view", "outcome": "observed"}
    TestClient(collector.app).post("/api/events", json=[event])
    body = {"classification": "benign", "reason": "my own browser"}
    csrf = login(client).json()["csrf"]
    assert client.post(f"/api/events/{event['event_id']}/classification", json=body).status_code == 403
    r = client.post(f"/api/events/{event['event_id']}/classification", json=body, headers={"x-csrf-token": csrf})
    assert r.status_code == 200 and r.json()["actor"] == "analyst"
    viewer = TestClient(client.app, client=("127.0.0.9", 1))
    vcsrf = login(viewer, "watcher").json()["csrf"]
    assert viewer.post(f"/api/events/{event['event_id']}/classification", json=body,
                       headers={"x-csrf-token": vcsrf}).status_code == 403


def test_cross_origin_login_is_refused(stack):
    client, _ = stack
    r = client.post("/api/auth/login", json={"username": "analyst", "password": PASSWORD},
                    headers={"origin": "http://evil.example"})
    assert r.status_code == 403


def test_xai_without_key_says_unavailable_and_invents_nothing(stack):
    client, collector = stack
    event = {"event_id": str(uuid.uuid4()), "timestamp": "2026-11-01T10:00:00.000Z", "sensor_id": "db-01",
             "service": "database", "source_ip": "172.28.0.51", "destination_service": "database-honeypot",
             "event_type": "sql_query", "action": "sensitive_access", "outcome": "succeeded",
             "raw_evidence_redacted": {"detections": [{"rule": "D-SENS-01", "severity": "HIGH", "confidence": "high",
                                                       "rationale": "r", "attack": []}]}}
    TestClient(collector.app).post("/api/events", json=[event])
    csrf = login(client).json()["csrf"]
    [alert] = client.get("/api/data/alerts").json()["items"]
    r = client.post(f"/api/alerts/{alert['alert_id']}/explain", headers={"x-csrf-token": csrf})
    assert r.status_code == 503 and r.json()["available"] is False and "not configured" in r.json()["detail"]
    detail = client.get(f"/api/data/alerts/{alert['alert_id']}").json()
    assert detail["explanations"] == [] and detail["events"][0]["event_id"] == event["event_id"]


def test_collector_down_is_reported_not_hidden(stack, monkeypatch):
    client, _ = stack
    login(client)
    client.app.state.audit_queue.clear()

    async def boom(*a, **k):
        raise httpx.ConnectError("down")

    monkeypatch.setattr(httpx.AsyncClient, "request", boom)
    r = client.get("/api/data/summary")
    assert r.status_code == 502 and r.json()["detail"] == "collector unavailable"


def test_frontend_is_served_with_security_headers(stack):
    client, _ = stack
    r = client.get("/alerts/abc")
    assert r.status_code == 200 and "TransNova SOC" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert client.get("/api/nothing").status_code == 404


def test_block_unblock_and_reads_through_the_console(stack):
    """USP 1 + 5 via the console: CSRF + writer role to block; blocklist and Navigator readable when signed in."""
    client, _ = stack
    assert client.get("/api/data/blocklist").status_code == 401           # not signed in
    csrf = login(client).json()["csrf"]
    body = {"ip": "192.168.43.77", "reason": "caught on the portal"}
    assert client.post("/api/blocks", json=body).status_code == 403        # no CSRF token
    r = client.post("/api/blocks", json=body, headers={"x-csrf-token": csrf})
    assert r.status_code == 200 and r.json()["actor"] == "analyst"         # actor is the signed-in user, not the body
    active = client.get("/api/data/blocklist").json()["active"]
    assert [b["ip"] for b in active] == ["192.168.43.77"]
    assert client.post("/api/blocks", json={**body, "ip": "1.2.3.4; x"}, headers={"x-csrf-token": csrf}).status_code == 422
    viewer = TestClient(client.app, client=("127.0.0.9", 1))
    vcsrf = login(viewer, "watcher").json()["csrf"]
    assert viewer.post("/api/blocks", json=body, headers={"x-csrf-token": vcsrf}).status_code == 403
    assert client.post("/api/blocks/remove", json=body, headers={"x-csrf-token": csrf}).status_code == 200
    assert client.get("/api/data/blocklist").json()["active"] == []
    layer = client.get("/api/data/navigator")
    assert layer.status_code == 200 and layer.json()["domain"] == "enterprise-attack"
