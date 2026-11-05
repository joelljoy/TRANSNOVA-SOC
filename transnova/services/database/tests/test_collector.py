"""Collector tests, including real web decoy sample events (proof of the shared contract)."""

from __future__ import annotations

import importlib
import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    import collector.app as module
    importlib.reload(module)
    return TestClient(module.app)


def db_event(**kw):
    base = {"event_id": str(uuid.uuid4()), "timestamp": "2026-10-31T12:00:00.000Z", "sensor_id": "db-01",
            "service": "database", "source_ip": "172.28.0.51", "destination_service": "database-honeypot",
            "event_type": "sql_query", "action": "sensitive_access", "outcome": "succeeded", "session_id": "s1",
            "command": "SELECT * FROM api_credentials", "table_names": ["api_credentials"],
            "raw_evidence_redacted": {"severity": "HIGH", "detections": [
                {"rule": "D-SENS-01", "severity": "HIGH", "confidence": "high", "rationale": "because",
                 "attack": [{"technique": "T1552", "name": "Unsecured Credentials", "status": "observed"}]}]}}
    return {**base, **kw}


def test_web_decoy_samples_ingest_unchanged(client):
    lines = (ROOT / "services/web/samples/web-attack-campaign.sample.jsonl").read_text(encoding="utf-8").splitlines()
    events = [json.loads(ln) for ln in lines if ln.strip()]
    for i in range(0, len(events), 50):
        assert client.post("/api/events", json=events[i:i + 50]).status_code == 200
    assert client.get("/health").json()["events_stored"] == len(events)
    assert client.get("/api/alerts").json()  # web detections became alerts


def test_resend_is_deduplicated(client):
    e = db_event()
    client.post("/api/events", json=[e])
    assert client.post("/api/events", json=[e]).json() == {"received": 1, "stored": 0, "duplicates": 1}
    assert client.get("/api/alerts").json()[0]["event_count"] == 1


def test_repeat_rule_updates_one_alert(client):
    client.post("/api/events", json=[db_event(), db_event()])
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1 and alerts[0]["event_count"] == 2 and alerts[0]["attack_ids"] == ["T1552"]


def test_extra_field_is_rejected(client):
    assert client.post("/api/events", json=[db_event(hacker=1)]).status_code == 422


def test_oversize_batch_is_rejected(client):
    assert client.post("/api/events", json=[db_event() for _ in range(51)]).status_code == 413


def test_cross_service_source_raises_correlation_alert(client):
    client.post("/api/events", json=[db_event(), db_event(service="web", sensor_id="web-01", event_type="http_request",
                                                          raw_evidence_redacted={})])
    rules = {a["rule"] for a in client.get("/api/alerts").json()}
    assert "X-CORR-01" in rules


def test_followup_requires_a_successful_read_of_the_asset(client):
    record = {"adaptation_id": "a1", "timestamp": "2026-10-31T12:00:00.000Z", "sensor_id": "db-01", "service": "database",
              "rule_id": "B", "stage": 1, "trigger_event_id": "e", "trigger_reason": "r", "adaptation_type": "t",
              "asset_revealed": "backup_credentials", "source_ip": "x", "tracker_key": "k", "target_account": "d@%",
              "status": "applied"}
    client.post("/api/adaptations", json=[record])
    assert client.get("/api/adaptations").json()[0]["followup_event_ids"] == []
    denied = db_event(table_names=["backup_credentials"], outcome="blocked")
    client.post("/api/events", json=[denied])
    assert client.get("/api/adaptations").json()[0]["followup_event_ids"] == []
    good = db_event(table_names=["backup_credentials"])
    client.post("/api/events", json=[good])
    assert client.get("/api/adaptations").json()[0]["followup_event_ids"] == [good["event_id"]]


def test_empty_state_is_valid(client):
    assert client.get("/api/database/summary").json()["queries_captured"] == 0
    assert client.get("/api/attackers").json() == []
    assert client.get("/api/adaptations").json() == []
