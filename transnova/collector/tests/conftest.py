from __future__ import annotations

import importlib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
READ, CONSOLE, SSH = "read-token-for-tests", "console-token-for-tests", "ssh-token-for-tests"


@pytest.fixture
def tokens(tmp_path, monkeypatch):
    files = {}
    for name, value in (("read", READ), ("console", CONSOLE), ("ssh", SSH)):
        f = tmp_path / f"{name}.token"
        f.write_text(value, encoding="ascii")
        files[name] = f
    monkeypatch.setenv("SOC_READ_TOKEN_FILE", str(files["read"]))
    monkeypatch.setenv("SOC_CONSOLE_TOKEN_FILE", str(files["console"]))
    monkeypatch.setenv("SSH_INGEST_TOKEN_FILE", str(files["ssh"]))
    return files


@pytest.fixture
def app(tmp_path, monkeypatch, tokens):
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    import collector.app as module
    importlib.reload(module)
    return module


@pytest.fixture
def client(app):
    return TestClient(app.app)


def read_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {READ}"}


def console_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {CONSOLE}"}


def stamp(seconds_ago: float = 0) -> str:
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def web_event(**kw: Any) -> dict[str, Any]:
    base = {"event_id": str(uuid.uuid4()), "timestamp": stamp(), "sensor_id": "web-01", "service": "web",
            "source_ip": "172.28.0.50", "source_port": 40000, "destination_service": "web-decoy",
            "event_type": "http_request", "action": "page_view", "outcome": "observed", "request_path": "/",
            "http_method": "GET", "http_status": 200, "raw_evidence_redacted": {}, "tags": []}
    return {**base, **kw}


def failed_web_login(**kw: Any) -> dict[str, Any]:
    return web_event(**{"username": "alice", **kw}, event_type="authentication", action="login_attempt", outcome="failed",
                     request_path="/login", http_method="POST", http_status=401,
                     raw_evidence_redacted={"detections": [{
                         "rule": "W-AUTH-01", "category": "behavior_detected", "label": "auth:failed",
                         "owasp": "A07:2021-Identification and Authentication Failures", "confidence": "low",
                         "field": "form.username", "rationale": "login rejected", "attack": []}]})
