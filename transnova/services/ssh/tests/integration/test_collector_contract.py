"""The translator against the real collector code, in memory, with a temporary database.

Nothing here touches a running service. The shared collector and dashboard source files are
imported read-only. Fake markers are random and must never be shown. PYTEST_DONT_REWRITE turns
off pytest's assertion detail for this file, so a failure cannot print a marker.
"""

from __future__ import annotations

import importlib
import json
import os
import random
import secrets
import sys
import types
import typing
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

SSH_ROOT = Path(__file__).resolve().parents[2]
REPO = Path(__file__).resolve().parents[4]
for path in (str(REPO), str(SSH_ROOT / "sensor" / "src")):
    if path not in sys.path:
        sys.path.insert(0, path)

from collector.detections import ACTIONS, TITLES  # noqa: E402
from collector.schema import CanonicalEvent, EventType, Outcome, Service  # noqa: E402

from cowrie_soc import canonical  # noqa: E402
from cowrie_soc.canonical import source_address, translate, validate  # noqa: E402
from cowrie_soc.config import load_config  # noqa: E402
from cowrie_soc.detection import DetectionEngine  # noqa: E402
from cowrie_soc.normalize import NormalizeConfig, normalize  # noqa: E402
from cowrie_soc.parser import ParsedEvent, RawLine, parse_line  # noqa: E402
from cowrie_soc.redact import sanitize_event  # noqa: E402
from dataclasses import replace  # noqa: E402

from collector_support import auth, write_tokens  # noqa: E402

SENSOR = "ssh-01"
CAPTURE = SSH_ROOT / "sensor/tests/fixtures/real_capture_2026-10-31.json"
WEB_SAMPLE = REPO / "services/web/samples/web-attack-campaign.sample.jsonl"
TIMESTAMP = "2026-10-31T12:00:00.000Z"


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "collector.db"))
    ssh_token, read_token, settings = write_tokens(tmp_path)
    for name, value in settings.items():
        monkeypatch.setenv(name, value)
    import collector.app as module

    importlib.reload(module)
    test_client = TestClient(module.app, headers=auth(read_token))
    test_client.ssh_headers = auth(ssh_token)  # type: ignore[attr-defined]
    return test_client


def capture_events() -> list[dict[str, Any]]:
    cfg = load_config(SSH_ROOT / "sensor/config/collector.toml", env={})
    engine = DetectionEngine(cfg.detection, SENSOR, user_homes=cfg.user_homes)
    events = []
    for offset, line in enumerate(l for l in CAPTURE.read_text(encoding="utf-8").splitlines() if l.strip()):
        parsed = parse_line(RawLine(line.encode(), "cowrie.json", offset))
        assert isinstance(parsed, ParsedEvent)
        parsed = replace(parsed, event=sanitize_event(parsed.event))
        record = normalize(parsed, NormalizeConfig(SENSOR, include_passwords=False))
        findings = engine.process(record)
        session = engine.ctx.sessions.get(record["session_id"])
        events.append(translate(record, SENSOR, findings, session.username if session else None))
    return events


def post(client: TestClient, events: list[dict[str, Any]]) -> None:
    for i in range(0, len(events), 50):
        batch = events[i:i + 50]
        headers = client.ssh_headers if batch[0]["service"] == "ssh" else {}  # type: ignore[attr-defined]
        response = client.post("/api/events", json=batch, headers=headers)
        assert response.status_code == 200


def db_event(**change: Any) -> dict[str, Any]:
    return {"event_id": secrets.token_hex(8), "timestamp": TIMESTAMP, "sensor_id": "db-01", "service": "database",
            "source_ip": "172.28.0.51", "destination_service": "database-honeypot", "event_type": "sql_query",
            "action": "sensitive_access", "outcome": "succeeded", **change}


def ssh_event(source: Any, session: str, **change: Any) -> dict[str, Any]:
    event = capture_events()[0]
    event = {**event, "event_id": "00000000-0000-5000-8000-" + secrets.token_hex(6), "timestamp": TIMESTAMP,
             "session_id": session, "source_ip": source_address(source, session), **change}
    return event


# -- the schema, compared with the real model -----------------------------------------------

def test_field_names_and_order_match_the_real_model() -> None:
    assert canonical.FIELDS == tuple(CanonicalEvent.model_fields)
    assert len(canonical.FIELDS) == 26


def test_required_fields_match() -> None:
    required = {name for name, info in CanonicalEvent.model_fields.items() if info.is_required()}
    assert set(canonical.REQUIRED_TEXT) == required


def test_nullable_and_list_fields_match() -> None:
    fields = CanonicalEvent.model_fields
    nullable = {n for n, info in fields.items() if type(None) in typing.get_args(info.annotation)}
    assert nullable == (set(canonical.OPTIONAL_TEXT) | set(canonical.ALWAYS_NULL) | {"source_port"})
    assert typing.get_origin(fields["table_names"].annotation) is list
    assert typing.get_origin(fields["tags"].annotation) is list
    assert typing.get_origin(fields["raw_evidence_redacted"].annotation) is dict


def test_enum_values_match() -> None:
    assert canonical.ALLOWED_SERVICES == typing.get_args(Service)
    assert canonical.ALLOWED_EVENT_TYPES == typing.get_args(EventType)
    assert canonical.ALLOWED_OUTCOMES == typing.get_args(Outcome)


def collector_accepts(event: Any) -> bool:
    try:
        CanonicalEvent.model_validate(event)
    except (ValidationError, TypeError, ValueError):
        return False
    return True


BAD_VALUES = [None, "", "x", 0, 1, -1, 70000, 22.5, True, False, [], [1], ["x"], {}, {"a": 1}, {1: 2}, "2026-10-31T00:00:00",
              "2026-10-31T00:00:00+05:30", "2026-13-01T00:00:00Z", "SSH", "ssh", "web", "command", "observed", "Observed"]


def test_every_single_field_mutation_the_collector_rejects_is_rejected_locally() -> None:
    base = capture_events()[0]
    rejected = 0
    for field in canonical.FIELDS:
        for value in BAD_VALUES:
            mutated = {**base, field: value}
            if not collector_accepts(mutated):
                rejected += 1
                assert validate(mutated, SENSOR) is not None
    assert rejected > 100


def test_random_mutations_the_collector_rejects_are_rejected_locally() -> None:
    base = capture_events()
    generator = random.Random(20261101)
    rejected = 0
    for _ in range(3000):
        mutated = dict(generator.choice(base))
        for _ in range(generator.randint(1, 4)):
            choice = generator.random()
            if choice < 0.15:
                mutated.pop(generator.choice(list(mutated)), None)
            elif choice < 0.3:
                mutated[secrets.token_hex(3)] = 1
            else:
                mutated[generator.choice(canonical.FIELDS)] = generator.choice(BAD_VALUES)
        if not collector_accepts(mutated):
            rejected += 1
            assert validate(mutated, SENSOR) is not None
    assert rejected > 1000


def test_local_validator_only_passes_events_the_collector_accepts() -> None:
    for event in capture_events():
        assert validate(event, SENSOR) is None and collector_accepts(event)


# -- real collector behaviour ------------------------------------------------------------------

def test_every_captured_event_is_accepted_and_stored(client: TestClient) -> None:
    events = capture_events()
    post(client, events)
    assert client.get("/health").json()["events_stored"] == 104 == len(events)


def test_alerts_keep_their_techniques(client: TestClient) -> None:
    post(client, capture_events())
    alerts = [a for a in client.get("/api/alerts").json() if a["rule"].startswith("SSH-")]
    assert {a["rule"] for a in alerts} == {"SSH-BRUTE-001", "SSH-AUTH-002", "SSH-EXEC-001", "SSH-DISC-001", "SSH-CRED-001",
                                           "SSH-TOOL-001", "SSH-SEQ-001"}
    assert all(a["attack_ids"] for a in alerts)
    assert all(a["title"] == TITLES[a["rule"]] and a["recommended_action"] == ACTIONS[a["rule"]] for a in alerts)


def test_download_alert_shows_only_an_attempt(client: TestClient) -> None:
    post(client, capture_events())
    tool = next(a for a in client.get("/api/alerts").json() if a["rule"] == "SSH-TOOL-001")
    assert {x["status"] for x in tool["attack"]} == {"attempted"}


def test_resending_creates_no_duplicates(client: TestClient) -> None:
    events = capture_events()
    post(client, events)
    counts = {a["rule"]: a["event_count"] for a in client.get("/api/alerts").json()}
    post(client, events)
    assert client.get("/health").json()["events_stored"] == 104
    assert {a["rule"]: a["event_count"] for a in client.get("/api/alerts").json()} == counts


def test_marker_never_reaches_collector_alert_text(client: TestClient) -> None:
    secret = "X" + secrets.token_hex(16)
    record = normalize(replace(parse_line(RawLine(json.dumps({
        "eventid": "cowrie.command.input", "timestamp": "2026-10-31T12:00:00.000000Z", "session": "abc123",
        "src_ip": "10.0.0.9", "input": "id"}).encode(), "cowrie.json", 0)), raw_sha256="a" * 64),
        NormalizeConfig(SENSOR, include_passwords=False))
    dirty = {"rule_id": "SSH-CRED-001", "finding_id": "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee", "severity": "high",
             "confidence": "high", "title": secret, "explanation": secret, "rule_name": secret,
             "recommended_action": secret, "attack": [{"technique_id": "T1552.001", "name": secret, "tactic": secret}],
             "evidence": {"event_ids": [secret], "observed": {"command": secret, "username": secret}}}
    post(client, [translate(record, SENSOR, [dirty])])
    alerts = client.get("/api/alerts").json()
    assert len(alerts) == 1 and secret not in json.dumps(alerts)
    assert secret not in json.dumps(client.get("/api/events").json())


def test_ssh_web_and_database_are_stored_together(client: TestClient) -> None:
    web = [json.loads(l) for l in WEB_SAMPLE.read_text(encoding="utf-8").splitlines() if l.strip()]
    post(client, web)
    web_alerts = {a["rule"]: a["event_count"] for a in client.get("/api/alerts").json()}
    post(client, [db_event()])
    post(client, capture_events())
    assert client.get("/health").json()["events_stored"] == len(web) + 1 + 104
    after = {a["rule"]: a["event_count"] for a in client.get("/api/alerts").json()}
    assert all(after[rule] == count for rule, count in web_alerts.items())
    assert client.get("/api/database/summary").json()["queries_captured"] == 1


def test_separate_attackers_do_not_correlate(client: TestClient) -> None:
    post(client, [db_event()])
    post(client, [ssh_event("172.31.77.50", "abc001")])
    assert "X-CORR-01" not in {a["rule"] for a in client.get("/api/alerts").json()}


# -- a missing source address ------------------------------------------------------------------

def test_shared_word_unknown_would_falsely_correlate(client: TestClient) -> None:
    """Why the session label exists: this is the collector's behaviour with a shared word."""
    post(client, [db_event(source_ip="unknown"), db_event(source_ip="unknown", service="web", sensor_id="web-01",
                                                          event_type="http_request")])
    assert "X-CORR-01" in {a["rule"] for a in client.get("/api/alerts").json()}


def test_missing_address_never_correlates_with_database_unknown(client: TestClient) -> None:
    post(client, [db_event(source_ip="unknown")])
    post(client, [ssh_event(None, "abc001"), ssh_event(None, "abc002")])
    assert "X-CORR-01" not in {a["rule"] for a in client.get("/api/alerts").json()}


def test_two_sessions_with_no_address_are_separate_sources(client: TestClient) -> None:
    post(client, [ssh_event(None, "abc001"), ssh_event(None, "abc002"), ssh_event(None, "abc001")])
    sources = {a["source_ip"]: a for a in client.get("/api/attackers").json()}
    assert set(sources) == {"unknown-ssh-abc001", "unknown-ssh-abc002"}
    assert sources["unknown-ssh-abc001"]["event_count"] == 2 and sources["unknown-ssh-abc002"]["event_count"] == 1


def test_missing_address_works_through_the_profile_route(client: TestClient) -> None:
    post(client, [ssh_event(None, "abc001")])
    response = client.get("/api/attackers/unknown-ssh-abc001")
    assert response.status_code == 200 and len(response.json()["timeline"]) == 1
    assert client.get("/api/events", params={"source_ip": "unknown-ssh-abc001"}).json()


def test_missing_address_passes_the_validator() -> None:
    assert validate(ssh_event(None, "abc001"), SENSOR) is None


def test_dashboard_renders_ssh_events_and_a_missing_address(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Runs the real dashboard source against the in-memory collector. No network is used."""
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    import httpx

    post(client, capture_events())
    post(client, [ssh_event(None, "abc001")])
    post(client, [db_event(source_ip="unknown")])

    def fake_get(url: str, params: Any = None, headers: Any = None, **_kwargs: Any) -> httpx.Response:
        path = url.split("127.0.0.1:8000", 1)[-1]
        response = client.get(path, params=params, headers=headers)
        return httpx.Response(response.status_code, content=response.content,
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.delenv("COLLECTOR_BASE_URL", raising=False)
    app = AppTest.from_file(str(REPO / "dashboard" / "app.py"), default_timeout=60)
    app.run()
    assert not app.exception
    assert not app.error
    picker = next(box for box in app.selectbox if box.label == "Timeline for source")
    assert {"unknown-ssh-abc001", "unknown"} <= set(picker.options)  # never merged into one row
    picker.set_value("unknown-ssh-abc001").run()
    assert not app.exception
