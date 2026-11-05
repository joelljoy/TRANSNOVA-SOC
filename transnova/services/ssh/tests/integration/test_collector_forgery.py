"""Nobody without the SSH token can speak as the SSH honeypot, on any route, in any spelling.

Runs the real collector in memory with a temporary database. Tokens are random and never shown.
PYTEST_DONT_REWRITE turns off pytest's assertion detail, so a failure cannot print one.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from collector_support import TIMESTAMP, web_event, write_tokens

EVENTS, HEARTBEAT, ADAPTATIONS = "/api/events", "/api/sensors/heartbeat", "/api/adaptations"
ZERO_WIDTH = "​"


def variants(word: str) -> list[str]:
    fullwidth = "".join(chr(ord(c) + 0xfee0) if "!" <= c <= "~" else c for c in word)
    return [word, word.upper(), word.title(), f" {word}", f"{word} ", word.replace("-", "_"), word.replace("-", ""),
            word.replace("s", f"s{ZERO_WIDTH}", 1), fullwidth]


@pytest.fixture
def module(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    for name, value in write_tokens(tmp_path)[2].items():
        monkeypatch.setenv(name, value)
    import collector.app as loaded

    importlib.reload(loaded)
    return loaded


@pytest.fixture
def client(module: Any) -> TestClient:
    return TestClient(module.app)


def nothing_from_ssh(module: Any) -> bool:
    store = module.store
    return (not any(e["service"] == "ssh" or e["sensor_id"].lower().startswith("ssh") for e in store.events(1000))
            and not any(a["rule"].lower().startswith("ssh") or a["service"] == "ssh" for a in store.alerts(1000))
            and not any(s["service"] == "ssh" or s["sensor_id"].lower().startswith("ssh") for s in store.sensors())
            and not store.adaptations(1000))


def refused_and_clean(module: Any, client: TestClient, path: str, body: Any, status: int = 401) -> None:
    assert client.post(path, json=body).status_code == status
    assert module.store.count_events() == 0
    assert nothing_from_ssh(module)


def detection(**change: Any) -> dict[str, Any]:
    return {"raw_evidence_redacted": {"detections": [{"rule": "W-X", "severity": "critical", **change}]}}


CLAIMS = [
    pytest.param({"service": "ssh"}, id="service"),
    pytest.param({"sensor_id": "ssh-01"}, id="sensor"),
    pytest.param({"sensor_id": "cowrie-1"}, id="sensor_cowrie"),
    pytest.param({"destination_service": "ssh-honeypot"}, id="destination"),
    pytest.param({"destination_service": "my ssh honeypot"}, id="destination_inside"),
    pytest.param({"tags": ["ok", "ssh:x"]}, id="tag"),
    pytest.param(detection(rule="SSH-SEQ-001"), id="rule"),
    pytest.param(detection(label="ssh:x"), id="label"),
]


@pytest.mark.parametrize("claim", CLAIMS)
def test_every_claim_is_refused(module: Any, client: TestClient, claim: dict[str, Any]) -> None:
    refused_and_clean(module, client, EVENTS, [web_event(**claim)])
    refused_and_clean(module, client, EVENTS, web_event(**claim))  # a single object behaves the same


@pytest.mark.parametrize("field,word", [("service", "ssh"), ("sensor_id", "ssh-01"), ("destination_service", "ssh-honeypot")])
def test_spelling_variants_are_refused(module: Any, client: TestClient, field: str, word: str) -> None:
    for spelling in variants(word):
        refused_and_clean(module, client, EVENTS, [web_event(**{field: spelling})])


def test_tag_and_rule_variants_are_refused(module: Any, client: TestClient) -> None:
    for spelling in variants("ssh-x"):
        refused_and_clean(module, client, EVENTS, [web_event(tags=[spelling])])
        refused_and_clean(module, client, EVENTS, [web_event(**detection(rule=spelling))])
        refused_and_clean(module, client, EVENTS, [web_event(**detection(label=spelling))])


@pytest.mark.parametrize("rule", [["SSH-SEQ-001"], {"a": "SSH-SEQ-001"}, ("SSH-SEQ-001",)])
def test_a_rule_hidden_in_a_container_is_refused(module: Any, client: TestClient, rule: Any) -> None:
    refused_and_clean(module, client, EVENTS, [web_event(**detection(rule=rule))])


def test_a_critical_ssh_alert_cannot_be_forged_from_a_web_event(module: Any, client: TestClient) -> None:
    refused_and_clean(module, client, EVENTS, [web_event(**detection(rule="SSH-SEQ-001"))])
    assert module.store.alerts(10) == []


@pytest.mark.parametrize("first", [True, False])
def test_one_ssh_event_refuses_the_whole_batch(module: Any, client: TestClient, first: bool) -> None:
    good = [web_event() for _ in range(49)]
    batch = [web_event(service="ssh"), *good] if first else [*good, web_event(service="ssh")]
    refused_and_clean(module, client, EVENTS, batch)


def test_duplicate_json_key_cannot_hide_a_claim(module: Any, client: TestClient) -> None:
    body = json.dumps([web_event()]).replace('"service": "web"', '"service": "web", "service": "ssh"')
    assert client.post(EVENTS, content=body, headers={"content-type": "application/json"}).status_code == 401
    assert module.store.count_events() == 0


@pytest.mark.parametrize("item", [None, 1, "ssh", [], ["ssh"], True])
def test_non_object_items_store_nothing(module: Any, client: TestClient, item: Any) -> None:
    assert client.post(EVENTS, json=[item]).status_code == 422
    assert module.store.count_events() == 0


def test_a_malformed_claim_is_refused_before_the_schema_runs(module: Any, client: TestClient) -> None:
    refused_and_clean(module, client, EVENTS, [{"service": "ssh"}])
    refused_and_clean(module, client, EVENTS, [web_event(service="ssh", hacker=1)])


@pytest.mark.parametrize("value", [None, 1, ["ssh"], {"a": "ssh"}])
def test_wrong_types_in_marker_fields_do_not_crash(module: Any, client: TestClient, value: Any) -> None:
    for field in ("service", "sensor_id", "destination_service", "tags", "raw_evidence_redacted"):
        assert client.post(EVENTS, json=[web_event(**{field: value})]).status_code in (200, 401, 422)
    assert nothing_from_ssh(module)


def test_not_json_and_wrong_content_type_store_nothing(module: Any, client: TestClient) -> None:
    assert client.post(EVENTS, content=b"not json", headers={"content-type": "application/json"}).status_code in (400, 422)
    assert client.post(EVENTS, content=json.dumps([web_event()]), headers={"content-type": "text/plain"}).status_code == 422
    assert module.store.count_events() == 0


def beat(**change: Any) -> dict[str, Any]:
    return {"sensor_id": "web-01", "service": "web", "status": "ok", **change}


@pytest.mark.parametrize("change", [{"service": "ssh"}, {"sensor_id": "ssh-01"}, {"sensor_id": "SSH_01"}, {"sensor_id": "cowrie"},
                                    {"service": "ssh", "extra": 1}, {"service": "SSH"}])
def test_a_heartbeat_cannot_claim_ssh(module: Any, client: TestClient, change: dict[str, Any]) -> None:
    refused_and_clean(module, client, HEARTBEAT, beat(**change))


def adaptation(**change: Any) -> dict[str, Any]:
    return {"adaptation_id": "a", "timestamp": TIMESTAMP, "sensor_id": "db-01", "service": "database", "rule_id": "B", "stage": 1,
            "trigger_event_id": "e", "trigger_reason": "r", "adaptation_type": "t", "asset_revealed": "a", "source_ip": "x",
            "tracker_key": "k", "target_account": "d", "status": "applied", **change}


@pytest.mark.parametrize("change", [{"service": "ssh"}, {"sensor_id": "ssh-01"}, {"rule_id": "SSH-X"}, {"rule_id": "ssh_x"}])
def test_an_adaptation_cannot_claim_ssh(module: Any, client: TestClient, change: dict[str, Any]) -> None:
    refused_and_clean(module, client, ADAPTATIONS, [adaptation(**change)], status=403)


def test_a_forged_session_label_on_a_database_event_stays_a_database_event(module: Any, client: TestClient) -> None:
    """An audit line can set this value. A refusal would stall the Database sender forever."""
    event = web_event(service="database", sensor_id="db-01", destination_service="database-honeypot", event_type="sql_query",
                      source_ip="unknown-ssh-1")
    assert client.post(EVENTS, json=[event]).status_code == 200
    assert client.post(EVENTS, json=[web_event(source_ip="unknown-ssh-1")]).status_code == 200
    assert module.store.count_events() == 2
    assert "X-CORR-01" not in {a["rule"] for a in module.store.alerts(10)}


def test_correlation_still_fires_on_a_real_shared_address(module: Any, client: TestClient) -> None:
    event = web_event(service="database", sensor_id="db-01", destination_service="database-honeypot", event_type="sql_query")
    client.post(EVENTS, json=[event, web_event()])
    assert "X-CORR-01" in {a["rule"] for a in module.store.alerts(10)}


def test_web_and_database_identity_words_near_ssh_are_not_markers(module: Any, client: TestClient) -> None:
    """Attacker text in free fields is evidence, not identity."""
    event = web_event(request_path="/.ssh/id_rsa", user_agent="ssh-01", command="ssh root@host", username="ssh",
                      session_id="ssh-01", file_name="ssh-honeypot", table_names=["ssh_keys"], database_name="ssh",
                      action="ssh", raw_evidence_redacted={"note": "ssh-01", "path": "/.ssh/"})
    assert client.post(EVENTS, json=[event]).status_code == 200
    assert module.store.count_events() == 1
