"""The SSH token: who it admits, what it refuses, and how a broken secret fails.

Runs the real collector in memory with a temporary database. Tokens are random and never shown.
PYTEST_DONT_REWRITE turns off pytest's assertion detail, so a failure cannot print one.
"""

from __future__ import annotations

import copy
import importlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from collector_support import auth, web_event, write_tokens
from test_collector_contract import capture_events

SSH_EVENT = "00000000-0000-5000-8000-"
EVENTS, HEARTBEAT = "/api/events", "/api/sensors/heartbeat"


class Lab:
    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch, client_address: str = "testclient") -> None:
        monkeypatch.setenv("COLLECTOR_DB_PATH", str(folder / "c.db"))
        self.ssh_token, self.read_token, self.settings = write_tokens(folder)
        for name, value in self.settings.items():
            monkeypatch.setenv(name, value)
        import collector.app as module

        importlib.reload(module)
        self.module = module
        self.client = TestClient(module.app, client=(client_address, 50000))
        self.headers = auth(self.ssh_token)

    def stored(self) -> int:
        return self.module.store.count_events()


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Lab:
    return Lab(tmp_path, monkeypatch)


def real_batch() -> list[dict[str, Any]]:
    return copy.deepcopy(capture_events()[:50])


def good_event() -> dict[str, Any]:
    return real_batch()[0]


# -- the token -----------------------------------------------------------------------------------

def test_valid_token_stores_real_events_and_alerts(lab: Lab) -> None:
    events = capture_events()
    for i in range(0, len(events), 50):
        assert lab.client.post(EVENTS, json=events[i:i + 50], headers=lab.headers).status_code == 200
    assert lab.stored() == 104
    assert len({a["rule"] for a in lab.module.store.alerts(100)}) == 7


def test_resending_with_a_token_adds_nothing(lab: Lab) -> None:
    batch = real_batch()
    lab.client.post(EVENTS, json=batch, headers=lab.headers)
    assert lab.client.post(EVENTS, json=batch, headers=lab.headers).json()["duplicates"] == 50


def test_missing_and_wrong_token_look_identical(lab: Lab) -> None:
    missing = lab.client.post(EVENTS, json=real_batch())
    wrong = lab.client.post(EVENTS, json=real_batch(), headers=auth("wrong"))
    assert missing.status_code == wrong.status_code == 401
    assert missing.content == wrong.content and lab.stored() == 0


def test_evidence_ids_join_the_alert(lab: Lab) -> None:
    events = capture_events()
    for i in range(0, len(events), 50):
        lab.client.post(EVENTS, json=events[i:i + 50], headers=lab.headers)
    known = {e["event_id"] for e in events}
    for alert in lab.module.store.alerts(100):
        assert set(alert["related_event_ids"]) <= known and len(alert["related_event_ids"]) <= 200
    ids = [i for a in lab.module.store.alerts(100) for i in a["related_event_ids"]]
    assert len(ids) > sum(a["event_count"] for a in lab.module.store.alerts(100) if a["rule"].startswith("SSH-"))


@pytest.mark.parametrize("make", [
    pytest.param(lambda: [web_event()], id="web_event"),
    pytest.param(lambda: [good_event(), web_event()], id="mixed"),
    pytest.param(lambda: [web_event(service="database", sensor_id="db-01")], id="database_event")])
def test_the_token_cannot_write_for_another_service(lab: Lab, make: Any) -> None:
    assert lab.client.post(EVENTS, json=make(), headers=lab.headers).status_code == 403
    assert lab.stored() == 0


def test_heartbeat_with_and_without_the_token(lab: Lab) -> None:
    beat = {"sensor_id": "ssh-01", "service": "ssh", "status": "ok", "details": {"events": 1}}
    assert lab.client.post(HEARTBEAT, json=beat).status_code == 401
    assert lab.client.post(HEARTBEAT, json=beat, headers=lab.headers).status_code == 200
    assert [s["sensor_id"] for s in lab.module.store.sensors()] == ["ssh-01"]
    web = {"sensor_id": "web-01", "service": "web", "status": "ok"}
    assert lab.client.post(HEARTBEAT, json=web, headers=lab.headers).status_code == 403
    secret = {"sensor_id": "ssh-01", "service": "ssh", "status": "ok", "details": {"password": "x"}}
    assert lab.client.post(HEARTBEAT, json=secret, headers=lab.headers).status_code == 422


def test_no_adaptation_is_accepted_with_the_token(lab: Lab) -> None:
    record = {"adaptation_id": "a", "timestamp": "t", "sensor_id": "db-01", "service": "database", "rule_id": "B", "stage": 1,
              "trigger_event_id": "e", "trigger_reason": "r", "adaptation_type": "t", "asset_revealed": "a", "source_ip": "x",
              "tracker_key": "k", "target_account": "d", "status": "applied"}
    assert lab.client.post("/api/adaptations", json=[record], headers=lab.headers).status_code == 403
    assert lab.module.store.adaptations(10) == []


def test_a_batch_over_fifty_is_refused(lab: Lab) -> None:
    assert lab.client.post(EVENTS, json=[good_event() for _ in range(51)], headers=lab.headers).status_code == 413


# -- strict checks -------------------------------------------------------------------------------

def changed(**change: Any) -> dict[str, Any]:
    return {**good_event(), **change}


def evidence(mutate: Any) -> dict[str, Any]:
    event = good_event()
    mutate(event["raw_evidence_redacted"])
    return event


def detection_event(**change: Any) -> dict[str, Any]:
    event = next(e for e in capture_events() if e["raw_evidence_redacted"]["detections"])
    event = copy.deepcopy(event)
    event["raw_evidence_redacted"]["detections"][0].update(change)
    return event


BROKEN = [
    pytest.param(lambda: changed(sensor_id="ssh-02"), id="other_sensor"),
    pytest.param(lambda: changed(service="web"), id="other_service"),
    pytest.param(lambda: changed(destination_service="other"), id="other_destination"),
    pytest.param(lambda: changed(event_id="abc"), id="event_id"),
    pytest.param(lambda: changed(timestamp="2026-10-31T12:00:00+00:00"), id="timestamp_offset"),
    pytest.param(lambda: changed(timestamp=1793000000), id="timestamp_number"),
    pytest.param(lambda: changed(session_id="NOT-HEX"), id="session"),
    pytest.param(lambda: changed(source_ip="nonsense"), id="source"),
    pytest.param(lambda: changed(source_ip="unknown-ssh-ffff"), id="label_for_another_session"),
    pytest.param(lambda: changed(source_port="22"), id="port_text"),
    pytest.param(lambda: changed(source_port=True), id="port_bool"),
    pytest.param(lambda: changed(source_port=70000), id="port_range"),
    pytest.param(lambda: changed(request_path="/x"), id="http_field"),
    pytest.param(lambda: changed(rows_returned=1), id="sql_field"),
    pytest.param(lambda: changed(table_names=["t"]), id="table_names"),
    pytest.param(lambda: changed(command="x" * 2049), id="long_command"),
    pytest.param(lambda: changed(username="x" * 257), id="long_username"),
    pytest.param(lambda: changed(tags=["other"]), id="tag_prefix"),
    pytest.param(lambda: changed(tags=["ssh:x"] * 17), id="too_many_tags"),
    pytest.param(lambda: changed(raw_evidence_redacted=[]), id="evidence_type"),
    pytest.param(lambda: changed(extra=1), id="extra_field"),
    pytest.param(lambda: {k: v for k, v in good_event().items() if k != "tags"}, id="missing_field"),
    pytest.param(lambda: evidence(lambda e: e.update(honeypot_type="web")), id="honeypot_type"),
    pytest.param(lambda: evidence(lambda e: e.update(padding="x" * 9000)), id="evidence_size"),
    pytest.param(lambda: evidence(lambda e: e.update(password="x")), id="password"),
    pytest.param(lambda: evidence(lambda e: e.update(PassWord="x")), id="password_case"),
    pytest.param(lambda: evidence(lambda e: e["details"].update(message="x")), id="message_nested"),
    pytest.param(lambda: evidence(lambda e: e["details"].update(ttylog="x")), id="ttylog_nested"),
    pytest.param(lambda: evidence(lambda e: e["details"].update(format="x")), id="format_outside_raw"),
    pytest.param(lambda: evidence(lambda e: e["details"].update(a=[{"password": "x"}])), id="password_in_list"),
    pytest.param(lambda: evidence(lambda e: e["raw"].update(format="other")), id="raw_format"),
    pytest.param(lambda: detection_event(rule="SSH-UNKNOWN-1"), id="unknown_rule"),
    pytest.param(lambda: detection_event(label="other"), id="wrong_label"),
    pytest.param(lambda: detection_event(severity="huge"), id="severity"),
    pytest.param(lambda: detection_event(confidence="huge"), id="confidence"),
    pytest.param(lambda: detection_event(rationale="x" * 257), id="long_rationale"),
    pytest.param(lambda: detection_event(extra=1), id="detection_key"),
    pytest.param(lambda: detection_event(finding_id="x"), id="finding_id"),
    pytest.param(lambda: detection_event(evidence_event_ids=["x"]), id="evidence_id"),
    pytest.param(lambda: detection_event(attack=[{"other": "x"}]), id="attack_key"),
]


@pytest.mark.parametrize("make", BROKEN)
def test_each_broken_rule_refuses_the_whole_batch(lab: Lab, make: Any) -> None:
    good = real_batch()[1:3]
    response = lab.client.post(EVENTS, json=[*good, make()], headers=lab.headers)
    assert response.status_code in (403, 422) and lab.stored() == 0
    assert "x" * 20 not in response.text


def test_a_label_for_its_own_session_passes(lab: Lab) -> None:
    event = good_event()
    event["source_ip"] = f"unknown-ssh-{event['session_id']}"
    assert lab.client.post(EVENTS, json=[event], headers=lab.headers).status_code == 200


@pytest.mark.parametrize("depth", [20, 3000])
def test_deep_evidence_refuses_the_whole_batch_and_cannot_crash_storage(lab: Lab, depth: int) -> None:
    """Python 3.12 accepts 3,000 levels in json.dumps, and storage then fails. 3.13 refuses earlier."""
    event = good_event()
    event["raw_evidence_redacted"]["details"]["a"] = "DEEP"
    body = json.dumps([*real_batch()[1:3], event]).replace('"DEEP"', "[" * depth + "]" * depth)
    response = lab.client.post(EVENTS, content=body, headers={**lab.headers, "content-type": "application/json"})
    assert response.status_code in (400, 422) and lab.stored() == 0


def test_deep_heartbeat_details_are_refused(lab: Lab) -> None:
    body = '{"sensor_id":"ssh-01","service":"ssh","status":"ok","details":{"a":' + "[" * 3000 + "]" * 3000 + "}}"
    response = lab.client.post(HEARTBEAT, content=body, headers={**lab.headers, "content-type": "application/json"})
    assert response.status_code in (400, 422) and lab.module.store.sensors() == []


# -- the header ----------------------------------------------------------------------------------

def post_with(lab: Lab, raw_headers: list[tuple[bytes, bytes]]) -> int:
    """TestClient merges repeated headers, so these go straight to the app, as uvicorn hands them over."""
    import asyncio

    body = json.dumps(real_batch()[:1]).encode()
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST", "path": "/api/events",
             "raw_path": b"/api/events", "query_string": b"", "root_path": "", "scheme": "http", "server": ("t", 1),
             "client": ("t", 1), "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
                                             *raw_headers]}
    asyncio.run(lab.module.app(scope, receive, send))
    return sent[0]["status"]


def test_exact_header_is_accepted(lab: Lab) -> None:
    assert post_with(lab, [(b"authorization", b"Bearer " + lab.ssh_token.encode())]) == 200


@pytest.mark.parametrize("make", [
    pytest.param(lambda t: [(b"authorization", b"Bearer " + t), (b"authorization", b"Bearer " + t)], id="two_correct"),
    pytest.param(lambda t: [(b"authorization", b"Bearer " + t), (b"authorization", b"Bearer x")], id="correct_then_wrong"),
    pytest.param(lambda t: [(b"authorization", b"Bearer x"), (b"authorization", b"Bearer " + t)], id="wrong_then_correct"),
    pytest.param(lambda t: [(b"authorization", b"Bearer " + t + b", Bearer " + t)], id="comma_joined"),
    pytest.param(lambda t: [(b"authorization", b"bearer " + t)], id="lowercase"),
    pytest.param(lambda t: [(b"authorization", b"BEARER " + t)], id="uppercase"),
    pytest.param(lambda t: [(b"authorization", b"Basic " + t)], id="basic"),
    pytest.param(lambda t: [(b"authorization", t)], id="no_scheme"),
    pytest.param(lambda t: [(b"authorization", b"")], id="empty"),
    pytest.param(lambda t: [(b"authorization", b"Bearer ")], id="empty_token"),
    pytest.param(lambda t: [(b"authorization", b"Bearer  " + t)], id="two_spaces"),
    pytest.param(lambda t: [(b"authorization", b"Bearer " + t + b" ")], id="trailing_space"),
    pytest.param(lambda t: [(b"authorization", b"Bearer " + t + b"\xc3\xa9")], id="non_ascii"),
    pytest.param(lambda t: [(b"authorization", b"Bearer " + b"a" * 4097)], id="too_long"),
    pytest.param(lambda t: [(b"x-authorization", b"Bearer " + t)], id="other_header"),
])
def test_every_other_header_form_is_refused(lab: Lab, make: Any) -> None:
    assert post_with(lab, make(lab.ssh_token.encode())) == 401
    assert lab.stored() == 0


def test_token_in_the_url_is_ignored(lab: Lab) -> None:
    assert lab.client.post(f"{EVENTS}?token={lab.ssh_token}", json=real_batch()).status_code == 401


def test_a_stray_header_on_web_traffic_is_ignored_as_today(lab: Lab) -> None:
    assert lab.client.post(EVENTS, json=[web_event()], headers=auth("nonsense")).status_code == 200


# -- broken secrets ------------------------------------------------------------------------------

def missing(path: Path) -> None:
    path.unlink()


def empty(path: Path) -> None:
    path.write_bytes(b"")


def blank(path: Path) -> None:
    path.write_bytes(b" \n\t\n")


def huge(path: Path) -> None:
    path.write_bytes(b"a" * 5000)


def binary(path: Path) -> None:
    path.write_bytes(b"\xff\xfe\x00\x01")


def folder(path: Path) -> None:
    path.unlink()
    path.mkdir()


BREAKS = [missing, empty, blank, huge, binary, folder]


@pytest.mark.parametrize("damage", BREAKS)
def test_a_broken_ssh_secret_refuses_ssh_and_leaves_others_alone(lab: Lab, damage: Any) -> None:
    damage(Path(lab.settings["SSH_INGEST_TOKEN_FILE"]))
    assert lab.client.post(EVENTS, json=real_batch(), headers=lab.headers).status_code == 503
    assert lab.client.post(EVENTS, json=real_batch()).status_code == 503
    assert lab.stored() == 0
    assert lab.client.post(EVENTS, json=[web_event()]).status_code == 200
    assert lab.client.post(HEARTBEAT, json={"sensor_id": "db-01", "service": "database", "status": "ok"}).status_code == 200


def test_web_and_database_traffic_never_reads_the_token_file(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> None:
    def must_not_run(_path: Any) -> None:
        raise AssertionError("a token file was read")

    monkeypatch.setattr("collector.ssh_ingest.load_token", must_not_run)
    assert lab.client.post(EVENTS, json=[web_event()]).status_code == 200
    assert lab.client.post(HEARTBEAT, json={"sensor_id": "db-01", "service": "database", "status": "ok"}).status_code == 200


def test_setting_absent_refuses_ssh(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SSH_INGEST_TOKEN_FILE")
    assert lab.client.post(EVENTS, json=real_batch()).status_code == 503


def test_collector_starts_with_a_broken_secret(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_INGEST_TOKEN_FILE", str(tmp_path / "nothing"))
    monkeypatch.setenv("SOC_READ_TOKEN_FILE", str(tmp_path / "nothing"))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    import collector.app as module

    importlib.reload(module)
    assert TestClient(module.app).get("/health").status_code == 200


def test_a_repaired_or_rotated_secret_works_without_a_restart(lab: Lab) -> None:
    path = Path(lab.settings["SSH_INGEST_TOKEN_FILE"])
    path.write_bytes(b"")
    assert lab.client.post(EVENTS, json=real_batch(), headers=lab.headers).status_code == 503
    path.write_text("rotated-token", encoding="ascii")
    assert lab.client.post(EVENTS, json=real_batch(), headers=lab.headers).status_code == 401
    assert lab.client.post(EVENTS, json=real_batch(), headers=auth("rotated-token")).status_code == 200


def test_secrets_never_reach_logs_responses_or_storage(lab: Lab, caplog: pytest.LogCaptureFixture, tmp_path: Path) -> None:
    caplog.set_level(logging.DEBUG)
    from collector import guards

    guards._logged_at.clear()
    wrong = "wrong" + os.urandom(8).hex()
    responses = [lab.client.post(EVENTS, json=real_batch(), headers=lab.headers),
                 lab.client.post(EVENTS, json=real_batch(), headers=auth(wrong)),
                 lab.client.post(EVENTS, json=[web_event()], headers=lab.headers)]
    Path(lab.settings["SSH_INGEST_TOKEN_FILE"]).unlink()
    responses.append(lab.client.post(EVENTS, json=real_batch()))
    seen = caplog.text + "".join(r.text for r in responses) + json.dumps(lab.module.store.events(1000))
    for value in (lab.ssh_token, wrong, lab.settings["SSH_INGEST_TOKEN_FILE"], "Traceback", "FileNotFoundError"):
        assert value not in seen
    assert lab.ssh_token.encode() not in (tmp_path / "c.db").read_bytes()


def test_failure_logging_is_limited_to_one_line_a_minute(lab: Lab, caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="collector.guards")
    from collector import guards

    guards._logged_at.clear()
    for _ in range(5):
        lab.client.post(EVENTS, json=real_batch())
    assert caplog.text.count("request refused") == 1


# -- the optional address lock -------------------------------------------------------------------

def test_address_lock_refuses_the_token_from_elsewhere(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SSH_SENSOR_PEER", "172.31.78.3")
    assert lab.client.post(EVENTS, json=real_batch(), headers=lab.headers).status_code == 401


def test_address_lock_admits_the_sensor_and_limits_its_routes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    lab = Lab(tmp_path, monkeypatch, client_address="172.31.78.3")
    monkeypatch.setenv("SSH_SENSOR_PEER", "172.31.78.3")
    assert lab.client.post(EVENTS, json=real_batch(), headers=lab.headers).status_code == 200
    assert lab.client.get("/api/events").status_code == 403
    assert lab.client.get("/health").status_code == 403
    assert lab.client.post("/api/adaptations", json=[]).status_code == 403


def test_address_lock_unset_changes_nothing(lab: Lab) -> None:
    assert lab.client.get("/health").status_code == 200
    assert lab.client.post(EVENTS, json=[web_event()]).status_code == 200
