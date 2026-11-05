"""The queue to the SOC and how delivery behaves when the SOC misbehaves.

Fake markers are random and must never be shown. PYTEST_DONT_REWRITE turns off pytest's
assertion detail for this file, so a failure cannot print a marker.
"""

from __future__ import annotations

import json
import logging
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from cowrie_soc.canonical import translate
from cowrie_soc.config import Config, ConfigError, load_config
from cowrie_soc.encoders import ArrayEncoder
from cowrie_soc.normalize import NormalizeConfig, normalize
from cowrie_soc.pipeline import Pipeline
from cowrie_soc.sinks import AUTH, CONFIG, REJECTED, TOKEN, TRANSIENT, HttpSink, SinkError, SocDeliverer
from cowrie_soc.store import Store

from .conftest import CONFIG_FILE, cowrie_line, parse_text

SENSOR = "ssh-01"


def event(number: int = 0) -> dict[str, Any]:
    rec = normalize(parse_text(cowrie_line("cowrie.session.connect", session=f"{number + 1:012x}", at=number,
                                           uuid_extra=number)), NormalizeConfig(SENSOR, include_passwords=False))
    return translate(rec, SENSOR)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class FakeSink:
    name = "http"
    batch_size = 50

    def __init__(self, error: SinkError | None = None) -> None:
        self.error = error
        self.calls = 0
        self.sent: list[dict[str, Any]] = []

    def send(self, events: list[dict[str, Any]]) -> None:
        self.calls += 1
        if self.error is not None:
            raise self.error
        self.sent += events


def setup(tmp_path: Path, error: SinkError | None, events: int = 3) -> tuple[Store, FakeSink, SocDeliverer, Clock]:
    store = Store(tmp_path / "state.db")
    store.commit("s", None, [], canonical=[event(i) for i in range(events)])
    sink = FakeSink(error)
    clock = Clock()
    return store, sink, SocDeliverer(sink, store, SENSOR, clock=clock), clock


def run(deliverer: SocDeliverer, clock: Clock, seconds: float, step: float = 1.0) -> None:
    end = clock.now + seconds
    while clock.now < end:
        deliverer.deliver()
        clock.now += step


def test_delivered_events_advance_the_cursor(tmp_path: Path) -> None:
    store, sink, deliverer, _ = setup(tmp_path, None)
    assert deliverer.deliver() == 3 and len(sink.sent) == 3
    assert store.soc_status()["queued"] == 0 and store.soc_status()["delivered"] == 3


def test_batches_never_exceed_the_collector_limit(tmp_path: Path) -> None:
    store, sink, deliverer, _ = setup(tmp_path, None, events=120)
    sizes: list[int] = []
    sink.send = lambda events: sizes.append(len(events))  # type: ignore[method-assign]
    deliverer.deliver()
    assert sum(sizes) == 120 and max(sizes) == 50


def test_duplicate_events_are_queued_once(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    one = event()
    store.commit("s", None, [], canonical=[one])
    store.commit("s", None, [], canonical=[one])
    assert store.soc_pending() == 1


@pytest.mark.parametrize("status", [408, 425, 429, 500, 502, 503, 504])
def test_temporary_errors_keep_events_and_cap_the_retry_rate(tmp_path: Path, status: int) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", True, TRANSIENT, status))
    run(deliverer, clock, 3600)
    # 1, 2, 4, 8, 16, 32 s, then one a minute: 7 tries in the first 63 s, 58 more in the hour.
    assert sink.calls <= 66
    assert deliverer.state == "retrying" and store.soc_status()["queued"] == 3


def test_retry_delay_doubles_and_stops_at_sixty_seconds(tmp_path: Path) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", True, TRANSIENT, 503))
    gaps = []
    for _ in range(9):
        before = clock.now
        deliverer.deliver()
        gaps.append(deliverer.next_attempt - before)
        clock.now = deliverer.next_attempt
    assert gaps == [1, 2, 4, 8, 16, 32, 60, 60, 60]
    assert store.soc_status()["queued"] == 3


def test_recovery_after_temporary_errors_delivers_everything(tmp_path: Path) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", True, TRANSIENT, 503))
    run(deliverer, clock, 30)
    sink.error = None
    run(deliverer, clock, 70)
    assert len(sink.sent) == 3 and deliverer.state == "idle" and store.soc_status()["queued"] == 0


@pytest.mark.parametrize(("kind", "state"), [(AUTH, "unauthorized"), (TOKEN, "token_unavailable")])
def test_auth_failures_stop_after_three_attempts(tmp_path: Path, kind: str, state: str) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", kind == TOKEN, kind, 401))
    run(deliverer, clock, 7200)
    assert sink.calls == 3 and deliverer.state == state
    assert store.soc_status()["state"] == state and store.soc_status()["queued"] == 3


@pytest.mark.parametrize(("kind", "state"), [(CONFIG, "misconfigured"), (REJECTED, "rejected")])
def test_errors_needing_a_person_stop_at_once(tmp_path: Path, kind: str, state: str) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", False, kind, 422))
    run(deliverer, clock, 600)
    assert sink.calls == 1 and deliverer.state == state and store.soc_status()["queued"] == 3


def test_nothing_is_ever_dead_lettered(tmp_path: Path) -> None:
    store, _, deliverer, clock = setup(tmp_path, SinkError("x", False, REJECTED, 422))
    run(deliverer, clock, 10)
    assert store.status()["dead_letters"] == 0


def test_restart_clears_a_stopped_state_and_keeps_events(tmp_path: Path) -> None:
    store, sink, deliverer, clock = setup(tmp_path, SinkError("x", False, AUTH, 401))
    run(deliverer, clock, 600)
    sink.error = None
    restarted = SocDeliverer(sink, store, SENSOR, clock=clock)
    assert restarted.deliver() == 3


def test_event_failing_the_last_check_stops_delivery_without_sending(tmp_path: Path) -> None:
    store, sink, deliverer, _ = setup(tmp_path, None)
    store.db.execute("UPDATE soc_outbox SET body = ? WHERE seq = 1", (json.dumps({"event_id": "tampered"}),))
    assert deliverer.deliver() == 0
    assert sink.calls == 0 and deliverer.state == "rejected" and store.soc_status()["queued"] == 3


def test_queue_limit_skips_new_events_and_keeps_what_is_queued(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    store.commit("s", None, [], canonical=[event(i) for i in range(5)], max_soc_pending=3)
    assert store.soc_pending() == 3 and store.soc_status()["skipped"] == {"queue_full": 2}


def test_only_validated_events_can_be_sent_and_the_local_outbox_is_never_read(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    store.commit("s", None, [{"record_type": "event", "event_id": "old-record"}], canonical=[event()])
    sink = FakeSink()
    SocDeliverer(sink, store, SENSOR).deliver()
    assert [e["event_id"] for e in sink.sent] == [event()["event_id"]]


def test_skipped_table_holds_only_safe_id_and_reason(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    store.commit("s", None, [], skipped=[("sha256:" + "a" * 64, "bad_session")])
    assert [r[0] for r in store.db.execute("PRAGMA table_info(soc_skipped)")] == [0, 1, 2, 3]
    assert [r[1] for r in store.db.execute("PRAGMA table_info(soc_skipped)")] == ["id", "safe_id", "reason", "created_at"]


def test_prune_never_removes_pending_events(tmp_path: Path) -> None:
    store, _, deliverer, _ = setup(tmp_path, SinkError("x", True, TRANSIENT, 503))
    deliverer.deliver()
    store.soc_prune(0)
    assert store.soc_pending() == 3


def test_prune_keeps_only_recent_delivered_events(tmp_path: Path) -> None:
    store, _, deliverer, _ = setup(tmp_path, None, events=5)
    deliverer.deliver()
    assert store.soc_prune(2) == 3


class _Server(BaseHTTPRequestHandler):
    status = 200
    body = b""
    hits: list[str] = []
    payloads: list[Any] = []

    def do_POST(self) -> None:  # noqa: N802
        self.hits.append(self.headers.get("Authorization", ""))
        self.payloads.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


def start(status: int, body: bytes = b"") -> tuple[ThreadingHTTPServer, type]:
    handler = type("H", (_Server,), {"status": status, "body": body, "hits": [], "payloads": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server, handler


@pytest.mark.parametrize(("status", "kind"), [(401, AUTH), (403, AUTH), (400, REJECTED), (404, REJECTED), (413, REJECTED),
                                              (422, REJECTED), (503, TRANSIENT), (429, TRANSIENT), (307, CONFIG)])
def test_status_codes_map_to_kinds(status: int, kind: str) -> None:
    server, _ = start(status)
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder())
        with pytest.raises(SinkError) as exc:
            sink.send([{"a": 1}])
        assert exc.value.kind == kind and exc.value.status == status
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_collector_is_temporary() -> None:
    with pytest.raises(SinkError) as exc:
        HttpSink("http://127.0.0.1:9/x", ArrayEncoder(), timeout=1).send([{"a": 1}])
    assert exc.value.kind == TRANSIENT


def test_token_and_response_body_appear_nowhere(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    token, body = "T" + secrets.token_hex(16), "B" + secrets.token_hex(16)
    path = tmp_path / "token"
    path.write_text(token, encoding="utf-8")
    server, handler = start(401, body.encode())
    store = Store(tmp_path / "state.db")
    store.commit("s", None, [], canonical=[event()])
    clock = Clock()
    sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder(), token_file=str(path))
    deliverer = SocDeliverer(sink, store, SENSOR, clock=clock)
    try:
        with caplog.at_level(logging.DEBUG):
            run(deliverer, clock, 120)
    finally:
        server.shutdown()
        server.server_close()
    assert len(handler.hits) == 3 and deliverer.state == "unauthorized"
    assert handler.hits[0] == f"Bearer {token}"
    text = caplog.text + json.dumps(store.status())
    assert token not in text and body not in text


def test_pipeline_sends_real_capture_as_validated_events(tmp_path: Path, config: Config, real_lines: list[bytes]) -> None:
    server, handler = start(200)
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "cowrie.json").write_bytes(b"\n".join(real_lines) + b"\n")
    config.source.log_dir = str(logs)
    config.collector.state_db = str(tmp_path / "state.db")
    config.jsonl.path = str(tmp_path / "out.jsonl")
    config.http.enabled, config.http.url = True, f"http://127.0.0.1:{server.server_address[1]}/x"
    pipeline = Pipeline(config)
    try:
        for _ in range(10):
            pipeline.step()
    finally:
        server.shutdown()
        server.server_close()
    sent = [e for payload in handler.payloads for e in payload]
    assert len(sent) == 104 and max(len(p) for p in handler.payloads) <= 50
    assert all("record_type" not in e for e in sent)
    assert sum(len(e["raw_evidence_redacted"]["detections"]) for e in sent) == 14


def test_delivery_off_builds_no_soc_route(tmp_path: Path, config: Config) -> None:
    config.source.log_dir = str(tmp_path)
    config.collector.state_db = str(tmp_path / "state.db")
    config.jsonl.path = str(tmp_path / "out.jsonl")
    assert Pipeline(config).soc is None


@pytest.mark.parametrize("text", ['payload_format = "envelope"', 'field_map = { a = "b" }', "batch_size = 51"])
def test_config_refuses_formats_the_collector_would_reject(tmp_path: Path, text: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(f'[sinks.http]\nenabled = true\nurl = "http://127.0.0.1:1/x"\n{text}\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(path, env={})


def test_status_shows_only_safe_delivery_fields(tmp_path: Path) -> None:
    store = Store(tmp_path / "state.db")
    assert set(store.status()["soc_delivery"]) == {"state", "attempts", "last_status", "delivered", "queued", "skipped"}


def test_shipped_file_is_loadable() -> None:
    assert CONFIG_FILE.exists()
