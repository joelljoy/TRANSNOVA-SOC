"""HTTP sink against the local dev receiver and a stub that returns errors."""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from cowrie_soc.config import Config
from cowrie_soc.devreceiver import serve
from cowrie_soc.encoders import ArrayEncoder, EnvelopeEncoder, make_encoder
from cowrie_soc.pipeline import Pipeline
from cowrie_soc.sinks import HttpSink, SinkError


def _start(server: ThreadingHTTPServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


@pytest.fixture
def receiver(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[str, Any]]:
    monkeypatch.setenv("TEST_RECEIVER_TOKEN", "s3cret")
    server = serve("127.0.0.1", 0, str(tmp_path / "received.jsonl"), token_env="TEST_RECEIVER_TOKEN")
    _start(server)
    yield f"http://127.0.0.1:{server.server_address[1]}/ingest", server
    server.shutdown()
    server.server_close()


def test_sink_delivers_to_dev_receiver(receiver: tuple[str, Any], tmp_path: Path, config: Config,
                                       real_lines: list[bytes], monkeypatch: pytest.MonkeyPatch) -> None:
    url, server = receiver
    monkeypatch.setenv("COWRIE_SOC_HTTP_TOKEN", "s3cret")
    logs = tmp_path / "logs"
    logs.mkdir()
    (logs / "cowrie.json").write_bytes(b"\n".join(real_lines) + b"\n")
    config.source.log_dir = str(logs)
    config.collector.state_db = str(tmp_path / "state.db")
    out = tmp_path / "out.jsonl"
    config.jsonl.path = str(out)
    p = Pipeline(config)
    for _ in range(20):
        p.step()
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 104 + 14
    sink = HttpSink(url, EnvelopeEncoder("x"), token_env="COWRIE_SOC_HTTP_TOKEN")
    sink.send(records)
    state = server.state
    assert len(state.records) == 118 and state.duplicates == 0
    # Re-sending the same records (at-least-once) is de-duplicated by record id.
    sink.send(state.records[:5])
    assert state.duplicates == 5 and len(state.records) == 118


def test_receiver_requires_token(receiver: tuple[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    url, _ = receiver
    monkeypatch.delenv("NO_TOKEN", raising=False)
    sink = HttpSink(url, EnvelopeEncoder("x"), token_env="NO_TOKEN")
    with pytest.raises(SinkError) as exc:
        sink.send([{"record_type": "event"}])
    assert "401" in str(exc.value) and not exc.value.retryable


class _Stub(BaseHTTPRequestHandler):
    status = 503

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(self.status)
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args: Any) -> None:
        pass


@pytest.mark.parametrize(("status", "retryable"), [(503, True), (429, True), (400, False), (422, False)])
def test_http_status_classification(status: int, retryable: bool) -> None:
    handler = type("H", (_Stub,), {"status": status})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    _start(server)
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder())
        with pytest.raises(SinkError) as exc:
            sink.send([{"a": 1}])
        assert exc.value.retryable is retryable
    finally:
        server.shutdown()
        server.server_close()


class _Redirect(BaseHTTPRequestHandler):
    status = 307
    requests: list[tuple[str, str]] = []

    def _handle(self) -> None:
        self.requests.append((self.command, self.path))
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(self.status)
        self.send_header("Location", "/ingest/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = do_GET = _handle

    def log_message(self, *args: Any) -> None:
        pass


@pytest.mark.parametrize("status", [301, 302, 307, 308])
def test_redirect_is_not_followed_and_is_retryable(status: int) -> None:
    # Regression: urllib turned 301/302 into a body-less GET and 307/308 into a non-retryable
    # error, so a redirecting ingest URL dead-lettered every batch.
    handler = type("R", (_Redirect,), {"status": status, "requests": []})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    _start(server)
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/ingest", ArrayEncoder())
        with pytest.raises(SinkError) as exc:
            sink.send([{"a": 1}])
        assert exc.value.retryable
        assert "redirect" in str(exc.value) and "/ingest/" not in str(exc.value)  # Location is not stored
        assert handler.requests == [("POST", "/ingest")]  # no follow-up GET/POST
    finally:
        server.shutdown()
        server.server_close()


def test_unreachable_backend_is_retryable() -> None:
    sink = HttpSink("http://127.0.0.1:9/ingest", ArrayEncoder(), timeout=1)
    with pytest.raises(SinkError) as exc:
        sink.send([{"a": 1}])
    assert exc.value.retryable


def test_encoders_and_field_map() -> None:
    rec = {"record_type": "event", "source_ip": "10.0.0.1", "session_id": "abc"}
    env = make_encoder("envelope", "cowrie-1", {"source_ip": "src_ip"}).encode_batch([rec])
    assert env["sensor_id"] == "cowrie-1" and env["count"] == 1
    assert env["records"][0]["src_ip"] == "10.0.0.1" and "source_ip" not in env["records"][0]
    assert make_encoder("array", "x").encode_batch([rec]) == [rec]
    with pytest.raises(ValueError):
        make_encoder("xml", "x")
    with pytest.raises(ValueError):
        HttpSink("file:///etc/passwd", ArrayEncoder())
    json.dumps(env)


def test_receiver_refuses_to_start_with_empty_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: an empty token silently disabled auth, and the decoy container can reach the
    # receiver by IP on Docker Desktop (verified in review), so it must fail closed.
    from cowrie_soc.devreceiver import ReceiverConfigError

    monkeypatch.setenv("EMPTY_TOKEN", "")
    with pytest.raises(ReceiverConfigError):
        serve("127.0.0.1", 0, str(tmp_path / "r.jsonl"), token_env="EMPTY_TOKEN")


def test_receiver_records_endpoint_requires_token(receiver: tuple[str, Any]) -> None:
    import urllib.error
    import urllib.request

    url, _ = receiver
    base = url.rsplit("/", 1)[0]
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(base + "/records", timeout=3)
    assert exc.value.code == 401
    ok = urllib.request.Request(base + "/records?limit=x", headers={"Authorization": "Bearer s3cret"})
    with pytest.raises(urllib.error.HTTPError) as bad:
        urllib.request.urlopen(ok, timeout=3)
    assert bad.value.code == 400
    health = json.loads(urllib.request.urlopen(base + "/health", timeout=3).read())
    assert health["status"] == "ok"


def test_credentials_in_url_are_not_logged() -> None:
    sink = HttpSink("http://user:pa55@127.0.0.1:9/ingest?token=abc", ArrayEncoder(), timeout=1)
    with pytest.raises(SinkError) as exc:
        sink.send([{"a": 1}])
    assert "pa55" not in str(exc.value) and "abc" not in str(exc.value)
    assert "http://127.0.0.1:9/ingest" in str(exc.value)
