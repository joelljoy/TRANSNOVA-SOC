"""What the sensor keeps when input is hostile.

Fake markers are random and must never be shown. PYTEST_DONT_REWRITE turns off pytest's
assertion detail for this file, so a failure cannot print a marker. Symlink, FIFO, device
and race cases need Linux: tests/live/linux_tailer_check.py runs them in the sensor image.
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

from cowrie_soc.encoders import ArrayEncoder
from cowrie_soc.parser import ParseError, RawLine, parse_line
from cowrie_soc.pipeline import Pipeline, Processor
from cowrie_soc.config import Config
from cowrie_soc.sinks import HttpSink, JsonlSink, SinkError
from cowrie_soc.store import Store
from cowrie_soc.tailer import LogFollower, UnsafeLogFile, open_log

from .conftest import cowrie_line


def marker() -> str:
    return "X" + secrets.token_hex(16)


def test_a_directory_named_like_the_log_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "cowrie.json").mkdir()
    follower = LogFollower(tmp_path)
    assert follower.poll(None).checkpoint is None
    assert sum(follower.rejected.values()) == 1


@pytest.mark.parametrize("name", ["", ".", "..", "../x", "a/b", "a\\b", "x\0y"])
def test_names_outside_the_directory_are_refused(tmp_path: Path, name: str) -> None:
    with pytest.raises(UnsafeLogFile):
        open_log(tmp_path, name)


def test_missing_file_is_not_an_error(tmp_path: Path) -> None:
    assert open_log(tmp_path, "cowrie.json") is None


def test_rejection_is_reported_once_without_any_path(tmp_path: Path) -> None:
    (tmp_path / "cowrie.json").mkdir()
    follower = LogFollower(tmp_path)
    notices = follower.poll(None).notices + follower.poll(None).notices
    assert len(notices) == 1 and str(tmp_path) not in notices[0]


@pytest.mark.parametrize("name", ["cowrie.json.a b", "cowrie.json.", "cowrie.jsonx", "other.json"])
def test_unexpected_rotated_names_are_ignored(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("{}\n", encoding="utf-8")
    assert name not in LogFollower(tmp_path)._rotated_names()


@pytest.mark.parametrize("build", [
    lambda m: f'{{"eventid": "cowrie.login.failed", "password": "{m}"',
    lambda m: json.dumps({"eventid": m, "timestamp": "2026-10-31T00:00:00Z", "session": "s"}),
    lambda m: json.dumps({"eventid": "cowrie.x", "timestamp": m, "session": "s"}),
    lambda m: cowrie_line("cowrie.session.connect", src_ip=m),
    lambda m: f'["{m}"]',
    lambda m: f'{{"eventid": "cowrie.x\xff{m}"}}',
], ids=["bad-json", "bad-eventid", "bad-timestamp", "bad-ip", "not-object", "bad-utf8"])
def test_quarantine_keeps_no_line_content(build: Any) -> None:
    secret = marker()
    data = build(secret).encode("latin-1")
    result = parse_line(RawLine(data, "cowrie.json", 7))
    assert isinstance(result, ParseError)
    assert secret not in repr(result)


def test_oversized_line_keeps_no_content() -> None:
    secret = marker()
    result = parse_line(RawLine(secret.encode(), "cowrie.json", 7, oversized=True))
    assert isinstance(result, ParseError) and secret not in repr(result)


def test_processing_failure_records_no_exception_text(monkeypatch: pytest.MonkeyPatch,
                                                      caplog: pytest.LogCaptureFixture) -> None:
    secret = marker()

    def broken(_parsed: Any, _cfg: Any) -> None:
        raise ValueError(secret)

    monkeypatch.setattr("cowrie_soc.pipeline.normalize", broken)
    with caplog.at_level(logging.DEBUG):
        out = Processor(Config()).process([RawLine(cowrie_line("cowrie.session.connect").encode(), "cowrie.json", 0)])
    assert len(out.quarantined) == 1
    assert secret not in repr(out.quarantined[0]) and secret not in caplog.text


def test_unclean_line_is_cleaned_before_storage(tmp_path: Path) -> None:
    """A line that skipped Cowrie's cleaning: nothing from it may reach any sink."""
    secrets_used = [marker() for _ in range(7)]
    lines = [
        cowrie_line("cowrie.login.failed", username="root", password=secrets_used[0], message=secrets_used[1]),
        cowrie_line("cowrie.session.input", input=secrets_used[2], realm="tee"),
        cowrie_line("cowrie.client.var", name="DB_SECRET", value=secrets_used[3]),
        cowrie_line("cowrie.brand.new", input=secrets_used[4], data=secrets_used[5]),
        cowrie_line("cowrie.command.input", input=f"mysql -p{secrets_used[6]}"),
    ]
    config = Config()
    logs = tmp_path / "logs"
    logs.mkdir()
    config.source.log_dir = str(logs)
    (logs / "cowrie.json").write_text("\n".join(lines) + "\n", encoding="utf-8")
    jsonl = tmp_path / "state" / "normalized.jsonl"
    config.jsonl.path = str(jsonl)
    store = Store(tmp_path / "state" / "collector.db")
    pipeline = Pipeline(config, store=store, sinks=[JsonlSink(jsonl)])
    pipeline.step()
    pipeline.step()
    store.close()
    stored = jsonl.read_text(encoding="utf-8")
    assert len(stored.splitlines()) >= 5
    assert sum(s in stored for s in secrets_used) == 0


class _Echo(BaseHTTPRequestHandler):
    body = b""
    status = 500
    seen: list[str] = []

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        self.seen.append(self.headers.get("Authorization", ""))
        self.send_response(self.status)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *args: Any) -> None:
        pass


def serve(handler: type) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_collector_response_body_is_not_kept() -> None:
    secret = marker()
    server = serve(type("H", (_Echo,), {"body": secret.encode(), "status": 422, "seen": []}))
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder())
        with pytest.raises(SinkError) as exc:
            sink.send([{"a": 1}])
        assert "422" in str(exc.value) and secret not in str(exc.value)
    finally:
        server.shutdown()
        server.server_close()


def test_proxy_settings_are_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.delenv("no_proxy", raising=False)
    handler = type("H", (_Echo,), {"status": 200, "seen": []})
    server = serve(handler)
    try:
        HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder()).send([{"a": 1}])
        assert len(handler.seen) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_token_is_read_from_file_and_sent_as_a_header(tmp_path: Path) -> None:
    secret = marker()
    path = tmp_path / "token"
    path.write_text(secret + "\n", encoding="utf-8")
    handler = type("H", (_Echo,), {"status": 200, "seen": []})
    server = serve(handler)
    try:
        sink = HttpSink(f"http://127.0.0.1:{server.server_address[1]}/x", ArrayEncoder(), token_file=str(path))
        sink.send([{"a": 1}])
        assert handler.seen == [f"Bearer {secret}"]
        assert secret not in repr(vars(sink))
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("content", [None, "", "\n", "a\nb", "x" * 5000])
def test_unusable_token_file_stops_delivery_without_showing_it(tmp_path: Path, content: str | None) -> None:
    path = tmp_path / "token"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    sink = HttpSink("http://127.0.0.1:9/x", ArrayEncoder(), token_file=str(path))
    with pytest.raises(SinkError) as exc:
        sink.send([{"a": 1}])
    assert exc.value.retryable and "token file" in str(exc.value)
    assert "xxxx" not in str(exc.value) and str(tmp_path) not in str(exc.value)
