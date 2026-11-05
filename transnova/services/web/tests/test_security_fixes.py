"""Regression tests for the focused security review fixes F1-F5 (2026-10-31)."""

import asyncio
import json
import random
import socket
import threading
import time
from dataclasses import replace

import pytest
import uvicorn
from fastapi.testclient import TestClient
from uvicorn.protocols.http.h11_impl import H11Protocol

from web_decoy import serve
from web_decoy.app import create_app
from .conftest import GOOD_PASS, GOOD_USER, OUTSIDE_IP, read_events


# ---- F1a: request BODY deadline (middleware) --------------------------------------

def test_stalled_body_times_out_with_408_and_is_recorded(settings):
    s = replace(settings, body_timeout_s=0.3)
    app = create_app(s)
    sent = []
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": "POST",
             "scheme": "http", "path": "/login", "raw_path": b"/login", "query_string": b"",
             "root_path": "", "client": (OUTSIDE_IP, 5000), "server": ("127.0.0.1", 8080),
             "headers": [(b"host", b"x"), (b"content-type", b"application/x-www-form-urlencoded"),
                         (b"content-length", b"60000")]}
    first = True

    async def receive():
        nonlocal first
        if first:
            first = False
            return {"type": "http.request", "body": b"username=a", "more_body": True}
        await asyncio.Event().wait()  # stall forever, like a slowloris client

    async def send(msg):
        sent.append(msg)

    start = time.monotonic()
    asyncio.run(asyncio.wait_for(app(scope, receive, send), 5))
    assert time.monotonic() - start < 2
    assert sent[0]["status"] == 408
    e = read_events(s)[-1]
    assert e["outcome"] == "blocked" and e["http_status"] == 408 and "body_timeout" in e["tags"]


def test_normal_body_unaffected_by_deadline(client, settings):
    r = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert r.status_code == 302


# ---- F1b: request HEADER deadline (uvicorn protocol) ------------------------------

def _start_server(protocol, port_holder):
    config = uvicorn.Config("web_decoy.app:app", host="127.0.0.1", port=0, http=protocol,
                            limit_concurrency=3, log_level="error", lifespan="off")
    server = uvicorn.Server(config)
    server.install_signal_handlers = lambda: None  # running in a thread

    def run():
        server.run()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    port_holder.append(server.servers[0].sockets[0].getsockname()[1])
    return server, t


def _trickle_conns(port, n):
    conns = []
    for _ in range(n):
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")  # headers never completed
        conns.append(s)
    return conns


def _closed_by_server(sock):
    sock.settimeout(0.3)
    try:
        return sock.recv(10) == b""
    except socket.timeout:
        return False
    except OSError:
        return True


@pytest.mark.parametrize("protocol,expect_closed", [(serve.HeaderDeadlineH11Protocol, True),
                                                    (H11Protocol, False)],  # control: stock uvicorn
                         ids=["with-fix", "stock-uvicorn-control"])
def test_incomplete_headers_are_closed_by_deadline(monkeypatch, protocol, expect_closed):
    monkeypatch.setattr(serve, "HEADER_TIMEOUT_S", 0.5)
    port = []
    server, thread = _start_server(protocol, port)
    try:
        conns = _trickle_conns(port[0], 3)
        # Keep trickling one byte every 0.2 s for 1.6 s (> 3x the 0.5 s deadline), like a real
        # slowloris client. A deadline that resets on each byte would never fire.
        end = time.monotonic() + 1.6
        while time.monotonic() < end:
            time.sleep(0.2)
            for c in conns:
                try:
                    c.sendall(b"a")
                except OSError:
                    pass             # already closed by the server
        closed = [_closed_by_server(c) for c in conns]
        assert all(closed) is expect_closed, closed
        for c in conns:
            c.close()
    finally:
        server.should_exit = True
        thread.join(5)


def test_complete_requests_still_served_with_header_deadline(monkeypatch):
    monkeypatch.setattr(serve, "HEADER_TIMEOUT_S", 0.5)
    port = []
    server, thread = _start_server(serve.HeaderDeadlineH11Protocol, port)
    try:
        s = socket.create_connection(("127.0.0.1", port[0]))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        s.settimeout(5)
        assert s.recv(12).startswith(b"HTTP/1.1 200")
        s.close()
    finally:
        server.should_exit = True
        thread.join(5)


# ---- F2: login accepts only URL-encoded --------------------------------------------

def test_multipart_login_rejected_and_recorded(client, settings):
    r = client.post("/login", files={"username": (None, GOOD_USER), "password": (None, GOOD_PASS)})
    assert r.status_code == 400 and "<center>nginx</center>" in r.text
    assert "set-cookie" not in r.headers
    e = read_events(settings)[-1]
    assert e["event_type"] == "authentication" and e["outcome"] == "blocked"


def test_json_login_rejected(client):
    assert client.post("/login", json={"username": GOOD_USER, "password": GOOD_PASS}).status_code == 400


def test_urlencoded_with_charset_still_accepted(client):
    r = client.post("/login", content=f"username={GOOD_USER}&password=TransNova%23Spring26".encode(),
                    headers={"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"})
    assert r.status_code == 302


def test_sqli_can_no_longer_hide_in_login(client, settings):
    """The F2 exploit: every accepted login now passes through middleware parsing."""
    client.post("/login", data={"username": "admin", "password": "' OR 1=1 --"})
    assert any(d["rule"] == "W-SQLI-01" for d in read_events(settings)[-1]["raw_evidence_redacted"]["detections"])


# ---- F3: script markers anywhere in the upload -------------------------------------

def _upload_rules(client, settings, name, content, ctype):
    client.post("/upload", files={"document": (name, content, ctype)})
    e = read_events(settings)[-1]
    return e["raw_evidence_redacted"]["upload"], {d["rule"] for d in e["raw_evidence_redacted"]["detections"]}


@pytest.mark.parametrize("name,content,ctype,marker", [
    ("avatar.gif", b"GIF89a\x01\x00\x01\x00\x00\x00\x00;<?php system($_GET['c']); ?>", "image/gif", "php"),
    ("avatar.jpg", b"\xff\xd8\xff\xe0" + b"A" * 40 + b"<?php system($_GET['c']); ?>", "image/jpeg", "php"),
    ("photo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100 + b"<?= $_GET['x'] ?>", "image/png", "php"),
    ("doc.pdf", b"%PDF-1.4\n" + b"x" * 200 + b'<%@ page import="java.io.*" %>', "application/pdf", "jsp"),
    ("img.gif", b"GIF89a" + b"\x00" * 50 + b"<%@ Language=VBScript %>", "image/gif", "asp"),
])
def test_polyglot_uploads_flagged(client, settings, name, content, ctype, marker):
    up, rules = _upload_rules(client, settings, name, content, ctype)
    assert marker in up["script_markers"] and "W-UPL-01" in rules


def test_marker_split_across_read_chunks(client, settings):
    payload = b"GIF89a" + b"\x00" * (65536 - 6 - 3) + b"<?php system(1); ?>"  # '<?p' | 'hp ...'
    up, rules = _upload_rules(client, settings, "big.gif", payload, "image/gif")
    assert up["script_markers"] == ["php"] and "W-UPL-01" in rules


def test_random_binary_has_no_false_marker(client, settings):
    data = random.Random(1234).randbytes(settings.max_upload_bytes - 1)  # deterministic
    up, rules = _upload_rules(client, settings, "noise.bin", data, "application/octet-stream")
    assert up["script_markers"] == [] and "W-UPL-01" not in rules


def test_benign_files_have_no_markers(client, settings):
    for name, content, ctype in [("a.pdf", b"%PDF-1.4 <html> 100% <% done", "application/pdf"),
                                 ("notes.txt", b"meet at 10 <? maybe ?> ok", "text/plain")]:
        up, rules = _upload_rules(client, settings, name, content, ctype)
        assert up["script_markers"] == [] and "W-UPL-01" not in rules, name


# ---- F5: an upload part can never spill to a temp file ------------------------------

def test_upload_limits_fit_under_starlette_spool_threshold(settings):
    from starlette.formparsers import MultiPartParser
    assert settings.max_upload_bytes + settings.multipart_overhead_bytes <= MultiPartParser.spool_max_size


def test_max_size_upload_never_rolls_to_disk(client, settings, monkeypatch):
    import tempfile
    rolled = []
    orig = tempfile.SpooledTemporaryFile.rollover

    def spy(self):
        rolled.append(True)
        return orig(self)

    monkeypatch.setattr(tempfile.SpooledTemporaryFile, "rollover", spy)
    r = client.post("/upload", files={"document": ("max.bin", b"A" * settings.max_upload_bytes,
                                                    "application/octet-stream")})
    assert r.status_code == 200 and rolled == []


# ---- P13: forged X-Forwarded-For through the REAL server --------------------------

def test_real_server_ignores_forwarded_for(tmp_path, monkeypatch):
    """TestClient bypasses uvicorn, so this runs the actual hardened server config.
    Plain `uvicorn web_decoy.app:app` would log 8.8.8.8 here (it trusts XFF from 127.0.0.1)."""
    log = tmp_path / "ev.jsonl"
    monkeypatch.setenv("EVENT_LOG_PATH", str(log))
    monkeypatch.setenv("SPOOL_PATH", str(tmp_path / "sp.jsonl"))
    monkeypatch.setenv("COLLECTOR_URL", "")
    server = uvicorn.Server(serve.build_config(host="127.0.0.1", port=0, tls=False, log_level="error"))
    server.install_signal_handlers = lambda: None
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    try:
        for _ in range(100):
            if server.started:
                break
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET /admin HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 8.8.8.8\r\nConnection: close\r\n\r\n")
        s.settimeout(5)
        s.recv(100)
        s.close()
        time.sleep(0.2)
        event = json.loads(log.read_text().splitlines()[-1])
        assert event["source_ip"] == "127.0.0.1"
    finally:
        server.should_exit = True
        t.join(5)
