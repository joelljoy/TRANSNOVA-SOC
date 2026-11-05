"""F6: one source cannot fill the decoy's 200 slots with fast requests or connections."""

import socket
import threading
import time
from dataclasses import replace

import pytest
import uvicorn
from fastapi.testclient import TestClient

from web_decoy import serve
from web_decoy.app import create_app
from web_decoy.ratelimit import RateLimiter
from .conftest import OUTSIDE_IP, read_events


class Clock:
    def __init__(self):
        self.t = 100.0

    def __call__(self):
        return self.t


def test_token_bucket_burst_then_limit_then_refill():
    clk = Clock()
    rl = RateLimiter(rate_per_s=1, burst=3, log_every_s=10, clock=clk)
    assert [rl.check("a")[0] for _ in range(3)] == [True, True, True]
    assert rl.check("a") == (False, 1)          # first rejection is logged
    assert rl.check("a") == (False, None)       # further rejections only counted
    assert rl.check("a") == (False, None)
    clk.t += 10                                  # refill + new log window
    assert rl.check("a")[0] is True
    for _ in range(2):
        rl.check("a")
    allowed, count = rl.check("a")
    assert allowed is False and count == 3       # 2 suppressed earlier + this one


def test_sources_are_independent():
    rl = RateLimiter(rate_per_s=1, burst=1, clock=Clock())
    assert rl.check("a")[0] and not rl.check("a")[0]
    assert rl.check("b")[0]


def test_disabled_when_zero():
    rl = RateLimiter(rate_per_s=0, burst=0)
    assert all(rl.check("a")[0] for _ in range(1000))


def test_memory_bounded():
    from web_decoy import ratelimit
    rl = RateLimiter(rate_per_s=1, burst=1)
    for i in range(ratelimit.MAX_SOURCES + 100):
        rl.check(f"10.0.{i // 256}.{i % 256}")
    assert len(rl._state) == ratelimit.MAX_SOURCES


def test_flood_gets_429_and_is_logged_once_per_window(settings):
    app = create_app(replace(settings, rate_limit_per_s=1, rate_limit_burst=3))
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    codes = [c.get("/").status_code for _ in range(50)]
    assert codes[:3] == [200, 200, 200] and set(codes[3:]) == {429}
    r = c.get("/")
    assert r.status_code == 429 and "<center>nginx</center>" in r.text
    assert "Too Many Requests" in r.text and r.headers["server"] == "nginx"
    limited = [e for e in read_events(settings) if "rate_limited" in e["tags"]]
    assert len(limited) == 1                                  # 48 rejections, one event
    assert limited[0]["outcome"] == "blocked" and limited[0]["http_status"] == 429
    assert limited[0]["raw_evidence_redacted"]["rate_limit"] == {"suppressed": 1, "limit_per_s": 1.0, "burst": 3}


def test_rate_limited_request_body_is_not_read(settings):
    app = create_app(replace(settings, rate_limit_per_s=1, rate_limit_burst=1))
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    c.get("/")
    r = c.post("/login", content=b"a=" + b"x" * 200000, headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 429                                # refused before the 413 size check


def test_other_sources_unaffected_by_a_flooder(settings):
    app = create_app(replace(settings, rate_limit_per_s=1, rate_limit_burst=3))
    flooder = TestClient(app, client=("203.0.113.66", 1))
    for _ in range(30):
        flooder.get("/")
    assert flooder.get("/").status_code == 429
    assert TestClient(app, client=("203.0.113.77", 1)).get("/").status_code == 200


def test_default_settings_have_flood_limit_on():
    from web_decoy.config import Settings
    s = Settings()
    assert s.rate_limit_per_s == 20 and s.rate_limit_burst == 60


def test_normal_demo_burst_is_not_rate_limited(settings):
    """The demo's biggest burst (~10 quick requests) must pass under the default limits."""
    from web_decoy.config import Settings
    d = Settings()
    app = create_app(replace(settings, rate_limit_per_s=d.rate_limit_per_s, rate_limit_burst=d.rate_limit_burst))
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    assert all(c.get("/.env").status_code == 404 for _ in range(40))


# ---- per-IP connection cap on the REAL server ---------------------------------------

def test_one_source_cannot_hold_more_than_its_connection_share(monkeypatch, tmp_path):
    monkeypatch.setattr(serve, "MAX_CONN_PER_IP", 3)
    monkeypatch.setenv("EVENT_LOG_PATH", str(tmp_path / "ev.jsonl"))
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
        before = serve.HeaderDeadlineH11Protocol.rejected_connections
        socks = [socket.create_connection(("127.0.0.1", port)) for _ in range(5)]   # idle: hold slots
        time.sleep(0.3)

        def closed(s):
            s.settimeout(0.3)
            try:
                return s.recv(1) == b""
            except socket.timeout:
                return False
            except OSError:
                return True

        state = [closed(s) for s in socks]
        assert state == [False, False, False, True, True], state
        assert serve.HeaderDeadlineH11Protocol.rejected_connections - before == 2
        for s in socks:
            s.close()
        time.sleep(0.3)                                   # slots released -> new client served
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        s.settimeout(5)
        assert s.recv(12).startswith(b"HTTP/1.1 200")
        s.close()
    finally:
        server.should_exit = True
        t.join(5)
