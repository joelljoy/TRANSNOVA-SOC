"""USP 1 on the main site: SOC blocklist enforcement, fail-safe polling, no leak of why."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from anonintel import AnonIntel
from mainsite.app import create_app
from mainsite.blockfeed import BlockFeed, _parse, http_fetch
from mainsite.config import Settings

ATTACKER, OTHER = "192.168.43.77", "192.168.43.50"


class Feed:
    """Stand-in for the collector: returns whatever `answer` holds, or raises."""
    def __init__(self, answer):
        self.answer = answer
        self.seen = []

    def __call__(self, url, token):
        self.seen.append((url, token))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def settings(tmp_path):
    (tmp_path / "anon").mkdir()
    return Settings(portal_url="http://p", anon_data_dir=str(tmp_path / "anon"), access_log_path=str(tmp_path / "b.jsonl"))


def make(settings, tmp_path, answer):
    f = BlockFeed("http://collector/api/blocklist/feed", "tok", fetch=Feed(answer))
    f.poll_once()
    return create_app(settings, intel=AnonIntel(tmp_path / "anon"), feed=f), f


def c(app, ip):
    return TestClient(app, client=(ip, 50000))


def test_blocked_attacker_refused_others_served(settings, tmp_path):
    app, _ = make(settings, tmp_path, json.dumps({"ips": [ATTACKER]}).encode())
    r = c(app, ATTACKER).get("/tracking?number=TNL50211")
    assert r.status_code == 403 and "refused by our security policy" in r.text
    assert "honeypot" not in r.text.lower() and "Kiel" not in r.text
    assert c(app, OTHER).get("/").status_code == 200
    rec = json.loads((tmp_path / "b.jsonl").read_text().splitlines()[-1])
    assert rec["category"] == "soc_block" and rec["ip"] == ATTACKER


def test_collector_down_keeps_last_good_list(settings, tmp_path):
    app, f = make(settings, tmp_path, json.dumps({"ips": [ATTACKER]}).encode())
    f._fetch.answer = ConnectionRefusedError()
    f.poll_once()
    assert f.last_error == "ConnectionRefusedError"
    assert c(app, ATTACKER).get("/").status_code == 403   # cutting the link does not unblock


def test_malformed_feed_ignored(settings, tmp_path):
    app, f = make(settings, tmp_path, json.dumps({"ips": [ATTACKER]}).encode())
    for bad in (b"not json", b'{"nope": 1}', b'{"ips": "1.2.3.4"}'):
        f._fetch.answer = bad
        f.poll_once()
        assert f.ips == frozenset({ATTACKER})


def test_parse_drops_invalid_entries():
    assert _parse(b'{"ips": ["1.2.3.4", "x", "::1", 5]}') == {"1.2.3.4", "::1"}


def test_unblock_takes_effect_on_next_poll(settings, tmp_path):
    app, f = make(settings, tmp_path, json.dumps({"ips": [ATTACKER]}).encode())
    f._fetch.answer = b'{"ips": []}'
    f.poll_once()
    assert c(app, ATTACKER).get("/").status_code == 200


def test_forwarded_header_cannot_dodge_the_block(settings, tmp_path):
    app, _ = make(settings, tmp_path, json.dumps({"ips": [ATTACKER]}).encode())
    r = TestClient(app, client=(ATTACKER, 1)).get("/", headers={"X-Forwarded-For": "8.8.4.4"})
    assert r.status_code == 403


def test_no_feed_configured_means_no_polling(settings, tmp_path):
    app = create_app(settings, intel=AnonIntel(tmp_path / "anon"))
    assert app.state.feed is None and c(app, ATTACKER).get("/").status_code == 200


def test_healthz_reports_feed_locally(settings, tmp_path):
    app, _ = make(settings, tmp_path, json.dumps({"ips": [ATTACKER, "127.0.0.1"]}).encode())
    assert c(app, "127.0.0.1").get("/").status_code == 403       # still blocked for pages
    h = c(app, "127.0.0.1").get("/healthz").json()
    assert h["soc_blocklist"]["blocked_ips"] == 2 and h["soc_blocklist"]["enabled"] is True  # healthz still answers


def test_real_http_fetch_sends_bearer_token():
    got = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            got["auth"] = self.headers.get("Authorization")
            body = b'{"ips": ["10.0.0.9"]}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.handle_request, daemon=True).start()
    raw = http_fetch(f"http://127.0.0.1:{srv.server_port}/api/blocklist/feed", "secret-tok")
    srv.server_close()
    assert got["auth"] == "Bearer secret-tok" and _parse(raw) == {"10.0.0.9"}


def test_token_not_in_settings_repr():
    assert "s3cr3t" not in repr(Settings(blocklist_token="s3cr3t"))
