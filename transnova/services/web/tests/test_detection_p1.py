"""Phase 4 P1 scenarios: SSRF, suspicious upload, IDOR, webshell path probes."""

import pytest

from .conftest import GOOD_PASS, GOOD_USER, read_events
from .detect_helpers import FakeClock, all_rules, app_with_clock, by_rule, client_for, last, rules


@pytest.fixture
def c(settings):
    return client_for(app_with_clock(settings, FakeClock()))


@pytest.fixture
def logged(c):
    c.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    return c


# ---- W-SSRF-01 ----------------------------------------------------------------------

SSRF = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "http://localhost/admin",
        "http://[::1]/", "http://2130706433/", "http://0x7f000001/", "http://10.0.0.5/",
        "http://192.168.1.1/", "http://172.28.0.20:8000/api/events", "file:///etc/passwd",
        "gopher://localhost:6379/_INFO", "dict://127.0.0.1:11211/stats", "http://0.0.0.0:8080/",
        "http://metadata.google.internal/computeMetadata/v1/", "HTTP://LOCALHOST/",
        "http%3A%2F%2F169.254.169.254%2F"]


@pytest.mark.parametrize("url", SSRF)
def test_ssrf_detected(c, settings, url):
    r = c.get("/api/v1/preview", params={"url": url})
    assert r.json() == {"status": "preview unavailable"}
    d = by_rule(last(settings), "W-SSRF-01")
    assert d["field"] == "query.url" and d["owasp"].startswith("A10")
    assert "never fetched" in d["rationale"]


@pytest.mark.parametrize("url", ["http://example.com/", "https://transnova-logistics.example/x",
                                 "https://8.8.8.8/", "not a url", "http//broken"])
def test_external_or_non_url_not_ssrf(c, settings, url):
    c.get("/api/v1/preview", params={"url": url})
    assert "W-SSRF-01" not in rules(last(settings))


def test_ssrf_in_any_parameter_name(c, settings):
    c.get("/search", params={"q": "x", "callback": "http://169.254.169.254/"})
    assert by_rule(last(settings), "W-SSRF-01")["field"] == "query.callback"


# ---- W-UPL-01 -----------------------------------------------------------------------

@pytest.mark.parametrize("name,content,ctype", [
    ("shell.php", b"<?php system($_GET['c']); ?>", "application/x-php"),
    ("photo.jpg", b"<?php echo 1; ?>", "image/jpeg"),              # disguised
    ("invoice.pdf", b"\x7fELF\x02\x01\x01", "application/pdf"),      # ELF binary
    ("run.sh", b"#!/bin/sh\necho hi\n", "text/plain"),
    ("tool.exe", b"MZ\x90\x00", "application/octet-stream"),
    ("page.jsp", b"<% out.println(1); %>", "text/plain"),
])
def test_suspicious_upload(c, settings, name, content, ctype):
    c.post("/upload", files={"document": (name, content, ctype)})
    e = last(settings)
    d = by_rule(e, "W-UPL-01")
    assert d["attack"][0]["technique"] == "T1105" and "never stored or executed" in d["rationale"]
    assert e["event_type"] == "file_transfer" and e["outcome"] == "observed"


@pytest.mark.parametrize("name,content,ctype", [
    ("invoice.pdf", b"%PDF-1.4 synthetic", "application/pdf"),
    ("scan.png", b"\x89PNG\r\n\x1a\nxxxx", "image/png"),
    ("notes.txt", b"plain notes", "text/plain"),
])
def test_benign_upload_not_flagged(c, settings, name, content, ctype):
    c.post("/upload", files={"document": (name, content, ctype)})
    assert "W-UPL-01" not in rules(last(settings))


# ---- W-IDOR-01 ----------------------------------------------------------------------

def test_idor_other_users_record(logged, settings):
    logged.get("/api/v1/users/1002")
    d = by_rule(last(settings), "W-IDOR-01")
    assert d["owasp"].startswith("A01") and d["attack"][0]["technique"] == "T1213"
    assert "authz:idor_attempt" in last(settings)["tags"]


def test_idor_other_partners_shipment(logged, settings):
    logged.get("/portal/shipments/50318")  # owned by user 1002
    assert "W-IDOR-01" in rules(last(settings))


@pytest.mark.parametrize("path", ["/api/v1/users/1001", "/portal/shipments/50211", "/api/v1/users/4242",
                                  "/api/v1/users"])
def test_own_or_missing_objects_not_idor(logged, settings, path):
    logged.get(path)
    assert "W-IDOR-01" not in rules(last(settings))


def test_idor_requires_a_session(c, settings):
    c.get("/api/v1/users/1002")  # 401, not an authorization bypass attempt
    assert "W-IDOR-01" not in rules(last(settings))


# ---- W-SHELL-01 ---------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/shell.php", "/cmd.php", "/c99.php", "/wso.php", "/uploads/x.jsp",
                                  "/wp-content/uploads/2026/10/up.php", "/upload/b374k.php"])
def test_webshell_path_probe(c, settings, path):
    c.get(path)
    e = last(settings)
    d = by_rule(e, "W-SHELL-01")
    assert d["confidence"] == "low" and [a["technique"] for a in d["attack"]] == ["T1595.003"]
    assert "no webshell exists" in d["rationale"] and e["http_status"] == 404


@pytest.mark.parametrize("path", ["/wp-login.php", "/config.php"])
def test_common_php_paths_are_enumeration_not_webshell(c, settings, path):
    c.get(path)
    r = rules(last(settings))
    assert "W-ENUM-01" in r and "W-SHELL-01" not in r


def test_health_and_counters(settings):
    app = app_with_clock(settings, FakeClock())
    c = client_for(app)
    c.get("/shell.php")
    c.get("/search", params={"q": "' OR 1=1--"})
    lab = client_for(app, "127.0.0.1")
    counts = lab.get("/health").json()["detections_total"]
    assert counts["W-SHELL-01"] == 1 and counts["W-SQLI-01"] == 1
