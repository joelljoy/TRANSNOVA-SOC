"""Phase 2 exit tests: every route in PLAN.md §3 behaves as documented."""

import socket

import pytest

from web_decoy.errors import nginx_error_body
from .conftest import OUTSIDE_IP

NGINX_404 = nginx_error_body(404)


# --- §3.1 / §3.2 public route table (unauthenticated attacker view) -----------------

@pytest.mark.parametrize(
    "path,status,location",
    [
        ("/", 200, None),
        ("/login", 200, None),
        ("/search", 200, None),
        ("/portal", 302, "/login"),
        ("/portal/shipments/50211", 302, "/login"),
        ("/admin", 302, "/admin/login"),
        ("/admin/", 302, "/admin/login"),
        ("/admin/login", 200, None),
        ("/backup", 403, None),
        ("/backup/", 403, None),
        ("/config", 403, None),
        ("/config.php", 404, None),
        ("/.env", 404, None),
        ("/.git/config", 404, None),
        ("/api", 200, None),
        ("/api/v1/users", 401, None),
        ("/api/v1/users/1001", 401, None),
        ("/api/v1/orders", 401, None),
        ("/upload", 200, None),
        ("/shell.php", 404, None),
        ("/wp-content/uploads/cmd.php", 404, None),
        ("/static/style.css", 200, None),
    ],
)
def test_route_table(client, path, status, location):
    r = client.get(path)
    assert r.status_code == status, path
    if location:
        assert r.headers["location"] == location


# --- §3.4 fingerprinting -----------------------------------------------------------

@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"])
def test_framework_docs_disabled(client, path):
    r = client.get(path)
    assert r.status_code == 404
    assert r.text == NGINX_404


def test_unknown_path_is_nginx_404(client):
    r = client.get("/definitely-not-here")
    assert r.status_code == 404
    assert r.text == NGINX_404
    assert "detail" not in r.text


def test_method_not_allowed_is_nginx_not_json(client):
    r = client.get("/logout")
    assert r.status_code == 405
    assert "<center>nginx</center>" in r.text
    assert "application/json" not in r.headers["content-type"]


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["server"] == "nginx"
    csp = r.headers["content-security-policy"]
    assert "script-src 'none'" in csp and "frame-ancestors 'none'" in csp
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"


def test_error_pages_also_get_security_headers(client):
    assert client.get("/nope").headers["server"] == "nginx"


def test_non_numeric_id_is_404_not_422(logged_in):
    r = logged_in.get("/portal/shipments/abc")
    assert r.status_code == 404
    assert "detail" not in r.text
    r = logged_in.get("/api/v1/users/1%20OR%201=1")
    assert r.status_code == 404


def test_html_pages_have_no_inline_script(client):
    for path in ("/", "/login", "/admin/login", "/search", "/upload"):
        assert "<script" not in client.get(path).text.lower(), path


# --- /health (§3.1, PLAN §0.1 P8) --------------------------------------------------

def test_health_detailed_for_lab_source(lab_client):
    r = lab_client.get("/health")
    assert r.status_code == 200
    body = r.json()
    for key in ("status", "sensor_id", "service", "version", "uptime_s", "collector",
                "queue", "spool", "events_emitted_total", "detections_total"):
        assert key in body, key
    assert body["sensor_id"] == "web-01"
    assert body["service"] == "web"


def test_health_hidden_from_outside_source(client):
    r = client.get("/health")
    assert r.status_code == 404
    assert r.text == client.get("/no-such-page").text  # indistinguishable from unknown path


def test_health_rejects_non_ip_client(app):
    from fastapi.testclient import TestClient
    c = TestClient(app)  # default client host is the string "testclient"
    assert c.get("/health").status_code == 404


def test_health_ignores_forwarded_for(client):
    r = client.get("/health", headers={"X-Forwarded-For": "127.0.0.1"})
    assert r.status_code == 404


# --- reflection / XSS-safe rendering ----------------------------------------------

def test_search_reflection_is_escaped(client):
    payload = "<script>alert(1)</script>"
    r = client.get("/search", params={"q": payload})
    assert r.status_code == 200
    assert payload not in r.text
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in r.text


def test_search_attribute_breakout_is_escaped(client):
    payload = '"><img src=x onerror=alert(1)>'
    r = client.get("/search", params={"q": payload})
    assert payload not in r.text
    assert "&#34;&gt;&lt;img" in r.text


# --- /download trap: no filesystem access -----------------------------------------

def test_download_known_fake_file(client):
    r = client.get("/download", params={"file": "manifest-template.csv"})
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "TNLU1234567" in r.text


@pytest.mark.parametrize(
    "value",
    ["../../etc/passwd", "/etc/passwd", "..%2f..%2fetc%2fpasswd", "....//....//etc/passwd",
     "..\\..\\windows\\win.ini", "manifest-template.csv%00.php", "app.py", "../web_decoy/app.py"],
)
def test_download_traversal_never_reads_files(client, value, fs_guard):
    # Only the decoy's own event log may be opened; anything else is a traversal bug.
    with fs_guard() as opened:
        r = client.get("/download", params={"file": value})
    assert opened == [], f"/download touched the filesystem: {opened!r}"
    assert r.status_code == 404
    assert "root:" not in r.text


# --- /api/v1/preview SSRF trap ----------------------------------------------------

@pytest.mark.parametrize(
    "url", ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:22/", "file:///etc/passwd",
            "gopher://localhost:6379/_INFO", "http://example.com/"],
)
def test_preview_never_connects(client, url, monkeypatch, fs_guard):
    attempts = []

    def no_connect(*a, **kw):
        attempts.append(a)
        raise OSError("outbound connection blocked by test")

    # Start the client's event loop BEFORE blocking sockets. On Windows, creating
    # an asyncio loop opens an internal loopback socketpair via connect(); that is
    # test-harness plumbing, not the app. Only connects during the request count.
    with client:
        monkeypatch.setattr(socket.socket, "connect", no_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", no_connect)
        monkeypatch.setattr(socket, "create_connection", no_connect)
        monkeypatch.setattr(socket, "getaddrinfo", no_connect)
        # file:// "fetches" read local files without any socket, so watch opens too.
        with fs_guard() as file_reads:
            r = client.get("/api/v1/preview", params={"url": url})
        monkeypatch.undo()
    # Recorded, not just raised: a handler that swallows OSError cannot hide an attempt.
    assert attempts == [], f"preview attempted outbound connection(s): {attempts!r}"
    assert file_reads == [], f"preview touched the filesystem: {file_reads!r}"
    assert r.status_code == 200
    assert r.json() == {"status": "preview unavailable"}


# --- /upload: capped, content discarded -------------------------------------------

def test_upload_small_file_accepted(client):
    r = client.post("/upload", files={"document": ("invoice.pdf", b"%PDF-1.4 synthetic", "application/pdf")})
    assert r.status_code == 200
    assert r.json()["status"] == "received"


def test_upload_over_cap_by_content_length(client, settings):
    # Whole body over file cap + multipart overhead: rejected before the route runs.
    big = b"A" * (settings.max_upload_bytes + settings.multipart_overhead_bytes + 10)
    r = client.post("/upload", content=big, headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 413


def test_upload_file_over_cap_inside_body_limit(client, settings):
    # File itself 1 byte over the cap, body still under the overall limit: route rejects it.
    data = b"A" * (settings.max_upload_bytes + 1)
    r = client.post("/upload", files={"document": ("big.bin", data, "application/octet-stream")})
    assert r.status_code == 413


def test_upload_file_exactly_at_cap_is_accepted(client, settings):
    data = b"A" * settings.max_upload_bytes
    r = client.post("/upload", files={"document": ("max.bin", data, "application/octet-stream")})
    assert r.status_code == 200


def test_upload_over_cap_chunked_without_length(client, settings):
    def gen():
        chunk = b"B" * 65536
        for _ in range(settings.max_upload_bytes // len(chunk) + 2):
            yield chunk

    r = client.post("/upload", content=gen(), headers={"Content-Type": "application/octet-stream"})
    assert r.status_code == 413


def test_upload_bad_content_length(client):
    r = client.post("/upload", content=b"x", headers={"Content-Length": "abc"})
    assert r.status_code in (400, 413)


def test_upload_writes_nothing_to_disk(client, fs_guard, settings):
    payload = b"<?php system($_GET['c']); ?>"
    with fs_guard() as opened:
        r = client.post("/upload", files={"document": ("shell.php", payload, "text/plain")})
    assert r.status_code == 200
    assert opened == [], f"upload opened files other than the event log: {opened!r}"
    from pathlib import Path
    assert b"system(" not in Path(settings.event_log_path).read_bytes()  # content never logged


# --- API index -------------------------------------------------------------------

def test_api_index_lists_fake_endpoints(client):
    body = client.get("/api").json()
    assert body["service"] == "transnova-partner-api"
    assert "/api/v1/users" in body["endpoints"]


def test_api_unauthorized_is_json(client):
    r = client.get("/api/v1/users")
    assert r.json() == {"error": "unauthorized"}


def test_outside_ip_constant_is_outside_lab():
    from web_decoy.config import Settings, ip_in
    assert not ip_in(OUTSIDE_IP, Settings().health_allowed)


def test_docker_gateway_not_trusted_by_default(app):
    """P9: published-port traffic arrives from the lab gateway; it must not see detailed health."""
    from fastapi.testclient import TestClient
    c = TestClient(app, client=("172.28.0.1", 40000), follow_redirects=False)
    assert c.get("/health").status_code == 404


def test_allowlists_default_to_single_hosts():
    from web_decoy.config import Settings
    for net in Settings().health_allowed:
        assert net.prefixlen == net.max_prefixlen, f"{net} is a range, not a single host"
