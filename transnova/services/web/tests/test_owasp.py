"""OWASP Top 10 gap closures (2021 A02/A06/A08; 2025 A03/A04/A08/A10). See OWASP.md."""

import os
import re
import socket
import ssl
import stat
import threading
import time
from dataclasses import replace
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient

from web_decoy import serve
from web_decoy.app import create_app
from .conftest import GOOD_PASS, GOOD_USER, OUTSIDE_IP, read_events

WEB = Path(__file__).resolve().parent.parent


# ---- 2021 A02 / 2025 A04: cryptographic failures (TLS, Secure cookie, HSTS) ----------

def _run_server(**kw):
    server = uvicorn.Server(serve.build_config(host="127.0.0.1", port=0, log_level="error", **kw))
    server.install_signal_handlers = lambda: None
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    return server, t, server.servers[0].sockets[0].getsockname()[1]


def test_real_server_serves_tls_and_refuses_plain_http(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENT_LOG_PATH", str(tmp_path / "ev.jsonl"))
    monkeypatch.setenv("SPOOL_PATH", str(tmp_path / "sp.jsonl"))
    monkeypatch.setenv("COLLECTOR_URL", "")
    monkeypatch.setenv("WEB_DECOY_TLS", "1")
    server, t, port = _run_server(tls=True)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE           # self-signed lab certificate
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                assert tls.version() in ("TLSv1.2", "TLSv1.3")
                cert = ssl.DER_cert_to_PEM_cert(tls.getpeercert(binary_form=True))
                assert "BEGIN CERTIFICATE" in cert
                tls.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                head = tls.recv(4096)
        assert head.startswith(b"HTTP/1.1 200")
        assert b"strict-transport-security: max-age=31536000" in head.lower()
        # Plain HTTP on the TLS port must not get a page.
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            raw.sendall(b"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
            raw.settimeout(3)
            try:
                reply = raw.recv(200)
            except (socket.timeout, ConnectionResetError):
                reply = b""
        assert not reply.startswith(b"HTTP/1.1 200")
    finally:
        server.should_exit = True
        t.join(5)


def test_old_tls_versions_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("EVENT_LOG_PATH", str(tmp_path / "ev.jsonl"))
    monkeypatch.setenv("COLLECTOR_URL", "")
    server, t, port = _run_server(tls=True)
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.TLSv1
            ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        except (ValueError, ssl.SSLError):
            pytest.skip("local OpenSSL cannot even offer TLS 1.0/1.1")
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with pytest.raises(ssl.SSLError):
                ctx.wrap_socket(raw, server_hostname="localhost")
    finally:
        server.should_exit = True
        t.join(5)


def test_certificate_is_fresh_and_key_is_private(tmp_path):
    c1, k1 = serve.make_ephemeral_certificate(_mkdir(tmp_path / "a"))
    c2, k2 = serve.make_ephemeral_certificate(_mkdir(tmp_path / "b"))
    assert Path(k1).read_bytes() != Path(k2).read_bytes()     # new key every start
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(k1).st_mode) == 0o600
    assert b"PRIVATE KEY" in Path(k1).read_bytes()


def _mkdir(p):
    p.mkdir()
    return str(p)


def test_no_private_key_or_certificate_committed():
    pattern = re.compile(rb"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----")
    for path in WEB.rglob("*"):
        if path.is_file() and ".venv" not in path.parts and path.suffix not in (".pyc",):
            if path.name == "test_redaction.py":
                continue  # contains a fake key fixture on purpose
            assert not pattern.search(path.read_bytes()), path


def test_cookie_secure_and_hsts_when_tls(settings):
    app = create_app(replace(settings, tls=True))
    c = TestClient(app, client=(OUTSIDE_IP, 1), follow_redirects=False)
    r = c.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert "secure" in r.headers["set-cookie"].lower()
    assert r.headers["strict-transport-security"] == "max-age=31536000"
    big = c.post("/login", content=b"a=" + b"x" * 70000,
                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert big.status_code == 413 and big.headers["strict-transport-security"]


def test_no_secure_or_hsts_on_plain_http_dev_run(client):
    r = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert "secure" not in r.headers["set-cookie"].lower()
    assert "strict-transport-security" not in r.headers


# ---- 2021 A06 + A08 / 2025 A03 + A08: supply chain and integrity ---------------------

@pytest.mark.parametrize("name", ["requirements.txt", "requirements-dev.txt"])
def test_every_dependency_is_version_and_hash_pinned(name):
    text = (WEB / name).read_text()
    blocks = re.split(r"\n(?=[a-z0-9])", text)
    packages = [b for b in blocks if re.match(r"[a-z0-9][a-z0-9._-]*==", b)]
    assert len(packages) >= 20
    for block in packages:
        assert "--hash=sha256:" in block, block.splitlines()[0]
    # nothing unpinned or editable sneaks in
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith(("#", "--hash")) and not line.startswith("-"):
            assert "==" in line, line


def test_dockerfile_requires_hashes_and_pins_base_image():
    text = (WEB / "Dockerfile").read_text()
    code = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))  # ignore comments
    installs = [l for l in code.splitlines() if "pip install" in l]
    assert installs and all("--require-hashes" in l for l in installs), installs
    assert re.search(r"FROM python:3\.12-slim@sha256:[0-9a-f]{64}", text)
    assert "WEB_DECOY_TLS=1" in text


# ---- 2025 A10: mishandling of exceptional conditions (fail closed) ---------------------

def test_error_during_login_check_fails_closed(settings, monkeypatch):
    from web_decoy.routes import auth

    def broken(*a, **kw):
        raise RuntimeError("credential store unavailable")

    monkeypatch.setattr(auth, "_check", broken)
    app = create_app(settings)
    c = TestClient(app, client=(OUTSIDE_IP, 1), follow_redirects=False, raise_server_exceptions=False)
    r = c.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert r.status_code == 500 and "set-cookie" not in r.headers   # no session granted
    assert "credential store" not in r.text and "Traceback" not in r.text
    assert c.get("/portal").status_code == 302                       # still logged out
    assert read_events(settings)[-2]["http_status"] == 500           # the failure was recorded


def test_error_in_session_store_fails_closed(settings, monkeypatch):
    app = create_app(settings)

    def broken(token):
        raise RuntimeError("session store corrupted")

    monkeypatch.setattr(app.state.sessions, "get", broken)
    c = TestClient(app, client=(OUTSIDE_IP, 1), follow_redirects=False, raise_server_exceptions=False)
    c.cookies.set("hf_session", "anything")
    r = c.get("/portal")
    assert r.status_code in (302, 500) and "Jordan Miller" not in r.text


def test_malformed_inputs_never_crash_into_tracebacks(client):
    for method, path, kw in [
        ("post", "/login", {"content": b"\xff\xfe\x00garbage", "headers": {"Content-Type": "application/x-www-form-urlencoded"}}),
        ("post", "/upload", {"content": b"--x\r\nbroken", "headers": {"Content-Type": "multipart/form-data; boundary=x"}}),
        ("post", "/api/v1/orders", {"content": b"[" * 5000, "headers": {"Content-Type": "application/json"}}),
        ("get", "/search?q=%ff%fe%00", {}),
        ("get", "/portal/shipments/99999999999999999999", {}),
    ]:
        r = getattr(client, method)(path, **kw)
        assert r.status_code < 600 and "Traceback" not in r.text and "detail" not in r.text, (path, r.status_code)
