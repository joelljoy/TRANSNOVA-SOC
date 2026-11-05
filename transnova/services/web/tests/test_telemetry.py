"""Phase 3: what gets recorded for each kind of request."""

from fastapi.testclient import TestClient

from web_decoy.app import create_app
from web_decoy.sessions import COOKIE_NAME
from .conftest import GOOD_PASS, GOOD_USER, LAB_IP, OUTSIDE_IP, read_events


def last(settings):
    return read_events(settings)[-1]


def test_page_view_event(client, settings):
    client.get("/", headers={"User-Agent": "Mozilla/5.0 test"})
    e = last(settings)
    assert e["event_type"] == "http_request" and e["action"] == "page_view"
    assert e["outcome"] == "observed" and e["http_status"] == 200 and e["http_method"] == "GET"
    assert e["request_path"] == "/" and e["user_agent"] == "Mozilla/5.0 test"
    assert e["source_ip"] == OUTSIDE_IP and e["source_port"] == 40000
    assert e["destination_service"] == "web-decoy"


def test_probe_paths_are_route_probe(client, settings):
    for path in ("/.env", "/backup", "/shell.php", "/api/v1/users"):
        client.get(path)
    events = read_events(settings)
    assert [e["action"] for e in events] == ["route_probe"] * 4
    assert [e["http_status"] for e in events] == [404, 403, 404, 401]


def test_failed_login_event(client, settings):
    client.post("/login", data={"username": GOOD_USER, "password": "Wr0ngPass!"})
    e = last(settings)
    assert e["event_type"] == "authentication" and e["action"] == "login_attempt"
    assert e["outcome"] == "failed" and e["username"] == GOOD_USER and e["http_status"] == 401
    assert e["session_id"] is None
    assert e["raw_evidence_redacted"]["form"]["password"] == "[REDACTED]"


def test_successful_login_and_session_correlation(client, settings):
    client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    login = last(settings)
    assert login["outcome"] == "succeeded" and login["session_id"]
    client.get("/portal")
    portal = last(settings)
    assert portal["session_id"] == login["session_id"]
    assert "authenticated_session" in portal["tags"]
    # The session_id is an opaque id, NOT the cookie secret.
    token = client.cookies.get(COOKIE_NAME)
    assert token not in open(settings.event_log_path).read()


def test_logout_event_keeps_session_id(client, settings):
    client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    sid = last(settings)["session_id"]
    client.post("/logout")
    assert last(settings)["session_id"] == sid


def test_upload_event_metadata_only(client, settings):
    content = b"%PDF-1.4 synthetic invoice body SECRETCONTENT"
    client.post("/upload", files={"document": ("..\\..\\evil/invoice.pdf", content, "application/pdf")})
    e = last(settings)
    assert e["event_type"] == "file_transfer" and e["action"] == "upload_attempt"
    assert e["file_direction"] == "upload" and e["file_name"] == "invoice.pdf"  # basename only
    up = e["raw_evidence_redacted"]["upload"]
    import hashlib
    assert up["sha256"] == hashlib.sha256(content).hexdigest()
    assert up["size_bytes"] == len(content) and up["sniffed_type"] == "application/pdf"
    assert up["stored"] is False
    assert b"SECRETCONTENT" not in open(settings.event_log_path, "rb").read()


def test_upload_sniffs_disguised_script(client, settings):
    client.post("/upload", files={"document": ("photo.jpg", b"<?php echo 1; ?>", "image/jpeg")})
    up = last(settings)["raw_evidence_redacted"]["upload"]
    assert up["declared_type"] == "image/jpeg" and up["sniffed_type"] == "application/x-php"


def test_oversize_upload_event_blocked(client, settings):
    data = b"A" * (settings.max_upload_bytes + 1)
    client.post("/upload", files={"document": ("big.bin", data, "application/octet-stream")})
    e = last(settings)
    assert e["outcome"] == "blocked" and e["http_status"] == 413
    assert e["raw_evidence_redacted"]["upload"]["sha256"] is None


def test_body_over_limit_rejected_and_recorded(client, settings):
    r = client.post("/login", content=b"a=" + b"x" * (settings.max_body_bytes + 1),
                    headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413
    assert r.headers["server"] == "nginx" and "content-security-policy" in r.headers
    e = last(settings)
    assert e["outcome"] == "blocked" and "body_rejected" in e["tags"]
    assert "form" not in e["raw_evidence_redacted"]  # rejected bodies are not parsed


def test_chunked_body_over_limit_rejected(client, settings):
    def gen():
        for _ in range(settings.max_body_bytes // 4096 + 2):
            yield b"x" * 4096
    r = client.post("/search", content=gen())
    assert r.status_code == 413


def test_non_numeric_content_length_is_400(client, settings):
    r = client.post("/login", content=b"x", headers={"Content-Length": "abc"})
    assert r.status_code == 400


def test_static_assets_not_recorded(client, settings):
    client.get("/static/style.css")
    assert read_events(settings) == []
    client.get("/static/../../etc/passwd")
    client.get("/static/nope.js")
    assert len(read_events(settings)) >= 1  # failed static probes ARE recorded


def test_health_from_lab_not_recorded_but_outside_probe_is(lab_client, client, settings):
    lab_client.get("/health")
    assert read_events(settings) == []
    client.get("/health")
    e = last(settings)
    assert e["action"] == "route_probe" and e["http_status"] == 404


def test_health_reports_live_stats(lab_client, client, settings):
    client.get("/admin")
    client.get("/.env")
    body = lab_client.get("/health").json()
    assert body["events_emitted_total"] == 2
    assert body["collector"]["url"] is None          # collector disabled in tests
    assert body["queue"]["dropped_events"] == 0
    assert body["status"] == "ok"


def test_json_body_flattened_and_redacted(client, settings):
    client.post("/api/v1/orders", json={"user": {"name": "x", "api_key": "k-123456"}, "items": [1, 2]})
    ev = last(settings)["raw_evidence_redacted"]
    assert ev["json"]["user.api_key"] == "[REDACTED]" and ev["json"]["user.name"] == "x"


def test_unhandled_exception_is_nginx_500_and_recorded(settings):
    app = create_app(settings)

    @app.get("/boom")
    def boom():
        raise RuntimeError("internal detail that must not leak")

    c = TestClient(app, client=(OUTSIDE_IP, 1), raise_server_exceptions=False)
    r = c.get("/boom")
    assert r.status_code == 500 and "<center>nginx</center>" in r.text
    assert "internal detail" not in r.text and "Traceback" not in r.text
    assert last(settings)["http_status"] == 500


def test_detectors_see_raw_values_but_events_never_contain_them(settings):
    """PLAN §0.1 P5: detection runs before redaction; only rule + field are stored."""
    seen = {}

    def detector(ctx):
        form = dict(ctx.form)
        seen["password"] = form.get("password")
        if "' or 1=1" in (form.get("password") or "").lower():
            # Even if a detector wrongly tries to include the value, it is sanitized.
            return [{"rule": "TEST-SQLI", "label": "probe:test", "field": "password",
                     "rationale": f"value was {form['password']}", "value": form["password"],
                     "attack": [{"technique": "T1190", "status": "candidate", "raw": "x"}]}]
        return []

    app = create_app(settings)
    app.state.detectors.append(detector)
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    secret = "zz' OR 1=1 -- password=hunter2"
    c.post("/login", data={"username": GOOD_USER, "password": secret})
    assert seen["password"] == secret                       # detector saw the raw value
    e = last(settings)
    d = next(x for x in e["raw_evidence_redacted"]["detections"] if x["rule"] == "TEST-SQLI")
    # The real Phase 4 detectors also saw this password (SQLi-like) and must not leak it either.
    assert any(x["rule"] == "W-SQLI-01" and x["field"] == "form.password"
               for x in e["raw_evidence_redacted"]["detections"])
    assert d["rule"] == "TEST-SQLI" and d["field"] == "password"
    assert "value" not in d and "raw" not in d["attack"][0]  # unknown keys dropped
    assert "hunter2" not in open(settings.event_log_path).read()
    assert "probe:test" in e["tags"]


def test_broken_detector_never_breaks_requests(settings):
    app = create_app(settings)
    app.state.detectors.append(lambda ctx: 1 / 0)
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    assert c.get("/").status_code == 200
    assert len(read_events(settings)) == 1
    assert app.state.telemetry_errors == 1


def test_log_write_failure_never_breaks_requests(tmp_path):
    from web_decoy.config import Settings
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("x")
    s = Settings(collector_url="", event_log_path=str(blocker / "events.jsonl"),
                 spool_path=str(tmp_path / "spool.jsonl"))
    app = create_app(s)
    c = TestClient(app, client=(OUTSIDE_IP, 1))
    assert c.get("/").status_code == 200
    assert app.state.emitter.log.write_errors == 1
    lab = TestClient(app, client=(LAB_IP, 1))
    assert lab.get("/health").json()["status"] == "degraded"


def test_detection_labels_are_not_mangled_by_redaction(settings):
    """Bug found in Phase 4: 'auth:failed' matched the 'auth: <secret>' redaction pattern."""
    app = create_app(settings)
    app.state.detectors = [lambda ctx: [{"rule": "R", "label": "auth:bruteforce", "owasp": "A07:2021-X",
                                         "attack": [{"technique": "T1110.001", "status": "candidate"}]}]]
    TestClient(app, client=(OUTSIDE_IP, 1)).get("/")
    e = last(settings)
    assert "auth:bruteforce" in e["tags"]
    d = e["raw_evidence_redacted"]["detections"][0]
    assert d["label"] == "auth:bruteforce" and d["attack"][0]["technique"] == "T1110.001"


def test_vocab_fields_cannot_smuggle_values(settings):
    app = create_app(settings)
    app.state.detectors = [lambda ctx: [{"rule": "R<script>\n", "label": "x" * 500}]]
    TestClient(app, client=(OUTSIDE_IP, 1)).get("/")
    d = last(settings)["raw_evidence_redacted"]["detections"][0]
    assert d["rule"] == "Rscript" and len(d["label"]) == 80
