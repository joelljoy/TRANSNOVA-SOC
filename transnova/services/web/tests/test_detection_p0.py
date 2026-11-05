"""Phase 4 P0 scenarios: enumeration, brute force, spraying, decoy success, SQLi, XSS, traversal."""

import pytest

from web_decoy.detection.normalize import normalize
from .conftest import GOOD_PASS, GOOD_USER, read_events
from .detect_helpers import (FakeClock, all_rules, app_with_clock, by_rule, client_for, dets, last,
                             rules)


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def c(settings, clock):
    return client_for(app_with_clock(settings, clock))


# ---- W-ENUM-01 / W-ENUM-02: route enumeration -------------------------------------

def test_single_sensitive_path_is_low_and_unmapped(c, settings):
    c.get("/.env")
    d = by_rule(last(settings), "W-ENUM-01")
    assert d["confidence"] == "low" and d["attack"] == []
    assert "enum:sensitive_path" in last(settings)["tags"]


SCAN = ["/.env", "/.git/config", "/backup.zip", "/wp-login.php", "/phpmyadmin", "/server-status",
        "/old/", "/db.sql", "/test", "/x1"]


def test_route_scan_fires_on_eighth_distinct_path(c, settings):
    for p in SCAN[:7]:
        c.get(p)
    assert not any("W-ENUM-02" in r for r in all_rules(settings))
    c.get(SCAN[7])
    d = by_rule(last(settings), "W-ENUM-02")
    assert d["attack"][0]["technique"] == "T1595.003" and d["attack"][0]["status"] == "candidate"
    assert "threshold 8" in d["rationale"] and "60s" in d["rationale"]


def test_route_scan_tags_every_request_while_over_threshold(c, settings, clock):
    for p in SCAN:
        c.get(p)
    assert sum("W-ENUM-02" in r for r in all_rules(settings)) == 3  # 8th, 9th, 10th path
    assert "10 distinct" in by_rule(last(settings), "W-ENUM-02")["rationale"]
    c.get("/.env")  # repeat of a known path while the scan is still live: still tagged
    assert "W-ENUM-02" in rules(last(settings))
    c.get("/")  # normal 200 page from the same source is not a scan hit
    assert "W-ENUM-02" not in rules(last(settings))
    clock.advance(61)  # window empties: counting starts again
    c.get("/x2")
    assert "W-ENUM-02" not in rules(last(settings))
    for p in SCAN[:7]:
        c.get(p + "?again")
    assert "W-ENUM-02" in rules(last(settings))  # 8 distinct again in the new window


def test_slow_scan_outside_window_does_not_fire(c, settings, clock):
    for p in SCAN[:8]:
        c.get(p)
        clock.advance(10)  # 8 paths over 80s: never 8 inside one 60s window
    assert not any("W-ENUM-02" in r for r in all_rules(settings))


def test_repeating_one_path_is_not_a_scan(c, settings):
    for _ in range(20):
        c.get("/.env")
    assert not any("W-ENUM-02" in r for r in all_rules(settings))


def test_scans_are_tracked_per_source(settings, clock):
    app = app_with_clock(settings, clock)
    a, b = client_for(app, "203.0.113.1"), client_for(app, "203.0.113.2")
    for i, p in enumerate(SCAN[:8]):
        (a if i % 2 else b).get(p)  # 4 paths each
    assert not any("W-ENUM-02" in r for r in all_rules(settings))


def test_normal_browsing_is_not_a_scan(c, settings):
    for p in ["/", "/login", "/search", "/search?q=x", "/upload", "/static/style.css"]:
        c.get(p)
    assert not any("W-ENUM-02" in r for r in all_rules(settings))


# ---- W-AUTH-01..04 ------------------------------------------------------------------

def _fail(c, user=GOOD_USER, n=1):
    for i in range(n):
        c.post("/login", data={"username": user, "password": f"guess{i}"})


def test_every_failed_login_tagged(c, settings):
    _fail(c)
    assert "W-AUTH-01" in rules(last(settings)) and "auth:failed" in last(settings)["tags"]


def test_bruteforce_medium_at_5_high_at_15(c, settings):
    _fail(c, n=4)
    assert not any("W-AUTH-02" in r for r in all_rules(settings))
    _fail(c, n=1)
    d = by_rule(last(settings), "W-AUTH-02")
    assert d["confidence"] == "medium" and d["attack"][0]["technique"] == "T1110.001"
    assert d["attack"][0]["confidence"] == "medium"
    _fail(c, n=9)
    assert sum("W-AUTH-02" in r for r in all_rules(settings)) == 10  # every failure 5..14 tagged
    assert by_rule(last(settings), "W-AUTH-02")["confidence"] == "medium"
    _fail(c, n=1)
    d = by_rule(last(settings), "W-AUTH-02")
    assert d["confidence"] == "high" and d["attack"][0]["confidence"] == "high"
    assert sum("W-AUTH-02" in r for r in all_rules(settings)) == 11


def test_sustained_bruteforce_stays_high_on_every_request(c, settings):
    # Owner's report: 50 failures in ~30 s showed only W-AUTH-01(low) after the 15th.
    _fail(c, n=50)
    evs = [e for e in read_events(settings) if e["request_path"] == "/login"]
    assert len(evs) == 50
    for i, e in enumerate(evs, start=1):
        d = [x for x in dets(e) if x["rule"] == "W-AUTH-02"]
        if i < 5:
            assert not d
        else:
            assert d and d[0]["confidence"] == ("high" if i >= 15 else "medium")
            assert f"{i} failed logins" in d[0]["rationale"]


def test_bruteforce_drops_back_after_window(c, settings, clock):
    _fail(c, n=20)
    assert by_rule(last(settings), "W-AUTH-02")["confidence"] == "high"
    clock.advance(61)
    _fail(c, n=1)
    assert "W-AUTH-02" not in rules(last(settings))  # old failures left the 60 s window


def test_slow_bruteforce_outside_window_does_not_fire(c, settings, clock):
    for _ in range(6):
        _fail(c)
        clock.advance(20)  # never 5 within 60s
    assert not any("W-AUTH-02" in r for r in all_rules(settings))


def test_spraying_detected(c, settings):
    for user in ["admin", "root", "a.okafor", "s.lindqvist"]:
        _fail(c, user=user)
    d = by_rule(last(settings), "W-AUTH-03")
    assert d["attack"][0]["technique"] == "T1110.003"
    assert not any("W-AUTH-02" in r for r in all_rules(settings))  # not brute force
    _fail(c, user="m.duarte")  # spray continues: next attempt still tagged
    assert "5 distinct usernames" in by_rule(last(settings), "W-AUTH-03")["rationale"]


def test_three_tries_each_is_not_spraying(c, settings):
    for user in ["admin", "root", "a.okafor", "s.lindqvist"]:
        _fail(c, user=user, n=3)
    assert not any("W-AUTH-03" in r for r in all_rules(settings))


def test_decoy_success_high_with_prior_failures(c, settings):
    _fail(c, n=3)
    c.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    d = by_rule(last(settings), "W-AUTH-04")
    assert d["confidence"] == "high" and d["category"] == "decoy_interaction"
    assert d["attack"][0]["technique"] == "T1078" and d["attack"][0]["status"] == "candidate"
    assert "after 3 failed attempts" in d["rationale"]
    assert last(settings)["outcome"] == "succeeded"


# ---- W-SQLI-01 ---------------------------------------------------------------------

SQLI = ["' OR 1=1 --", "admin'--", "' or 'a'='a", "1 UNION SELECT username,password FROM users",
        "1; DROP TABLE users", "x' AND SLEEP(5)#", "1 or 1=1", "' union all select null--",
        "%27%20OR%201%3D1--", "%2527%2520OR%25201%253D1--",  # single and double URL-encoded
        "1 AND extractvalue(1,concat(0x7e,version()))", "'; WAITFOR DELAY '0:0:5'--",
        "x' AND 1=(SELECT COUNT(*) FROM information_schema.tables)--"]


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_query(c, settings, payload):
    c.get("/search", params={"q": payload})
    e = last(settings)
    d = by_rule(e, "W-SQLI-01")
    assert d["field"] == "query.q" and d["category"] == "probe_detected"
    assert d["attack"][0]["technique"] == "T1190" and d["attack"][0]["status"] == "candidate"
    assert "no evidence of success" in d["attack"][0]["rationale"]
    assert e["outcome"] == "observed"  # a probe, never "succeeded"


def test_sqli_in_password_field_detected_but_not_logged(c, settings):
    """PLAN §0.1 P5, end to end with the real detectors."""
    secret_marker = "zq9' OR 1=1 -- Zq9Marker"
    c.post("/login", data={"username": "admin", "password": secret_marker})
    e = last(settings)
    assert by_rule(e, "W-SQLI-01")["field"] == "form.password"
    assert "Zq9Marker" not in open(settings.event_log_path).read()


def test_sqli_in_json_body(c, settings):
    c.post("/api/v1/orders", json={"filter": {"id": "1 UNION SELECT 1,2,3"}})
    assert by_rule(last(settings), "W-SQLI-01")["field"] == "json.filter.id"


BENIGN = ["O'Brien", "Rotterdam", "HFCU1234567", "select a container", "Tom & Jerry's", "50% off",
          "shipment 50211 or 50212", "a=b", "rock'n'roll", "C:\\Users\\docs", "<3 thanks",
          "https://transnova-logistics.example/track", "dropbox link", "update me please", "Q&A -- notes"]


@pytest.mark.parametrize("value", BENIGN)
def test_benign_input_triggers_no_input_rule(c, settings, value):
    c.get("/search", params={"q": value})
    assert not rules(last(settings)) & {"W-SQLI-01", "W-XSS-01", "W-PATH-01", "W-SSRF-01"}, value


# ---- W-XSS-01 ----------------------------------------------------------------------

XSS = ["<script>alert(1)</script>", '"><img src=x onerror=alert(1)>', "<svg/onload=alert(1)>",
       "javascript:alert(document.cookie)", "<iframe src=//evil>", "<body onload=x()>",
       "%3Cscript%3Ealert(1)%3C%2Fscript%3E", "<ScRiPt>alert(1)</sCrIpT>",
       "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e"]  # full-width < > folded by NFKC


@pytest.mark.parametrize("payload", XSS)
def test_xss(c, settings, payload):
    c.get("/search", params={"q": payload})
    d = by_rule(last(settings), "W-XSS-01")
    assert d["owasp"].startswith("A03") and d["attack"][0]["technique"] == "T1189"


# ---- W-PATH-01 ---------------------------------------------------------------------

TRAV = ["../../etc/passwd", "..\\..\\windows\\win.ini", "....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%252e%252e%252fetc%252fpasswd",
        "manifest-template.csv%00.php", "/proc/self/environ", "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "\uff0e\uff0e\uff0fetc\uff0fpasswd"]  # full-width ../


@pytest.mark.parametrize("payload", TRAV)
def test_traversal_in_query(c, settings, payload):
    r = c.get("/download", params={"file": payload})
    assert r.status_code == 404
    d = by_rule(last(settings), "W-PATH-01")
    assert d["field"] == "query.file" and "no file was opened" in d["rationale"]


def test_traversal_in_path(c, settings):
    c.get("/static/%2e%2e/%2e%2e/etc/passwd")
    assert by_rule(last(settings), "W-PATH-01")["field"] == "path"


def test_legit_download_not_flagged(c, settings):
    c.get("/download", params={"file": "manifest-template.csv"})
    assert "W-PATH-01" not in rules(last(settings))


# ---- general -----------------------------------------------------------------------

def test_one_detection_per_rule_with_field_count(c, settings):
    c.get("/search", params={"q": "' OR 1=1--", "sort": "1 UNION SELECT 1", "page": "x' AND SLEEP(1)#"})
    e = last(settings)
    assert [d["rule"] for d in dets(e)].count("W-SQLI-01") == 1
    assert "matched in 3 fields" in by_rule(e, "W-SQLI-01")["rationale"]


def test_detection_rationale_never_contains_the_value(c, settings):
    marker = "UNIQUEMARKER7731"
    c.get("/search", params={"q": f"' OR 1=1 -- {marker}"})
    for d in dets(last(settings)):
        assert marker.lower() not in d["rationale"].lower()


def test_no_t1505_003_ever(c, settings):
    for p in ["/shell.php", "/wp-content/uploads/cmd.php", "/uploads/x.jsp"]:
        c.get(p)
    c.post("/upload", files={"document": ("shell.php", b"<?php system($_GET['c']); ?>", "text/plain")})
    assert "T1505.003" not in open(settings.event_log_path).read()


def test_normalize_double_decodes_and_folds():
    assert normalize("%252e%252e%252f")[0] == "../"
    assert normalize("\uff1cSCRIPT\uff1e")[0] == "<script>"
    assert normalize("a%00b") == ("ab", True)
    assert len(normalize("x" * 100000)[0]) == 2048
