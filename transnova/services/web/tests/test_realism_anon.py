"""Phase 2: TransNova realism pages, Tor/VPN labelling (W-ANON-01/02) and client fingerprints."""

import dataclasses

import pytest
from fastapi.testclient import TestClient

from web_decoy.app import create_app
from .conftest import read_events
from .detect_helpers import dets, last, rules

TOR_IP = "185.220.101.7"     # public address; on our temporary list only
VPN_IP = "45.86.200.9"
HOST_IP = "34.120.1.2"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0"


def _client(app, ip, **headers):
    return TestClient(app, client=(ip, 40000), follow_redirects=False, headers=headers)


@pytest.fixture
def lists(tmp_path):
    d = tmp_path / "anon"
    d.mkdir()
    (d / "tor_exits.txt").write_text(f"{TOR_IP}\n# comment\nnot-an-ip\n")
    (d / "vpn_ipv4.txt").write_text("45.86.200.0/24\n")
    (d / "datacenter_ipv4.txt").write_text("34.64.0.0/10\n45.86.0.0/16\n")
    (d / "demo.txt").write_text("192.168.43.77 tor\n10.9.9.0/24 vpn\nbad line here\n")
    (d / "META.json").write_text('{"fetched_at": "2026-11-01T05:33:41Z"}')
    return d


@pytest.fixture
def app_anon(settings, lists):
    return create_app(dataclasses.replace(settings, anon_data_dir=str(lists)))


# ---- realism pages ------------------------------------------------------------------

@pytest.mark.parametrize("path, text", [
    ("/", "TransNova Logistics"), ("/status", "EDI gateway"), ("/changelog", "3.8.2"),
    ("/help", "EORI"), ("/login", "Partner sign in"),
])
def test_realism_pages_render_and_are_not_probes(client, settings, path, text):
    r = client.get(path)
    assert r.status_code == 200 and text in r.text
    assert "Halden" not in r.text
    assert not dets(last(settings))  # an ordinary page view, no rule fires


def test_robots_txt_leaks_bait_paths(client):
    r = client.get("/robots.txt")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    for p in ("/admin/", "/backup/", "/api/"):
        assert f"Disallow: {p}" in r.text


def test_footer_links_back_to_main_site_and_shows_version(settings):
    app = create_app(dataclasses.replace(settings, main_site_url="http://192.168.43.10:8000"))
    r = _client(app, "203.0.113.10").get("/")
    assert 'href="http://192.168.43.10:8000"' in r.text and "Portal 3.8.2" in r.text


def test_legacy_js_bundle_leaks_endpoints(client):
    r = client.get("/static/js/portal.js")
    assert r.status_code == 200 and "/api/v1/preview" in r.text and "/admin/login" in r.text


def test_logged_in_portal_shows_activity_feed(client):
    client.post("/login", data={"username": "j.miller", "password": "TransNova#Spring26"})
    r = client.get("/portal")
    assert "Recent activity" in r.text and "min ago" in r.text


def test_every_response_has_a_request_id(client):
    assert len(client.get("/").headers["x-request-id"]) == 16


# ---- anonymizer labelling -----------------------------------------------------------

def test_tor_exit_is_allowed_but_labelled(app_anon, settings):
    r = _client(app_anon, TOR_IP).get("/login")
    assert r.status_code == 200  # the honeypot lets Tor in: we want the activity
    e = last(settings)
    assert "W-ANON-01" in rules(e) and "anon:tor" in e["tags"]
    d = next(x for x in dets(e) if x["rule"] == "W-ANON-01")
    assert d["attack"][0]["technique"] == "T1090.003" and d["attack"][0]["status"] == "candidate"
    assert "owasp" not in d
    assert e["raw_evidence_redacted"]["anonymizer"] == {
        "category": "tor", "source": "tor_exit_list", "list_date": "2026-11-01T05:33:41Z"}


def test_vpn_beats_hosting_and_hosting_is_labelled(app_anon, settings):
    _client(app_anon, VPN_IP).get("/")
    assert last(settings)["raw_evidence_redacted"]["anonymizer"]["category"] == "vpn"
    _client(app_anon, HOST_IP).get("/")
    e = last(settings)
    assert e["raw_evidence_redacted"]["anonymizer"]["category"] == "hosting"
    d = next(x for x in dets(e) if x["rule"] == "W-ANON-02")
    assert d["confidence"] == "low" and d["attack"][0]["technique"] == "T1090"


def test_private_addresses_only_match_through_demo_list(app_anon, settings):
    _client(app_anon, "192.168.43.77").get("/")
    e = last(settings)
    assert e["raw_evidence_redacted"]["anonymizer"]["source"] == "demo"
    assert "demo list" in next(x for x in dets(e) if x["rule"] == "W-ANON-01")["rationale"]
    _client(app_anon, "192.168.43.78").get("/")
    assert "anonymizer" not in last(settings)["raw_evidence_redacted"]


def test_ordinary_public_ip_is_not_labelled(app_anon, settings):
    _client(app_anon, "203.0.113.10").get("/")
    _client(app_anon, "8.8.4.4").get("/")
    for e in read_events(settings):
        assert "anonymizer" not in e["raw_evidence_redacted"]
        assert not ({"W-ANON-01", "W-ANON-02"} & rules(e))


def test_lists_reload_when_files_change(app_anon, settings, lists):
    intel = app_anon.state.anon
    assert intel.classify("198.51.100.1") is None
    (lists / "demo.txt").write_text("198.51.100.1 vpn\n")
    intel._checked = 0  # skip the 30 s recheck interval in the test
    assert intel.classify("198.51.100.1").category == "vpn"


def test_missing_or_broken_lists_never_break_the_decoy(settings, tmp_path):
    (tmp_path / "empty").mkdir()
    app = create_app(dataclasses.replace(settings, anon_data_dir=str(tmp_path / "empty")))
    assert _client(app, TOR_IP).get("/").status_code == 200
    app.state.anon = None  # module unavailable
    assert _client(app, TOR_IP).get("/").status_code == 200


# ---- client fingerprint -------------------------------------------------------------

def test_fingerprint_links_one_client_across_ips_without_storing_headers(app_anon, settings):
    _client(app_anon, TOR_IP, **{"user-agent": UA, "accept-language": "pl-PL"}).get("/")
    _client(app_anon, VPN_IP, **{"user-agent": UA, "accept-language": "pl-PL"}).get("/")
    _client(app_anon, VPN_IP, **{"user-agent": "curl/8.5.0"}).get("/")
    fps = [e["raw_evidence_redacted"]["client_fp"] for e in read_events(settings)]
    assert fps[0] == fps[1] != fps[2]
    assert len(fps[0]) == 16 and "pl-PL" not in str(read_events(settings)[0]["raw_evidence_redacted"]["client_fp"])
