"""Main site: real service pages, Tor/VPN/hosting block, the trail to the portal, and safety."""

import ast
import dataclasses
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from anonintel import AnonIntel
from mainsite.app import create_app
from mainsite.config import Settings

TOR_IP, VPN_IP, HOST_IP, CLEAN_IP = "185.220.101.7", "45.86.200.9", "34.120.1.2", "8.8.4.4"
PORTAL = "http://192.168.43.10:8081"


@pytest.fixture
def lists(tmp_path):
    d = tmp_path / "anon"
    d.mkdir()
    (d / "tor_exits.txt").write_text(f"{TOR_IP}\n")
    (d / "vpn_ipv4.txt").write_text("45.86.200.0/24\n")
    (d / "datacenter_ipv4.txt").write_text("34.64.0.0/10\n")
    (d / "demo.txt").write_text("192.168.43.77 tor\n")
    return d


@pytest.fixture
def settings(tmp_path, lists):
    return Settings(portal_url=PORTAL, anon_data_dir=str(lists), access_log_path=str(tmp_path / "blocked.jsonl"))


@pytest.fixture
def app(settings, lists):
    return create_app(settings, intel=AnonIntel(lists))


def client(app, ip=CLEAN_IP, **kw):
    return TestClient(app, client=(ip, 50000), follow_redirects=False, **kw)


# ---- the real service works ----------------------------------------------------------

@pytest.mark.parametrize("path, text", [("/", "Next sailings"), ("/services", "Customs brokerage"),
                                         ("/about", "1988"), ("/careers", "Customs Declarant"),
                                         ("/contact", "Get a quote"), ("/tracking", "Track a shipment")])
def test_pages(app, path, text):
    r = client(app).get(path)
    assert r.status_code == 200 and text in r.text


def test_tracking_lookup_and_unknown_number(app):
    r = client(app).get("/tracking", params={"number": "tnl-50211"})
    assert "In transit" in r.text and "Kiel Canal" in r.text
    assert "No shipment found" in client(app).get("/tracking", params={"number": "XYZ"}).text


def test_tracking_reflection_is_escaped(app):
    r = client(app).get("/tracking", params={"number": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in r.text and "&lt;script&gt;" in r.text


def test_contact_stores_nothing_and_escapes(app, tmp_path):
    r = client(app).post("/contact", data={"name": "<b>Ann</b>", "email": "a@b.c", "message": "2 x 40ft"})
    assert r.status_code == 200 and "Thank you, &lt;b&gt;Ann&lt;/b&gt;" in r.text
    assert not (tmp_path / "blocked.jsonl").exists()


def test_oversized_and_chunked_posts_refused(app):
    assert client(app).post("/contact", data={"name": "a", "message": "x" * 20000}).status_code == 413
    r = client(app).post("/contact", content=iter([b"name=a&message=b"]),
                         headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 413  # no Content-Length (chunked)
    r = client(app).post("/contact", data={"name": "a" * 101, "message": "b"})
    assert r.status_code == 400 and "{" not in r.text  # never FastAPI's JSON 422


def test_security_headers_and_no_framework_fingerprints(app):
    r = client(app).get("/")
    assert r.headers["x-frame-options"] == "DENY" and "script-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["server"] == "nginx"
    for p in ("/docs", "/openapi.json", "/redoc"):
        assert client(app).get(p).status_code == 404


def test_errors_are_html_not_json(app):
    r = client(app).get("/nope")
    assert r.status_code == 404 and "Page not found" in r.text and "detail" not in r.text


# ---- Tor / VPN / hosting block -------------------------------------------------------

@pytest.mark.parametrize("ip, category", [(TOR_IP, "tor"), (VPN_IP, "vpn"), (HOST_IP, "hosting"),
                                          ("192.168.43.77", "tor")])
def test_anonymizers_blocked_and_logged(app, settings, ip, category):
    r = client(app, ip).get("/tracking?number=TNL50211")
    assert r.status_code == 403 and "Access restricted" in r.text and "Kiel" not in r.text
    rec = json.loads(Path(settings.access_log_path).read_text().splitlines()[-1])
    assert rec["ip"] == ip and rec["category"] == category and rec["path"] == "/tracking"


def test_block_happens_before_routes_even_for_admin_trail(app):
    assert client(app, TOR_IP).get("/admin").status_code == 403  # no redirect leak to Tor users


def test_clean_and_private_visitors_allowed(app):
    assert client(app, CLEAN_IP).get("/").status_code == 200
    assert client(app, "192.168.43.50").get("/").status_code == 200


def test_forwarded_headers_cannot_bypass_or_frame_someone(app):
    # Tor user claiming a clean address: still blocked.
    assert client(app, TOR_IP, headers={"X-Forwarded-For": CLEAN_IP}).get("/").status_code == 403
    # Clean user claiming a Tor address: still allowed (header ignored).
    assert client(app, CLEAN_IP, headers={"X-Forwarded-For": TOR_IP}).get("/").status_code == 200


def test_block_categories_configurable(settings, lists):
    app = create_app(dataclasses.replace(settings, block_categories=("tor",)), intel=AnonIntel(lists))
    assert client(app, VPN_IP).get("/").status_code == 200
    assert client(app, TOR_IP).get("/").status_code == 403


def test_env_parsing_of_block_list(monkeypatch):
    monkeypatch.setenv("ANON_BLOCK", "tor, bogus ,VPN")
    assert Settings.from_env().block_categories == ("tor", "vpn")
    monkeypatch.setenv("ANON_BLOCK", "")
    assert Settings.from_env().block_categories == ()


def test_missing_lists_serve_everyone(settings, tmp_path):
    (tmp_path / "none").mkdir()
    app = create_app(settings, intel=AnonIntel(tmp_path / "none"))
    assert client(app, TOR_IP).get("/").status_code == 200


# ---- the trail to the partner portal (honeypot) --------------------------------------

def test_admin_and_partner_paths_redirect_to_portal(app):
    assert client(app).get("/admin").headers["location"] == PORTAL + "/admin/login"
    assert client(app).get("/partners").headers["location"] == PORTAL + "/login"


def test_leaks_point_to_portal(app):
    home = client(app).get("/").text
    assert f"<!-- partner portal moved to separate host (OPS-412): {PORTAL} -->" in home
    assert f'href="{PORTAL}/login"' in home
    assert "Disallow: /admin" in client(app).get("/robots.txt").text
    assert PORTAL in client(app).get("/js/site.js").text


def test_healthz_details_only_locally(app):
    assert client(app).get("/healthz").text == "ok"
    body = client(app, "127.0.0.1").get("/healthz").json()
    assert body["status"] == "ok" and body["anon_lists"]["counts"]["tor_exit_list"] == 1


# ---- safety ----------------------------------------------------------------------------

def test_no_dangerous_calls_or_unsafe_templates():
    pkg = Path(__file__).resolve().parents[1] / "mainsite"
    for py in pkg.glob("*.py"):
        tree = ast.parse(py.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                assert node.func.id not in ("eval", "exec", "compile", "__import__"), py
            if isinstance(node, ast.Import):
                assert not {a.name for a in node.names} & {"subprocess", "pickle", "httpx", "requests"}, py
    for tpl in (pkg / "templates").glob("*.html"):
        assert "|safe" not in tpl.read_text() and "autoescape false" not in tpl.read_text(), tpl


def test_server_never_trusts_proxy_headers():
    from mainsite.serve import build_config
    cfg = build_config()
    assert cfg.proxy_headers is False and cfg.host == "127.0.0.1"
