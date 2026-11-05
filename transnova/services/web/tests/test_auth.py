"""Phase 2 exit tests: synthetic login, sessions and session-only pages."""

import pytest

from web_decoy import fixtures
from web_decoy.routes.auth import GENERIC_ERROR
from web_decoy.sessions import COOKIE_NAME, SessionStore
from .conftest import GOOD_PASS, GOOD_USER


def test_login_page_has_form(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert 'name="username"' in r.text and 'type="password"' in r.text


@pytest.mark.parametrize(
    "username,password",
    [
        (GOOD_USER, "wrong"),
        ("nobody", GOOD_PASS),           # right password, wrong user
        ("nobody", "wrong"),
        (GOOD_USER, ""),
        ("", ""),
        ("admin' OR '1'='1", "x' OR '1'='1"),  # SQLi-like input must not bypass
        (GOOD_USER.upper(), GOOD_PASS),  # case-sensitive
        (GOOD_USER + " ", GOOD_PASS),
    ],
)
def test_failed_login_is_generic_401(client, username, password):
    r = client.post("/login", data={"username": username, "password": password})
    assert r.status_code == 401
    assert GENERIC_ERROR in r.text
    assert COOKIE_NAME not in r.headers.get("set-cookie", "")


def test_missing_fields_are_401_not_422(client):
    r = client.post("/login", content=b"", headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert r.status_code == 401
    assert "detail" not in r.text


def test_overlong_fields_do_not_crash(client):
    r = client.post("/login", data={"username": "u" * 10000, "password": "p" * 10000})
    assert r.status_code == 401


def test_failed_login_does_not_echo_password(client):
    secret = "Sup3rS3cretTry!"
    r = client.post("/login", data={"username": GOOD_USER, "password": secret})
    assert secret not in r.text


def test_successful_login_sets_secure_cookie(client):
    r = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert r.status_code == 302
    assert r.headers["location"] == "/portal"
    cookie = r.headers["set-cookie"].lower()
    assert cookie.startswith(COOKIE_NAME + "=")
    assert "httponly" in cookie and "samesite=lax" in cookie and "path=/" in cookie


def test_session_tokens_are_unique(app):
    from fastapi.testclient import TestClient
    tokens = set()
    for _ in range(5):
        c = TestClient(app, client=("203.0.113.10", 1), follow_redirects=False)
        c.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
        tokens.add(c.cookies.get(COOKIE_NAME))
    assert len(tokens) == 5 and None not in tokens


def test_portal_after_login(logged_in):
    r = logged_in.get("/portal")
    assert r.status_code == 200
    assert "Jordan Miller" in r.text
    assert "#50211" in r.text and "#50212" in r.text
    assert "#50318" not in r.text  # another partner's shipment not listed


def test_shipment_page(logged_in):
    r = logged_in.get("/portal/shipments/50211")
    assert r.status_code == 200
    assert "Rotterdam" in r.text
    assert logged_in.get("/portal/shipments/99999").status_code == 404


def test_forged_cookie_is_rejected(client):
    client.cookies.set(COOKIE_NAME, "forged-token-value")
    assert client.get("/portal").status_code == 302
    assert client.get("/api/v1/users").status_code == 401


def test_huge_cookie_is_rejected(client):
    client.cookies.set(COOKIE_NAME, "A" * 4000)
    assert client.get("/portal").status_code == 302


def test_logout_invalidates_server_side_session(client):
    client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    token = client.cookies.get(COOKIE_NAME)
    assert client.post("/logout").status_code == 302
    # Replaying the old token must not work: the session was deleted server-side.
    client.cookies.set(COOKIE_NAME, token)
    assert client.get("/portal").status_code == 302


def test_admin_realm_login(client):
    r = client.get("/admin/login")
    assert 'name="realm" value="admin"' in r.text
    assert "Administration console" in r.text
    bad = client.post("/login", data={"username": "admin", "password": "admin", "realm": "admin"})
    assert bad.status_code == 401 and "Administration console" in bad.text
    ok = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS, "realm": "admin"})
    assert ok.status_code == 302 and ok.headers["location"] == "/portal"


def test_realm_value_is_not_reflected(client):
    r = client.post("/login", data={"username": "x", "password": "y", "realm": '"><b>x'})
    assert '"><b>x' not in r.text
    assert 'value="partner"' in r.text


def test_api_with_session(logged_in):
    users = logged_in.get("/api/v1/users").json()["users"]
    assert {u["id"] for u in users} == set(fixtures.USERS)
    assert all(set(u) == {"id", "username"} for u in users)
    assert logged_in.get("/api/v1/users/1001").json()["name"] == "Jordan Miller"
    # IDOR bait: another user's record is returned by design (detected in Phase 4).
    assert logged_in.get("/api/v1/users/1002").status_code == 200
    assert logged_in.get("/api/v1/users/4242").status_code == 404
    orders = logged_in.get("/api/v1/orders").json()["orders"]
    assert {o["id"] for o in orders} == {9001, 9002}


def test_fixtures_contain_no_password_fields():
    from web_decoy import fixtures
    for u in fixtures.USERS.values():
        assert not any("pass" in k.lower() for k in u)


def test_session_store_is_bounded():
    store = SessionStore(max_sessions=3)
    tokens = [store.create(1001, "j.miller")[0] for _ in range(5)]
    assert len(store) == 3
    assert store.get(tokens[0]) is None and store.get(tokens[-1]) is not None
