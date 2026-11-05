"""Reading the collector needs the read token, and SSH data cannot arrive while reads are open.

Tokens are random and never shown. PYTEST_DONT_REWRITE turns off pytest's assertion detail, so a
failure cannot print one.
"""

from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any, Iterator

import httpx
import pytest
from fastapi.testclient import TestClient

from collector_support import REPO, Server, auth, real_collector, web_event, write_tokens
from test_collector_contract import capture_events

ROUTES = ["/api/events", "/api/alerts", "/api/attackers", "/api/attackers/10.0.0.1", "/api/adaptations", "/api/database/summary",
          "/api/sensors"]
# The SOC console's reads (collector/console_api.py) sit behind the same read token.
V2_ROUTES = ["/api/v2/cursor", "/api/v2/summary", "/api/v2/events", "/api/v2/events/facets", "/api/v2/events/x",
             "/api/v2/alerts", "/api/v2/alerts/x", "/api/v2/sources", "/api/v2/sources/10.0.0.1", "/api/v2/sensors",
             "/api/v2/ingestion", "/api/v2/rules", "/api/v2/mitre", "/api/v2/owasp", "/api/v2/blocklist",
             "/api/v2/navigator"]


class Lab:
    def __init__(self, folder: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("COLLECTOR_DB_PATH", str(folder / "c.db"))
        self.ssh_token, self.read_token, self.settings = write_tokens(folder)
        for name, value in self.settings.items():
            monkeypatch.setenv(name, value)
        import collector.app as module

        importlib.reload(module)
        self.module = module
        self.client = TestClient(module.app)
        self.read = auth(self.read_token)
        self.write = auth(self.ssh_token)
        assert self.client.post("/api/events", json=[web_event("one")]).status_code == 200


@pytest.fixture
def lab(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Lab:
    return Lab(tmp_path, monkeypatch)


def test_this_list_covers_every_real_read_route(lab: Lab) -> None:
    real = {route.path for route in lab.module.api.routes if "GET" in getattr(route, "methods", ())}
    assert real == {"/api/events", "/api/alerts", "/api/attackers", "/api/attackers/{source_ip}", "/api/adaptations",
                    "/api/database/summary", "/api/sensors", "/health",
                    "/api/v2/cursor", "/api/v2/summary", "/api/v2/events", "/api/v2/events/facets", "/api/v2/events/{event_id}",
                    "/api/v2/alerts", "/api/v2/alerts/{alert_id}", "/api/v2/sources", "/api/v2/sources/{source_ip}",
                    "/api/v2/sensors", "/api/v2/ingestion", "/api/v2/rules", "/api/v2/mitre", "/api/v2/owasp",
                    "/api/v2/blocklist", "/api/v2/navigator"}


@pytest.mark.parametrize("path", [*ROUTES, *V2_ROUTES, "/nothing", "/api/nothing", "/api/events/", "/docs", "/"])
def test_no_token_reads_nothing(lab: Lab, path: str) -> None:
    response = lab.client.get(path, follow_redirects=False)
    assert response.status_code == 401 and response.json() == {"detail": "not authorized"}
    assert "one" not in response.text


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"])
def test_other_methods_are_denied_by_default(lab: Lab, method: str) -> None:
    assert lab.client.request(method, "/api/events").status_code == 401


@pytest.mark.parametrize("path", ROUTES)
def test_wrong_tokens_read_nothing(lab: Lab, path: str) -> None:
    for headers in (auth("wrong"), lab.write, {"Authorization": lab.read_token}, {"Authorization": f"bearer {lab.read_token}"}):
        assert lab.client.get(path, headers=headers).status_code == 401


@pytest.mark.parametrize("path", ROUTES)
def test_the_read_token_reads(lab: Lab, path: str) -> None:
    assert lab.client.get(path, headers=lab.read).status_code == 200


def test_two_authorization_headers_read_nothing(lab: Lab) -> None:
    import asyncio

    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    good = (b"authorization", b"Bearer " + lab.read_token.encode())
    scope = {"type": "http", "method": "GET", "path": "/api/events", "headers": [good, good]}
    asyncio.run(lab.module.app(scope, receive, send))
    assert sent[0]["status"] == 401


def test_health_says_only_up_without_a_token(lab: Lab) -> None:
    response = lab.client.get("/health")
    assert response.status_code == 200 and response.json() == {"status": "ok"}
    assert lab.client.get("/health", headers=auth("wrong")).json() == {"status": "ok"}


def test_health_gives_details_with_the_token(lab: Lab) -> None:
    assert lab.client.get("/health", headers=lab.read).json()["events_stored"] == 1


def test_the_read_token_cannot_write_ssh(lab: Lab) -> None:
    events = capture_events()[:5]
    assert lab.client.post("/api/events", json=events, headers=lab.read).status_code == 401
    assert lab.module.store.count_events() == 1


@pytest.mark.parametrize("content", [None, b"", b" \n", b"a" * 5000, b"\xff\xfe"])
def test_a_broken_read_secret_refuses_reads_and_ssh_but_not_writes(lab: Lab, content: bytes | None) -> None:
    path = Path(lab.settings["SOC_READ_TOKEN_FILE"])
    path.unlink() if content is None else path.write_bytes(content)
    assert lab.client.get("/api/events", headers=lab.read).status_code == 503
    assert lab.client.get("/health").json() == {"status": "ok"}
    assert lab.client.post("/api/events", json=capture_events()[:5], headers=lab.write).status_code == 503
    assert lab.client.post("/api/events", json=[web_event("two")]).status_code == 200
    assert lab.module.store.count_events() == 2


def test_with_the_setting_absent_reads_stay_open_and_ssh_is_refused(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_READ_TOKEN_FILE")
    assert lab.client.get("/api/events").status_code == 200
    assert lab.client.get("/health").json()["events_stored"] == 1
    assert lab.client.post("/api/events", json=capture_events()[:5], headers=lab.write).status_code == 503
    assert lab.module.store.count_events() == 1


def test_with_both_tokens_ssh_is_accepted(lab: Lab) -> None:
    assert lab.client.post("/api/events", json=capture_events()[:5], headers=lab.write).status_code == 200


def test_the_same_token_for_read_and_write_refuses_ssh(lab: Lab) -> None:
    Path(lab.settings["SOC_READ_TOKEN_FILE"]).write_text(lab.ssh_token, encoding="ascii")
    assert lab.client.post("/api/events", json=capture_events()[:5], headers=lab.write).status_code == 503


def test_healthcheck_command_needs_no_token() -> None:
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")
    assert "/health" in compose and "Authorization" not in compose


def test_real_server_denies_reads_over_raw_sockets(tmp_path: Path) -> None:
    ssh_token, read_token, settings = write_tokens(tmp_path)
    with real_collector(tmp_path, env=settings) as server:
        assert server.read(b"/api/events")[0] == "401"
        assert server.read(b"/health") == ("200", b'{"status":"ok"}')
        assert server.read(b"/api/events", b"Authorization: Bearer %s\r\n" % ssh_token.encode())[0] == "401"
        good = b"Authorization: Bearer %s\r\n" % read_token.encode()
        assert server.read(b"/api/events", good)[0] == "200"
        assert server.read(b"/api/events", good + good)[0] == "401"


# -- the real dashboard ------------------------------------------------------------------------

@pytest.fixture
def dashboard(lab: Lab, monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    lab.client.post("/api/events", json=capture_events()[:50], headers=lab.write)

    def fake_get(url: str, params: Any = None, headers: Any = None, **_kwargs: Any) -> httpx.Response:
        response = lab.client.get(url.split("127.0.0.1:8000", 1)[-1], params=params, headers=headers or {})
        return httpx.Response(response.status_code, content=response.content, request=httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.delenv("COLLECTOR_BASE_URL", raising=False)
    yield AppTest.from_file(str(REPO / "dashboard" / "app.py"), default_timeout=60)


def page_text(app: Any) -> str:
    return json.dumps([str(element.value) for element in (*app.metric, *app.error, *app.warning, *app.text, *app.info)])


def test_dashboard_with_the_token_shows_data(lab: Lab, dashboard: Any) -> None:
    dashboard.run()
    assert not dashboard.exception and not dashboard.error
    assert dashboard.metric[0].value == "51"


@pytest.mark.parametrize("content", ["wrong-token\n", ""])
def test_dashboard_with_a_bad_token_shows_an_error_and_no_data(lab: Lab, dashboard: Any, content: str,
                                                               monkeypatch: pytest.MonkeyPatch) -> None:
    """Both run in this process, so the collector keeps the real token and the dashboard gets a bad file."""
    real = Path(lab.settings["SOC_READ_TOKEN_FILE"]).read_bytes().strip()
    bad = Path(lab.settings["SOC_READ_TOKEN_FILE"]).with_name("dashboard.token")
    bad.write_text(content, encoding="ascii")
    monkeypatch.setattr("collector.read_auth.token", lambda: real)
    monkeypatch.setenv("SOC_READ_TOKEN_FILE", str(bad))
    dashboard.run()
    assert not dashboard.exception
    assert len(dashboard.error) == 1 and "Collector unavailable" in dashboard.error[0].value
    assert not dashboard.metric
    text = page_text(dashboard)
    assert lab.read_token not in text and "wrong-token" not in text


def test_dashboard_with_no_setting_works_as_before(lab: Lab, dashboard: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOC_READ_TOKEN_FILE")
    dashboard.run()
    assert not dashboard.exception and not dashboard.error and dashboard.metric[0].value == "51"


def test_dashboard_warns_when_a_read_was_capped(lab: Lab, dashboard: Any) -> None:
    lab.module.store.read_capped_at = "2026-11-01T12:00:00+00:00"
    dashboard.run()
    assert any("may be incomplete" in w.value for w in dashboard.warning)
