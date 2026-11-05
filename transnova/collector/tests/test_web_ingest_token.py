"""Optional web ingest token (two-laptop deployment): off by default, fail-closed when misconfigured."""

from __future__ import annotations

import asyncio
import dataclasses
import sys

import httpx
import pytest

from conftest import ROOT, web_event

WEB = "web-token-for-tests"


@pytest.fixture
def web_token(tmp_path, monkeypatch):
    f = tmp_path / "web.token"
    f.write_text(WEB, encoding="ascii")
    monkeypatch.setenv("WEB_INGEST_TOKEN_FILE", str(f))
    return f


def test_default_off_keeps_existing_senders_working(client, monkeypatch):
    monkeypatch.delenv("WEB_INGEST_TOKEN_FILE", raising=False)
    assert client.post("/api/events", json=[web_event()]).status_code == 200


def test_web_batch_needs_the_token(client, web_token):
    assert client.post("/api/events", json=[web_event()]).status_code == 401
    assert client.post("/api/events", json=[web_event()], headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.post("/api/events", json=[web_event()], headers={"Authorization": f"Bearer {WEB}"}).status_code == 200


def test_mixed_batch_with_a_web_event_is_gated(client, web_token):
    batch = [web_event(service="database", sensor_id="db-01"), web_event()]
    assert client.post("/api/events", json=batch).status_code == 401


def test_broken_token_file_fails_closed(client, web_token):
    web_token.write_text("has space", encoding="ascii")
    r = client.post("/api/events", json=[web_event()], headers={"Authorization": "Bearer has space"})
    assert r.status_code == 503
    web_token.unlink()
    assert client.post("/api/events", json=[web_event()], headers={"Authorization": f"Bearer {WEB}"}).status_code == 503


def test_token_is_never_echoed(client, web_token):
    r = client.post("/api/events", json=[web_event()], headers={"Authorization": "Bearer guess"})
    assert WEB not in r.text and "guess" not in r.text


def test_real_decoy_emitter_sends_the_token(app, client, web_token, tmp_path):
    """The web decoy's real Emitter, pointed at the collector app, gets its batch stored."""
    sys.path[:0] = [str(ROOT / "services/web")]
    from web_decoy.config import Settings
    from web_decoy.telemetry.emitter import Emitter

    base = Settings(collector_url="http://collector/api/events", event_log_path=str(tmp_path / "e.jsonl"),
                    spool_path=str(tmp_path / "s.jsonl"))
    transport = httpx.ASGITransport(app=app.app)

    async def send(settings):
        em = Emitter(settings, transport=transport)
        await em.start()
        em.emit(web_event())
        await asyncio.sleep(1.5)
        await em.stop()
        return em

    without = asyncio.run(send(base))
    assert without.spool and (tmp_path / "s.jsonl").exists()  # refused: spooled, not lost
    with_token = asyncio.run(send(dataclasses.replace(base, collector_token=WEB, spool_path=str(tmp_path / "s2.jsonl"))))
    assert not (tmp_path / "s2.jsonl").exists() or not (tmp_path / "s2.jsonl").read_text().strip()
    assert "collector_token" not in repr(with_token.settings)
