"""Phase 3: delivery to the collector, spool fallback, replay (PLAN §4.2).

All network traffic goes to an in-process httpx.MockTransport. This is a test
fixture, not a second collector.
"""

import asyncio
import json
from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from web_decoy.app import create_app
from web_decoy.telemetry.emitter import Emitter
from web_decoy.telemetry.replay import replay
from .conftest import LAB_IP, OUTSIDE_IP, read_events

URL = "http://collector.test/api/events"


class MockCollector:
    def __init__(self, status=200, fail_times=0, raise_exc=False):
        self.status, self.fail_times, self.raise_exc = status, fail_times, raise_exc
        self.batches: list[list[dict]] = []
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.raise_exc:
            raise httpx.ConnectError("refused", request=request)
        if self.fail_times > 0:
            self.fail_times -= 1
            return httpx.Response(503)
        self.batches.append(json.loads(request.content))
        return httpx.Response(self.status)

    @property
    def transport(self):
        return httpx.MockTransport(self.handler)


def _ev(i):
    return {"event_id": f"id-{i}", "raw_evidence_redacted": {}}


@pytest.fixture
def s(settings):
    return replace(settings, collector_url=URL, flush_interval_s=0.05)


def _spool_lines(settings):
    try:
        with open(settings.spool_path) as fh:
            return [json.loads(x) for x in fh if x.strip()]
    except FileNotFoundError:
        return []


def test_end_to_end_batch_delivery(s):
    col = MockCollector()
    app = create_app(s, emitter=Emitter(s, transport=col.transport))
    with TestClient(app, client=(OUTSIDE_IP, 1)) as c:  # `with` runs startup/shutdown
        for _ in range(3):
            c.get("/.env")
        asyncio.run(asyncio.sleep(0))  # yield; delivery happens on the app loop
        lab = TestClient(app, client=(LAB_IP, 1))
        for _ in range(50):
            if lab.get("/health").json()["events_delivered_total"] >= 3:
                break
            import time; time.sleep(0.05)
    delivered = [e for b in col.batches for e in b]
    assert len(delivered) == 3
    assert all(isinstance(b, list) and len(b) <= s.batch_size for b in col.batches)
    assert {e["request_path"] for e in delivered} == {"/.env"}
    req = col.requests[0]
    assert req.method == "POST" and req.headers["content-type"] == "application/json"
    assert len(read_events(s)) == 3  # JSONL always written too


def test_batches_capped_at_batch_size(s):
    col = MockCollector()

    async def run():
        em = Emitter(s, transport=col.transport)
        await em.start()
        for i in range(120):
            em.emit(_ev(i))
        for _ in range(100):
            if em.delivered_events == 120:
                break
            await asyncio.sleep(0.02)
        await em.stop()
        return em

    em = asyncio.run(run())
    assert em.delivered_events == 120
    assert max(len(b) for b in col.batches) <= 50


@pytest.mark.parametrize("col", [MockCollector(status=500), MockCollector(raise_exc=True)],
                         ids=["http-500", "connection-refused"])
def test_collector_failure_spools(s, col):
    async def run():
        em = Emitter(s, transport=col.transport)
        await em.start()
        for i in range(5):
            em.emit(_ev(i))
        for _ in range(100):
            if em.spooled_events >= 5:
                break
            await asyncio.sleep(0.02)
        await em.stop()
        return em

    em = asyncio.run(run())
    assert em.reachable is False and em.last_error
    assert [e["event_id"] for e in _spool_lines(s)] == [f"id-{i}" for i in range(5)]
    assert em.stats()["status"] == "degraded"


def test_queue_full_drops_but_jsonl_keeps(s):
    s2 = replace(s, queue_capacity=3)

    async def run():
        em = Emitter(s2, transport=MockCollector().transport)
        em.queue = asyncio.Queue(maxsize=3)  # queue present, no consumer running
        for i in range(10):
            em.emit(_ev(i))
        return em

    em = asyncio.run(run())
    assert em.dropped_events == 7
    assert len(read_events(s2)) == 10


def test_stop_spools_undelivered_events(s):
    async def run():
        em = Emitter(s, transport=MockCollector().transport)
        em.queue = asyncio.Queue(maxsize=100)
        em._task = asyncio.create_task(asyncio.sleep(3600))  # stand-in consumer
        for i in range(4):
            em.emit(_ev(i))
        await em.stop()

    asyncio.run(run())
    assert len(_spool_lines(s)) == 4


def test_no_collector_url_means_jsonl_only(settings):
    async def run():
        em = Emitter(settings)
        await em.start()
        em.emit(_ev(1))
        await em.stop()
        return em

    em = asyncio.run(run())
    assert em.queue is None and len(read_events(settings)) == 1


def test_client_ignores_proxy_env_and_redirects(s, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://evil-proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://evil-proxy.invalid:3128")
    col = MockCollector(status=302)

    async def run():
        em = Emitter(s, transport=col.transport)
        async with em._client() as client:
            assert client._trust_env is False
            return await em.send_batch(client, [_ev(1)])

    assert asyncio.run(run()) is False  # a redirect is not success, and is not followed
    assert len(col.requests) == 1


def test_replay_sends_and_empties_spool(s):
    with open(s.spool_path, "w") as fh:
        for i in range(120):
            fh.write(json.dumps(_ev(i)) + "\n")
    col = MockCollector()
    sent, remaining = asyncio.run(replay(s, transport=col.transport))
    assert (sent, remaining) == (120, 0)
    assert _spool_lines(s) == []
    assert [e["event_id"] for b in col.batches for e in b] == [f"id-{i}" for i in range(120)]


def test_replay_partial_failure_keeps_unsent(s):
    with open(s.spool_path, "w") as fh:
        for i in range(120):
            fh.write(json.dumps(_ev(i)) + "\n")
        fh.write("{torn line\n")
    col = MockCollector()
    calls = {"n": 0}

    def flaky(request):
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] == 1 else 503)

    sent, remaining = asyncio.run(replay(s, transport=httpx.MockTransport(flaky)))
    assert (sent, remaining) == (50, 70)
    assert [e["event_id"] for e in _spool_lines(s)] == [f"id-{i}" for i in range(50, 120)]


def test_log_rotation_caps_size(settings):
    s2 = replace(settings, max_log_bytes=2000)
    em = Emitter(s2)
    for i in range(100):
        em.emit({"event_id": f"id-{i}", "pad": "x" * 50, "raw_evidence_redacted": {}})
    from pathlib import Path
    p = Path(s2.event_log_path)
    assert p.stat().st_size <= 2000
    assert p.with_name(p.name + ".1").exists()
