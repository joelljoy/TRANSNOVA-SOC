"""Body limits on the real server path: uvicorn, h11, the guard and the collector, over raw sockets."""

from __future__ import annotations

import asyncio
import importlib
import json
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from collector import guards  # noqa: E402
from collector.guards import MAX_COMMAS, MAX_CONTAINERS, BodyGuard, too_complex  # noqa: E402

from collector_support import (MIB, POST_EVENTS, Server, chunked, event_request, post_request, real_collector,  # noqa: E402
                               web_event)


@pytest.fixture(scope="module")
def server(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Server]:
    with real_collector(tmp_path_factory.mktemp("collector")) as running:
        yield running


def body_of(event_id: str) -> bytes:
    return json.dumps([web_event(event_id)]).encode()


# -- conflicting framing -----------------------------------------------------------------------

BOTH_HEADERS = {
    "length_then_chunked": b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
    "chunked_then_length": b"Transfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n",
    "zero_length": b"Content-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
    "mixed_case": b"content-LENGTH: 5\r\nTRANSFER-encoding: CHUNKED\r\n\r\n",
    "same_length_twice": b"Content-Length: 5\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
}


@pytest.mark.parametrize("name", BOTH_HEADERS)
def test_both_framing_headers_are_refused_and_nothing_is_stored(server: Server, name: str) -> None:
    event_id = f"both-{name}"
    codes, closed = server.talk(POST_EVENTS + BOTH_HEADERS[name] + chunked(body_of(event_id)))
    assert codes == ["400"] and closed and not server.stored(event_id)


def test_both_headers_are_refused_before_any_body_byte_is_sent(server: Server) -> None:
    assert server.talk(POST_EVENTS + BOTH_HEADERS["length_then_chunked"], wait=2) == (["400"], True)


def test_a_smuggled_request_and_a_follower_are_never_stored(server: Server) -> None:
    smuggled, follower = event_request("smuggled"), event_request("follower")
    codes, closed = server.talk(POST_EVENTS + BOTH_HEADERS["length_then_chunked"] + b"0\r\n\r\n" + smuggled + follower)
    assert codes == ["400"] and closed
    assert not server.stored("smuggled") and not server.stored("follower")


@pytest.mark.parametrize("headers", [
    b"Content-Length: 5\r\nContent-Length: 6\r\n\r\n", b"Content-Length: 5, 6\r\n\r\n", b"Content-Length: +5\r\n\r\n",
    b"Content-Length: -1\r\n\r\n", b"Content-Length: abc\r\n\r\n", b"Transfer-Encoding: gzip, chunked\r\n\r\n",
    b"Transfer-Encoding: xchunked\r\n\r\n", b"Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"Transfer-Encoding : chunked\r\n\r\n", b"Content-Length: 5\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"Content-Length: 300\r\nTransfer-Encoding: identity\r\n\r\n"])
def test_invalid_framing_is_refused_by_the_parser(server: Server, headers: bytes) -> None:
    assert server.talk(POST_EVENTS + headers + body_of("x")) == (["400"], True)


def test_h11_keeps_both_headers_for_the_guard_to_see() -> None:
    """The guard depends on this. If an h11 update drops a header, this fails instead of the guard."""
    import h11

    connection = h11.Connection(h11.SERVER)
    connection.receive_data(b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n")
    names = {name for name, _ in connection.next_event().headers}
    assert {b"content-length", b"transfer-encoding"} <= names


def test_dockerfile_pins_the_parser_this_depends_on() -> None:
    root = Path(__file__).resolve().parents[4]
    assert '"--http", "h11"' in (root / "collector/Dockerfile").read_text(encoding="utf-8")
    assert "h11==" in (root / "collector/requirements.txt").read_text(encoding="utf-8")


@pytest.mark.parametrize("name,headers,tail", [
    ("control_length", b"Content-Length: {n}\r\n\r\n", False), ("control_chunked", b"Transfer-Encoding: chunked\r\n\r\n", True),
    ("duplicate_same_length", b"Content-Length: {n}\r\nContent-Length: {n}\r\n\r\n", False),
    ("comma_same_length", b"Content-Length: {n}, {n}\r\n\r\n", False)])
def test_framing_with_one_meaning_is_accepted(server: Server, name: str, headers: bytes, tail: bool) -> None:
    body = body_of(name)
    head = headers.replace(b"{n}", str(len(body)).encode())
    codes, closed = server.talk(POST_EVENTS + head + (chunked(body) if tail else body))
    assert codes == ["200"] and not closed and server.stored(name)


# -- bodies on requests that take none ---------------------------------------------------------

@pytest.mark.parametrize("request_line", [b"GET /health", b"HEAD /health", b"OPTIONS /health", b"PUT /api/events",
                                          b"DELETE /api/events", b"PATCH /api/events"])
@pytest.mark.parametrize("framing", [b"Content-Length: 5\r\n\r\nhello", b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
                                     b"Content-Length: 99999999\r\n\r\n"])
def test_a_body_on_any_other_method_is_refused(server: Server, request_line: bytes, framing: bytes) -> None:
    assert server.talk(request_line + b" HTTP/1.1\r\nHost: x\r\n" + framing) == (["400"], True)


@pytest.mark.parametrize("headers", [b"", b"Content-Length: 0\r\n"])
def test_an_empty_get_still_works(server: Server, headers: bytes) -> None:
    assert server.talk(b"GET /health HTTP/1.1\r\nHost: x\r\n" + headers + b"\r\n") == (["200"], False)


def test_post_to_an_unknown_path_is_refused_without_reading(server: Server) -> None:
    assert server.talk(b"POST /api/nothing HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n") == (["404"], True)


def test_every_real_post_route_has_a_limit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    import collector.app as module

    importlib.reload(module)
    routes = {route.path for route in module.api.routes if "POST" in getattr(route, "methods", ())}
    assert routes == set(guards.ROUTE_LIMITS)
    assert isinstance(module.app, BodyGuard)


# -- a refused request cannot leave anything behind ------------------------------------------

BIG = json.dumps([web_event("big", raw_evidence_redacted={"a": "x" * (17 * MIB)})]).encode()


def test_declared_oversize_is_refused_before_any_body_byte(server: Server) -> None:
    """Linux resets a socket that is still sending, which destroys the reply, so only headers go first."""
    assert server.talk(POST_EVENTS + b"Content-Length: %d\r\n\r\n" % len(BIG), wait=2) == (["413"], True)


def test_declared_oversize_leaves_the_follower_unstored(server: Server) -> None:
    server.talk(POST_EVENTS + b"Content-Length: %d\r\n\r\n" % len(BIG) + BIG + event_request("after-declared"), wait=2)
    assert not server.stored("after-declared")


def test_chunked_oversize_is_refused_and_the_follower_is_not_stored(server: Server) -> None:
    codes, closed = server.talk(POST_EVENTS + b"Transfer-Encoding: chunked\r\n\r\n" + chunked(BIG) + event_request("after-chunked"), wait=2)
    assert closed and not server.stored("after-chunked") and codes in ([], ["413"])


def test_get_with_a_body_cannot_hide_a_follower(server: Server) -> None:
    codes, closed = server.talk(b"GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n" + event_request("after-get"))
    assert codes == ["400"] and closed and not server.stored("after-get")


def test_junk_after_a_good_request_is_not_stored(server: Server) -> None:
    codes, closed = server.talk(POST_EVENTS + b"Content-Length: 2\r\n\r\n[]\x00\x01" + event_request("after-junk"))
    assert codes == ["200", "400"] and closed and not server.stored("after-junk")


def test_two_good_requests_on_one_socket_still_work(server: Server) -> None:
    assert server.talk(event_request("first") + event_request("second"))[0] == ["200", "200"]
    assert server.stored("first") and server.stored("second")


# -- sizes --------------------------------------------------------------------------------------

def event_of_size(size: int, event_id: str) -> bytes:
    empty = json.dumps([web_event(event_id, raw_evidence_redacted={"a": ""})]).encode()
    return json.dumps([web_event(event_id, raw_evidence_redacted={"a": "x" * (size - len(empty))})]).encode()


def declares(size: int, path: bytes = b"/api/events", extra: bytes = b"") -> bytes:
    return b"POST %s HTTP/1.1\r\nHost: x\r\n%sContent-Length: %d\r\n\r\n" % (path, extra, size)


def test_exactly_the_limit_passes_and_one_byte_more_does_not(server: Server) -> None:
    limit = 16 * MIB  # written out: a test must not read the value it is checking from the code
    assert len(event_of_size(limit, "at-limit")) == limit
    assert server.talk(post_request(event_of_size(limit, "at-limit")), wait=10)[0] == ["200"]
    assert server.talk(declares(limit + 1), wait=2) == (["413"], True)
    assert server.stored("at-limit")


def test_a_request_with_authorization_gets_the_small_limit(server: Server) -> None:
    assert server.talk(declares(MIB + 1, extra=b"Authorization: Bearer x\r\n"), wait=2) == (["413"], True)


def test_heartbeat_has_its_own_limit(server: Server) -> None:
    assert server.talk(declares(2 * MIB + 1, b"/api/sensors/heartbeat"), wait=2) == (["413"], True)
    normal = {"sensor_id": "db-01", "service": "database", "status": "ok", "details": {"a": "x" * MIB}}
    assert server.talk(post_request(json.dumps(normal).encode(), b"/api/sensors/heartbeat"), wait=2)[0] == ["200"]


def test_adaptations_keep_the_large_limit(server: Server) -> None:
    assert server.talk(declares(16 * MIB + 1, b"/api/adaptations"), wait=2) == (["413"], True)
    assert guards.ROUTE_LIMITS["/api/adaptations"] == 16 * MIB


def test_deep_nesting_is_refused_quickly(server: Server) -> None:
    deep = b"[" * 200_000 + b"]" * 200_000
    started = time.monotonic()
    assert server.talk(post_request(deep), wait=0.5)[0] == ["400"]
    assert time.monotonic() - started < 2


# -- time ---------------------------------------------------------------------------------------

def test_the_deadline_is_absolute_and_late_bytes_cannot_become_a_request(server: Server) -> None:
    """Real 15 second limit. One client keeps sending; a second sends part of a body and stops."""
    steady = socket.create_connection(("127.0.0.1", server.port), timeout=20)
    steady.sendall(POST_EVENTS + b"Content-Length: 1000\r\n\r\n")
    stalled = socket.create_connection(("127.0.0.1", server.port), timeout=20)
    stalled.sendall(POST_EVENTS + b"Content-Length: 500\r\n\r\n[")
    answers: list[tuple[bytes, float]] = []
    started = time.monotonic()
    threading.Thread(target=lambda: answers.append((steady.recv(100), time.monotonic() - started)), daemon=True).start()
    while not answers and time.monotonic() - started < 18:
        try:
            steady.sendall(b"x")
        except OSError:
            break
        time.sleep(0.25)
    time.sleep(0.2)
    assert answers and answers[0][0].startswith(b"HTTP/1.1 408") and 14.5 < answers[0][1] < 16.5
    assert stalled.recv(100).startswith(b"HTTP/1.1 408")
    try:
        stalled.sendall(b"x" * 499 + event_request("late"))
    except OSError:
        pass
    steady.close()
    stalled.close()
    time.sleep(0.2)
    assert not server.stored("late")


# -- the budget ---------------------------------------------------------------------------------

class Parts:
    """A guard around a small application, so each moment can be inspected."""

    def __init__(self, budget: int = 1000, deadline_s: float = 5.0) -> None:
        self.entered = asyncio.Event()
        self.finish = asyncio.Event()
        self.failure: Exception | None = None
        self.bodies: list[bytes] = []
        self.guard = BodyGuard(self._app, deadline_s=deadline_s, budget=budget)

    async def _app(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        self.bodies.append((await receive())["body"])
        self.entered.set()
        await self.finish.wait()
        if self.failure:
            raise self.failure
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})


def scope(size: int | None = None) -> dict[str, Any]:
    headers = [] if size is None else [(b"content-length", str(size).encode())]
    return {"type": "http", "method": "POST", "path": "/api/events", "headers": headers}


def run(steps: Any) -> Any:
    return asyncio.run(asyncio.wait_for(steps(), 10))


def collect() -> tuple[list[dict[str, Any]], Any]:
    sent: list[dict[str, Any]] = []

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    return sent, send


def whole(body: bytes) -> Any:
    delivered = [{"type": "http.request", "body": body, "more_body": False}]

    async def receive() -> dict[str, Any]:
        if delivered:
            return delivered.pop()
        await asyncio.Event().wait()
        raise AssertionError

    return receive


def test_budget_stays_held_until_the_application_finishes() -> None:
    async def steps() -> None:
        parts = Parts()
        sent, send = collect()
        task = asyncio.create_task(parts.guard(scope(600), whole(b"x" * 600), send))
        await parts.entered.wait()
        assert parts.guard.in_use == 600  # parsing, validation and storage all happen in here
        other_sent, other_send = collect()
        await parts.guard(scope(600), whole(b"y" * 600), other_send)
        assert other_sent[0]["status"] == 503 and parts.bodies == [b"x" * 600]
        parts.finish.set()
        await task
        assert parts.guard.in_use == 0 and sent[0]["status"] == 200

    run(steps)


def test_budget_is_released_when_the_application_raises() -> None:
    async def steps() -> None:
        parts = Parts()
        parts.failure = RuntimeError("storage failed")
        parts.finish.set()
        with pytest.raises(RuntimeError):
            await parts.guard(scope(600), whole(b"x" * 600), collect()[1])
        assert parts.guard.in_use == 0

    run(steps)


def test_budget_is_released_when_the_client_disconnects_mid_body() -> None:
    async def steps() -> None:
        parts = Parts()
        messages = [{"type": "http.request", "body": b"x" * 100, "more_body": True}, {"type": "http.disconnect"}]

        async def receive() -> dict[str, Any]:
            return messages.pop(0)

        await parts.guard(scope(600), receive, collect()[1])
        assert parts.guard.in_use == 0 and not parts.bodies

    run(steps)


def test_budget_is_released_on_timeout() -> None:
    async def steps() -> None:
        parts = Parts(deadline_s=0.05)

        async def receive() -> dict[str, Any]:
            await asyncio.Event().wait()
            raise AssertionError

        sent, send = collect()
        await parts.guard(scope(600), receive, send)
        assert parts.guard.in_use == 0 and sent[0]["status"] == 408

    run(steps)


def test_chunked_bytes_are_counted_as_they_arrive() -> None:
    async def steps() -> None:
        parts = Parts()
        parts.guard.in_use = 950
        messages = [{"type": "http.request", "body": b"x" * 40, "more_body": True},
                    {"type": "http.request", "body": b"x" * 40, "more_body": False}]

        async def receive() -> dict[str, Any]:
            return messages.pop(0)

        sent, send = collect()
        await parts.guard(scope(), receive, send)
        assert sent[0]["status"] == 503 and parts.guard.in_use == 950

    run(steps)


def test_refusals_ask_for_the_connection_to_close() -> None:
    async def steps() -> None:
        sent, send = collect()
        await Parts().guard({"type": "http", "method": "POST", "path": "/nothing", "headers": []}, whole(b""), send)
        assert (b"connection", b"close") in sent[0]["headers"]

    run(steps)


def test_senders_are_not_starved_by_a_slow_body(server: Server) -> None:
    slow = socket.create_connection(("127.0.0.1", server.port), timeout=5)
    slow.sendall(POST_EVENTS + b"Content-Length: 1000\r\n\r\n[")
    assert server.talk(event_request("beside-slow"))[0] == ["200"] and server.stored("beside-slow")
    slow.close()


# -- structure ----------------------------------------------------------------------------------

DB_NAMES = ",".join(f'"t{i:04d}"' for i in range(13_104))
FILTHY_NAMES = ",".join(f'"[,{{{i}"' for i in range(13_104))


@pytest.mark.parametrize("body", [
    pytest.param(("[" + ",".join(['{"table_names":[' + DB_NAMES + "]}"] * 50) + "]").encode(), id="worst_database_batch"),
    pytest.param(("[" + ",".join(['{"table_names":[' + FILTHY_NAMES + '],"command":"[,{"}'] * 50) + "]").encode(), id="names_full_of_brackets"),
    pytest.param(b'[{"command":"' + b"[" * (15 * MIB) + b'"}]', id="brackets_in_text"),
    pytest.param(b'[{"command":"' + b"," * (15 * MIB) + b'"}]', id="commas_in_text"),
    pytest.param(b'[{"command":"' + b'\\"[,' * (3 * MIB) + b'"}]', id="escaped_quotes_in_text"),
    pytest.param(b"[" + b'"[",' * (MAX_COMMAS - 1) + b'"a"]', id="just_under_the_comma_limit"),
    pytest.param(b"[" * (MAX_CONTAINERS - 1) + b'"' + b"x" * MIB + b'"' + b"]" * (MAX_CONTAINERS - 1), id="just_under_the_container_limit"),
])
def test_text_and_real_batches_are_never_rejected(body: bytes) -> None:
    assert not too_complex(body)


@pytest.mark.parametrize("body", [
    pytest.param(b"[" + b"{}," * (5 * MIB) + b"1]", id="empty_objects"),
    pytest.param(b"[" + b"[]," * (5 * MIB) + b"1]", id="empty_lists"),
    pytest.param(b"[" + b"0.1," * (4 * MIB) + b"1]", id="floats"),
    pytest.param(b"[" + b'"a",' * (4 * MIB) + b'"a"]', id="short_strings"),
    pytest.param(b"[" + b'"[",' * (MAX_COMMAS + 2) + b'"a"]', id="just_over_the_comma_limit"),
])
def test_structure_that_costs_memory_is_rejected(body: bytes) -> None:
    assert too_complex(body)


def test_small_bodies_are_not_scanned() -> None:
    assert not too_complex(b"[" + b"{}," * 300_000 + b"1]")


def test_the_real_server_refuses_expensive_structure(server: Server) -> None:
    """One valid event, so only the structure check can refuse it: a long list is refused by the
    batch limit, which is also a 413."""
    head = json.dumps([web_event("structure", raw_evidence_redacted={"a": "HERE"})]).encode()
    body = head.replace(b'"HERE"', b"[" + b"[]," * 500_000 + b"1]")
    assert MIB < len(body) < 16 * MIB and server.talk(post_request(body), wait=5)[0] == ["413"]
    assert not server.stored("structure")


# -- the read cap -------------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(tmp_path / "c.db"))
    import collector.app as module

    importlib.reload(module)
    monkeypatch.setattr("collector.storage.MAX_READ_BYTES", 3000)
    return TestClient(module.app)


def test_a_read_stops_at_the_cap_and_says_so(client: TestClient) -> None:
    assert client.get("/health").json()["read_capped_at"] is None
    events = [web_event(str(i), timestamp=f"2026-10-31T12:00:0{i}.000Z", raw_evidence_redacted={"a": "x" * 900}) for i in range(5)]
    assert client.post("/api/events", json=events).status_code == 200
    seen = [e["event_id"] for e in client.get("/api/events", params={"limit": 1000}).json()]
    assert seen == ["4", "3"]  # newest first, and nothing was deleted
    health = client.get("/health").json()
    assert health["events_stored"] == 5 and health["read_capped_at"]


def test_one_row_over_the_cap_is_still_returned(client: TestClient) -> None:
    client.post("/api/events", json=[web_event("huge", raw_evidence_redacted={"a": "x" * 5000})])
    assert [e["event_id"] for e in client.get("/api/events").json()] == ["huge"]
    assert client.get("/health").json()["read_capped_at"] is None


def test_every_list_read_goes_through_the_cap(client: TestClient) -> None:
    for i in range(4):
        client.post("/api/adaptations", json=[{
            "adaptation_id": str(i), "timestamp": f"2026-10-31T12:00:0{i}.000Z", "sensor_id": "db-01", "service": "database",
            "rule_id": "B", "stage": 1, "trigger_event_id": "e", "trigger_reason": "r" * 900, "adaptation_type": "t",
            "asset_revealed": "a", "source_ip": "x", "tracker_key": "k", "target_account": "d", "status": "applied"}])
        client.post("/api/sensors/heartbeat", json={"sensor_id": f"s{i}", "service": "web", "status": "ok",
                                                    "details": {"a": "x" * 900}})
        client.post("/api/events", json=[web_event(str(i), raw_evidence_redacted={"detections": [
            {"rule": f"W-{i}", "rationale": "x" * 900}]})])
    assert len(client.get("/api/adaptations").json()) < 4
    assert len(client.get("/api/sensors").json()) < 4
    assert len(client.get("/api/alerts").json()) < 4
