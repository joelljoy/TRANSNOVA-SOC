"""Request limits, applied before any request reaches the collector code.

BodyGuard wraps the whole FastAPI app, so it runs after the HTTP parser (h11) and before everything
else. h11 keeps both Content-Length and Transfer-Encoding in the parsed headers, so a request
carrying both is still seen here and refused. h11 may already have decoded the bytes it received
(about 64 KiB at most), but they are discarded: no body reaches the application until every check
below has passed. tests/integration/test_collector_body_limits.py proves this on a real server.

Every refusal closes the connection, so unread bytes can never be read as another request.

The body budget limits raw bytes in progress, and it stays held until the application finishes.
It is NOT a memory ceiling: parsed JSON can be many times larger than its text. The structure
check and the container memory limit are what keep memory bounded.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import os
import re
import time
from typing import Any, Awaitable, Callable

log = logging.getLogger("collector.guards")

Receive = Callable[[], Awaitable[dict[str, Any]]]
Send = Callable[[dict[str, Any]], Awaitable[None]]

MIB = 1 << 20
# POST routes and their body limits. A test keeps this equal to the application's real POST routes.
ROUTE_LIMITS = {"/api/events": 16 * MIB, "/api/adaptations": 16 * MIB, "/api/sensors/heartbeat": 2 * MIB,
                "/api/v2/analyst/alert-status": 64 << 10, "/api/v2/analyst/alert-note": 64 << 10,
                "/api/v2/analyst/event-classification": 64 << 10, "/api/v2/analyst/explanation": 64 << 10,
                "/api/v2/console/auth-event": 16 << 10, "/api/v2/analyst/block": 16 << 10,
                "/api/v2/analyst/unblock": 16 << 10, "/api/blocklist/feed": 1 << 10}
SENSOR_ROUTES = {("POST", "/api/events"), ("POST", "/api/sensors/heartbeat")}  # all SSH_SENSOR_PEER may use
AUTHORIZED_LIMIT = MIB  # applies to anything carrying Authorization, so a bad token cannot send more
BODY_DEADLINE_S = 15.0
BODY_BUDGET = 32 * MIB
LOG_INTERVAL_S = 60.0

# Largest real Database batch: about 655,000 commas and a few hundred containers. A body under
# STRUCTURE_MIN_BYTES cannot hold enough to matter, so it is never scanned.
STRUCTURE_MIN_BYTES = MIB
MAX_COMMAS = 1_500_000
MAX_CONTAINERS = 100_000
_TOKENS = re.compile(rb'"[^"\\]*+(?:\\.[^"\\]*+)*+"|[,\[{]', re.DOTALL)

_logged_at: dict[str, float] = {}
# Every refusal, counted since this process started, so the console can show ingestion failures.
# Reasons are fixed strings chosen in code, never request content.
_refusals: dict[tuple[str, str], dict[str, Any]] = {}
STARTED_AT = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# Which kind of request is being refused: "ingest" (sensors), "analyst" (console actions) or "read".
_kind: contextvars.ContextVar[str] = contextvars.ContextVar("refusal_kind", default="ingest")


def kind_for(path: str, method: str) -> str:
    if method != "POST":
        return "read"
    return "analyst" if path.startswith(("/api/v2/analyst/", "/api/v2/console/")) else "ingest"


def refusal_report() -> dict[str, Any]:
    rows = [{"reason": reason, "kind": kind, **v} for (kind, reason), v in
            sorted(_refusals.items(), key=lambda kv: -kv[1]["count"])]
    ingest = [r for r in rows if r["kind"] == "ingest"]
    return {"since": STARTED_AT, "total": sum(r["count"] for r in ingest), "reasons": ingest,
            "other": [r for r in rows if r["kind"] != "ingest"]}


def note_refusal(reason: str, kind: str | None = None) -> None:
    """One fixed line per reason per minute. Never a header, path or body."""
    entry = _refusals.setdefault((kind or _kind.get(), reason), {"count": 0, "last_at": None})
    entry["count"] += 1
    entry["last_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    now = time.monotonic()
    if now - _logged_at.get(reason, -LOG_INTERVAL_S) >= LOG_INTERVAL_S:
        _logged_at[reason] = now
        log.warning("request refused: %s", reason)


def too_complex(body: bytes) -> bool:
    """True when the JSON structure, counted outside strings, is too large to parse safely.

    Empty lists and objects cost about 25 times their text, so a size limit alone cannot protect
    memory. Text inside a string is never counted: attacker SQL full of brackets lands in strings,
    and rejecting it would stall the Database sender, which retries a refused batch forever.

    The scan keeps nothing and stops at the first limit passed: building a copy without the
    strings costs far more memory than the body itself.
    """
    if len(body) <= STRUCTURE_MIN_BYTES:
        return False
    if body.count(b",") <= MAX_COMMAS and body.count(b"[") + body.count(b"{") <= MAX_CONTAINERS:
        return False
    commas = containers = 0
    for match in _TOKENS.finditer(body):
        token = body[match.start()]
        if token == 44:  # ,
            commas += 1
            if commas > MAX_COMMAS:
                return True
        elif token != 34:  # a string match starts with "
            containers += 1
            if containers > MAX_CONTAINERS:
                return True
    return False


def _framing_problem(method: str, headers: list[tuple[bytes, bytes]]) -> str | None:
    lengths = [value for name, value in headers if name == b"content-length"]
    encodings = [value for name, value in headers if name == b"transfer-encoding"]
    if lengths and encodings:
        return "conflicting body framing"
    if len(lengths) > 1 or len(encodings) > 1:
        return "repeated body framing"
    if encodings and encodings[0].strip().lower() != b"chunked":
        return "unsupported transfer encoding"
    if lengths and not lengths[0].isdigit():
        return "invalid content length"
    if method != "POST" and (encodings or (lengths and int(lengths[0]) != 0)):
        return "body on a request that takes none"
    return None


class BodyGuard:
    def __init__(self, app: Callable[..., Awaitable[None]], *, deadline_s: float = BODY_DEADLINE_S,
                 budget: int = BODY_BUDGET) -> None:
        self.app, self.deadline_s, self.budget = app, deadline_s, budget
        self.in_use = 0

    @staticmethod
    async def _refuse(send: Send, status: int, reason: str) -> None:
        note_refusal(reason)
        body = json.dumps({"detail": "request refused"}).encode()
        await send({"type": "http.response.start", "status": status, "headers": [
            (b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()),
            (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope: dict[str, Any], receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        method, headers = scope["method"], scope["headers"]
        _kind.set(kind_for(scope["path"], method))
        problem = _framing_problem(method, headers)
        if problem:
            await self._refuse(send, 400, problem)
            return
        locked_to = os.environ.get("SSH_SENSOR_PEER")
        client = scope.get("client")
        if locked_to and client and client[0] == locked_to and (method, scope["path"]) not in SENSOR_ROUTES:
            await self._refuse(send, 403, "sensor address outside its routes")
            return
        if method != "POST":
            await self.app(scope, receive, send)
            return
        route_limit = ROUTE_LIMITS.get(scope["path"])
        if route_limit is None:
            await self._refuse(send, 404, "unknown route")
            return
        limit = min(route_limit, AUTHORIZED_LIMIT) if any(k == b"authorization" for k, _ in headers) else route_limit
        declared = next((int(value) for name, value in headers if name == b"content-length"), None)
        if declared is not None and declared > limit:
            await self._refuse(send, 413, "body over the limit")
            return
        held = 0
        if declared is not None:  # reserve it all first, so partly read bodies cannot starve each other
            if self.in_use + declared > self.budget:
                await self._refuse(send, 503, "body budget full")
                return
            self.in_use += declared
            held = declared
        try:
            body = bytearray()
            end = time.monotonic() + self.deadline_s  # absolute: set once, never reset by new bytes
            more = True
            while more:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    await self._refuse(send, 408, "body deadline passed")
                    return
                try:
                    message = await asyncio.wait_for(receive(), remaining)
                except TimeoutError:
                    await self._refuse(send, 408, "body deadline passed")
                    return
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                if len(body) + len(chunk) > limit:
                    await self._refuse(send, 413, "body over the limit")
                    return
                if declared is None:
                    if self.in_use + len(chunk) > self.budget:
                        await self._refuse(send, 503, "body budget full")
                        return
                    self.in_use += len(chunk)
                    held += len(chunk)
                body.extend(chunk)
                more = message.get("more_body", False)
            payload = [bytes(body)]
            body.clear()
            if await asyncio.to_thread(too_complex, payload[0]):
                await self._refuse(send, 413, "body structure over the limit")
                return

            async def replay() -> dict[str, Any]:
                if payload:
                    return {"type": "http.request", "body": payload.pop(), "more_body": False}
                return await receive()

            await self.app(scope, replay, send)
        finally:
            self.in_use -= held  # held through parsing, validation and storage, then always released
