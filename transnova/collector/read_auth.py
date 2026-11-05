"""Who may read the collector.

Events hold SQL, shell commands and attacker profiles, and adaptations reveal which tables are
decoys. The Web decoy is attacker-facing and shares a network with the collector, so anyone who
compromised it could otherwise read what was detected and undermine the deception.

This wraps the application, so it denies by default: everything except POST needs the read token,
including routes added later. POST routes have their own rules. /health stays open because the
Docker healthcheck has no token, but without one it says only that the collector is up.

With SOC_READ_TOKEN_FILE unset, reads stay open as they always were, and ssh_ingest refuses all SSH
data, so SSH events cannot arrive while reads are open. A broken token file refuses reads with 503,
and POST traffic carries on.
"""

from __future__ import annotations

import json
import os
from typing import Any, Awaitable, Callable

from .auth import bearer, load_token, same
from .guards import note_refusal

HEALTH = "/health"


def token_path() -> str | None:
    return os.environ.get("SOC_READ_TOKEN_FILE")


def token() -> bytes | None:
    return load_token(token_path())


async def _refuse(send: Callable[[dict[str, Any]], Awaitable[None]], status: int, detail: str, reason: str) -> None:
    note_refusal(reason, "read")
    body = json.dumps({"detail": detail}).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]
    if status == 401:
        headers.append((b"www-authenticate", b"Bearer"))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


class ReadGate:
    def __init__(self, app: Callable[..., Awaitable[None]]) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope["method"] == "POST":
            await self.app(scope, receive, send)
            return
        if not token_path():
            scope["read_access"] = True
            await self.app(scope, receive, send)
            return
        expected = token()
        allowed = same(bearer(scope["headers"]), expected)
        scope["read_access"] = allowed
        if scope["path"] == HEALTH or allowed:
            await self.app(scope, receive, send)
        elif expected is None:
            await _refuse(send, 503, "reads unavailable", "read token unavailable")
        else:
            await _refuse(send, 401, "not authorized", "read without a valid token")
