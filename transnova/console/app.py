"""TransNova SOC console backend: sign-in, the analyst's only door to the collector, and the React app.

The browser never holds a collector token or an AI key. It gets an HttpOnly session cookie and a
CSRF token; this process adds the read token to reads and the console token to analyst actions,
with the signed-in user as the actor. Every sign-in, failure, sign-out and expiry is sent to the
collector as a `soc` authentication event, so it lands in All Events like any decoy interaction.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field

from . import config, users, xai

log = logging.getLogger("console")
COOKIE = "soc_session"
LOGIN_WINDOW_S = 600
LOGIN_LIMIT = 10  # failures per source per window before sign-in is refused outright
AUDIT_BACKLOG = 1000
STREAM_POLL_S = 2.0
READ_ROUTES = [re.compile(p) for p in (
    r"summary", r"cursor", r"events", r"events/facets", r"events/[A-Za-z0-9._:-]{1,64}", r"alerts",
    r"alerts/[A-Za-z0-9-]{1,64}", r"sources", r"sources/[A-Za-z0-9.:_-]{1,64}", r"sensors", r"ingestion", r"rules",
    r"mitre", r"owasp", r"blocklist", r"navigator")]
LEGACY_READS = {"database/summary": "/api/database/summary", "adaptations": "/api/adaptations"}
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                               "connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
    "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer", "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
}


@dataclass
class Session:
    username: str
    role: str
    csrf: str
    created: float
    seen: float
    ref: str = field(default_factory=lambda: secrets.token_hex(8))


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class StatusBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(pattern="^(investigate|confirm|false_positive|resolve|reopen)$")
    note: str | None = Field(None, max_length=4000)


class NoteBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    note: str = Field(min_length=1, max_length=4000)


class BlockBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str = Field(min_length=2, max_length=64, pattern=r"^[0-9A-Fa-f:.]+$")
    reason: str = Field(min_length=1, max_length=500)
    alert_id: str | None = Field(None, max_length=64, pattern=r"^[A-Za-z0-9-]+$")


class ClassBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    classification: str = Field(pattern="^(benign|suspicious|confirmed_malicious|false_positive|unclassified)$")
    reason: str = Field(min_length=1, max_length=2000)


def _token(path: str) -> str | None:
    try:
        value = Path(path).read_text(encoding="ascii").strip()
    except (OSError, ValueError):
        return None
    return value or None


def create_app(settings: config.Settings | None = None, *, transport: httpx.AsyncBaseTransport | None = None) -> FastAPI:
    settings = settings or config.load()
    http = httpx.AsyncClient(base_url=settings.collector_url, timeout=8.0, trust_env=False, transport=transport)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        await http.aclose()

    app = FastAPI(title="TransNova SOC console", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    sessions: dict[str, Session] = {}
    failures: dict[str, deque[float]] = {}
    audit_queue: deque[dict[str, Any]] = deque(maxlen=AUDIT_BACKLOG)
    state = {"audit_dropped": 0}

    # ---- collector access --------------------------------------------------------------------

    async def collector(method: str, path: str, *, write: bool = False, **kw: Any) -> httpx.Response:
        token = _token(settings.console_token_file if write else settings.read_token_file)
        if token is None:
            raise HTTPException(status_code=503, detail="console backend is missing a collector token")
        try:
            return await http.request(method, path, headers={"Authorization": f"Bearer {token}"}, **kw)
        except httpx.HTTPError:
            raise HTTPException(status_code=502, detail="collector unavailable") from None

    def relay(resp: httpx.Response) -> Response:
        if resp.status_code >= 500 or resp.status_code in (401, 403):
            # A collector auth failure is a console misconfiguration, not the analyst's fault.
            detail = "collector unavailable" if resp.status_code >= 500 else "console is not authorised at the collector"
            return JSONResponse({"detail": detail}, status_code=502)
        return Response(resp.content, status_code=resp.status_code, media_type="application/json")

    async def audit(request: Request, action: str, outcome: str, *, username: str | None = None,
                    reason: str | None = None, ref: str | None = None) -> None:
        client = request.client
        event = {"action": action, "outcome": outcome, "source_ip": client.host if client else "0.0.0.0",
                 "source_port": client.port if client else None, "username": (username or None) and username[:64],
                 "user_agent": (request.headers.get("user-agent") or "")[:256] or None, "reason": reason,
                 "session_ref": ref}
        audit_queue.append(event)
        await flush_audit()

    async def flush_audit() -> None:
        while audit_queue:
            try:
                resp = await collector("POST", "/api/v2/console/auth-event", write=True, json=audit_queue[0])
            except HTTPException:
                return
            if resp.status_code == 200:
                audit_queue.popleft()
            elif 400 <= resp.status_code < 500 and resp.status_code not in (401, 429):
                audit_queue.popleft()  # will never be accepted; counted, not retried forever
                state["audit_dropped"] += 1
            else:
                return

    # ---- sessions ----------------------------------------------------------------------------

    async def current(request: Request) -> Session:
        sid = request.cookies.get(COOKIE)
        sess = sessions.get(sid or "")
        if sess is None:
            raise HTTPException(status_code=401, detail="sign in required")
        now = time.time()
        if now - sess.seen > settings.idle_minutes * 60 or now - sess.created > settings.max_hours * 3600:
            sessions.pop(sid, None)
            await audit(request, "session_expired", "observed", username=sess.username, reason="timeout", ref=sess.ref)
            raise HTTPException(status_code=401, detail="session expired")
        sess.seen = now
        return sess

    async def writer(request: Request, sess: Session = Depends(current)) -> Session:
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), sess.csrf):
            raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
        if sess.role == "viewer":
            raise HTTPException(status_code=403, detail="your role can view but not change alerts")
        return sess

    def same_origin(request: Request) -> None:
        origin = request.headers.get("origin")
        if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
            raise HTTPException(status_code=403, detail="cross-origin request refused")

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Response:
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---- auth --------------------------------------------------------------------------------

    @app.post("/api/auth/login", dependencies=[Depends(same_origin)])
    async def login(body: LoginBody, request: Request, response: Response) -> dict[str, Any]:
        source = request.client.host if request.client else "0.0.0.0"
        window = failures.setdefault(source, deque())
        now = time.time()
        while window and now - window[0] > LOGIN_WINDOW_S:
            window.popleft()
        if len(window) >= LOGIN_LIMIT:
            await audit(request, "login_rate_limited", "blocked", username=body.username, reason="too_many_failures")
            raise HTTPException(status_code=429, detail="too many failed sign-ins; wait a few minutes")
        user = await asyncio.to_thread(users.authenticate, users.load(settings.users_file), body.username, body.password)
        if user is None:
            window.append(now)
            await audit(request, "login", "failed", username=body.username, reason="invalid_credentials")
            raise HTTPException(status_code=401, detail="username or password is incorrect")
        sid = secrets.token_urlsafe(32)
        sess = Session(user.username, user.role, secrets.token_urlsafe(24), now, now)
        sessions[sid] = sess
        response.set_cookie(COOKIE, sid, httponly=True, samesite="strict", secure=settings.cookie_secure, path="/",
                            max_age=settings.max_hours * 3600)
        await audit(request, "login", "succeeded", username=user.username, ref=sess.ref)
        return {"username": user.username, "role": user.role, "csrf": sess.csrf}

    @app.post("/api/auth/logout")
    async def logout(request: Request, response: Response, sess: Session = Depends(current)) -> dict[str, str]:
        if not secrets.compare_digest(request.headers.get("x-csrf-token", ""), sess.csrf):
            raise HTTPException(status_code=403, detail="missing or invalid CSRF token")
        sessions.pop(request.cookies.get(COOKIE, ""), None)
        response.delete_cookie(COOKIE, path="/")
        await audit(request, "logout", "succeeded", username=sess.username, ref=sess.ref)
        return {"status": "signed out"}

    @app.get("/api/auth/me")
    async def me(request: Request) -> dict[str, Any]:
        """Not signed in is an ordinary answer here, not an error: the page asks this on every load."""
        try:
            sess = await current(request)
        except HTTPException:
            return {"authenticated": False}
        return {"authenticated": True, "username": sess.username, "role": sess.role, "csrf": sess.csrf,
                "idle_timeout_min": settings.idle_minutes, "session_started": sess.created}

    # ---- reads -------------------------------------------------------------------------------

    @app.get("/api/data/{path:path}", dependencies=[Depends(current)])
    async def read(path: str, request: Request) -> Response:
        if path in LEGACY_READS:
            target = LEGACY_READS[path]
        elif any(p.fullmatch(path) for p in READ_ROUTES):
            target = f"/api/v2/{path}"
        else:
            raise HTTPException(status_code=404, detail="unknown data route")
        return relay(await collector("GET", target, params=list(request.query_params.multi_items())))

    @app.get("/api/system", dependencies=[Depends(current)])
    async def system() -> dict[str, Any]:
        """Configuration status for Settings: names and states only, never a value."""
        try:
            health = (await http.get("/health", timeout=3.0)).json()
            collector_state = "reachable" if health.get("status") == "ok" else "unexpected answer"
        except (httpx.HTTPError, ValueError):
            collector_state = "unreachable"
        read_ok = None
        if collector_state == "reachable":
            try:
                read_ok = (await collector("GET", "/api/v2/cursor")).status_code == 200
            except HTTPException:
                read_ok = False
        await flush_audit()
        return {"collector": collector_state, "collector_url": settings.collector_url, "read_token_accepted": read_ok,
                "read_token_present": _token(settings.read_token_file) is not None,
                "console_token_present": _token(settings.console_token_file) is not None,
                "accounts": len(users.load(settings.users_file)),
                "ai": {"configured": bool(settings.anthropic_key), "model": settings.ai_model, "provider": "Anthropic"},
                "audit_backlog": len(audit_queue), "audit_dropped": state["audit_dropped"],
                "session": {"idle_timeout_min": settings.idle_minutes, "max_hours": settings.max_hours,
                            "cookie_secure": settings.cookie_secure}}

    @app.get("/api/stream")
    async def stream(request: Request, sess: Session = Depends(current)) -> StreamingResponse:
        """Server-sent change notices. The cursor only moves when the collector stored something new."""

        async def events() -> AsyncIterator[bytes]:
            last: dict[str, Any] | None = None
            beat = 0.0
            while not await request.is_disconnected():
                try:
                    resp = await collector("GET", "/api/v2/cursor")
                    cur = resp.json() if resp.status_code == 200 else None
                except (HTTPException, ValueError):
                    cur = None
                if cur is None:
                    yield b"event: status\ndata: {\"collector\": \"unavailable\"}\n\n"
                else:
                    marker = {k: cur[k] for k in ("events", "alerts_last_seen", "alert_history")}
                    if marker != last:
                        kind = "hello" if last is None else "change"
                        yield f"event: {kind}\ndata: {json.dumps(marker)}\n\n".encode()
                        last = marker
                if time.monotonic() - beat > 15:
                    beat = time.monotonic()
                    yield b": keep-alive\n\n"
                if sessions.get(request.cookies.get(COOKIE, "")) is not sess:
                    return
                await asyncio.sleep(STREAM_POLL_S)

        return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    # ---- analyst actions ---------------------------------------------------------------------

    @app.post("/api/alerts/{alert_id}/status")
    async def alert_status(alert_id: str, body: StatusBody, sess: Session = Depends(writer)) -> Response:
        return relay(await collector("POST", "/api/v2/analyst/alert-status", write=True,
                                     json={"alert_id": alert_id, "action": body.action, "actor": sess.username,
                                           "note": body.note}))

    @app.post("/api/alerts/{alert_id}/notes")
    async def alert_note(alert_id: str, body: NoteBody, sess: Session = Depends(writer)) -> Response:
        return relay(await collector("POST", "/api/v2/analyst/alert-note", write=True,
                                     json={"alert_id": alert_id, "actor": sess.username, "note": body.note}))

    @app.post("/api/blocks")
    async def block(body: BlockBody, sess: Session = Depends(writer)) -> Response:
        return relay(await collector("POST", "/api/v2/analyst/block", write=True,
                                     json={"ip": body.ip, "reason": body.reason, "alert_id": body.alert_id,
                                           "actor": sess.username}))

    @app.post("/api/blocks/remove")
    async def unblock(body: BlockBody, sess: Session = Depends(writer)) -> Response:
        return relay(await collector("POST", "/api/v2/analyst/unblock", write=True,
                                     json={"ip": body.ip, "reason": body.reason, "actor": sess.username}))

    @app.post("/api/events/{event_id}/classification")
    async def event_class(event_id: str, body: ClassBody, sess: Session = Depends(writer)) -> Response:
        return relay(await collector("POST", "/api/v2/analyst/event-classification", write=True,
                                     json={"event_id": event_id, "actor": sess.username,
                                           "classification": body.classification, "reason": body.reason}))

    @app.post("/api/alerts/{alert_id}/explain")
    async def alert_explain(alert_id: str, sess: Session = Depends(writer)) -> Response:
        resp = await collector("GET", f"/api/v2/alerts/{alert_id}")
        if resp.status_code != 200:
            return relay(resp)
        packet = xai.evidence_packet(resp.json())
        try:
            explanation = await xai.explain(settings.anthropic_key, settings.ai_model, packet)
        except xai.Unavailable as exc:
            return JSONResponse({"detail": str(exc), "available": False}, status_code=503)
        model = explanation.pop("model", settings.ai_model)
        return relay(await collector("POST", "/api/v2/analyst/explanation", write=True,
                                     json={"alert_id": alert_id, "actor": sess.username, "model": model,
                                           "evidence_digest": xai.digest(packet), "explanation": explanation}))

    # ---- health and the React app ------------------------------------------------------------

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    dist = settings.frontend_dir

    @app.get("/{path:path}", include_in_schema=False)
    async def spa(path: str) -> Response:
        if path.startswith("api/"):
            raise HTTPException(status_code=404, detail="unknown route")
        file = (dist / path).resolve()
        if path and file.is_file() and dist.resolve() in file.parents:
            cache = "public, max-age=31536000, immutable" if path.startswith("assets/") else "no-cache"
            return FileResponse(file, headers={"Cache-Control": cache})
        index = dist / "index.html"
        if not index.is_file():
            return JSONResponse({"detail": "frontend not built: run npm run build in frontend/"}, status_code=503)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})

    app.state.sessions = sessions
    app.state.audit_queue = audit_queue
    return app
