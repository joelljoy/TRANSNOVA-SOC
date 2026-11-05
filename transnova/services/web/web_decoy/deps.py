"""Shared request helpers."""

from __future__ import annotations

from pathlib import Path

from fastapi import Request
from fastapi.templating import Jinja2Templates

from .sessions import COOKIE_NAME, Session

TEMPLATES_DIR = Path(__file__).parent / "templates"

# Jinja2Templates enables autoescaping for .html templates. Templates must never use |safe.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def current_session(request: Request) -> Session | None:
    return request.app.state.sessions.get(request.cookies.get(COOKIE_NAME))


def parse_int_id(raw: str) -> int | None:
    """Parse a numeric path id without letting FastAPI emit a JSON 422 (fingerprint)."""
    if not raw.isdigit() or len(raw) > 9:
        return None
    return int(raw)


def source_ip(request: Request) -> str | None:
    """The same source address the telemetry middleware records (never a forwarded header unless
    TRUST_PROXY is on, exactly as in telemetry)."""
    from .telemetry.middleware import _source_ip
    headers = {k.lower(): v for k, v in request.headers.items()}
    return _source_ip(request.scope, headers, request.app.state.settings.trust_proxy)[0]


def adaptive_bait(request: Request) -> str | None:
    """USP 6: the bait link for this page, only for sources that already showed attack intent.
    Records the reveal on the event so the SOC sees when the breadcrumb was laid."""
    adaptive = getattr(request.app.state, "adaptive", None)
    ip = source_ip(request)
    if adaptive is None or not adaptive.engaged(ip):
        return None
    from .adaptive import BAIT_PATH
    adaptive.reveal(ip)
    state = getattr(request.state, "telemetry", None) or {}
    state["adaptive"] = {"stage": "revealed", "bait": BAIT_PATH}
    request.state.telemetry = state
    return BAIT_PATH
