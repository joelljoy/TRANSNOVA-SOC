"""Public and logged-in portal pages."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse, RedirectResponse

from .. import fixtures
from ..deps import adaptive_bait, current_session, parse_int_id, templates
from ..errors import nginx_error

router = APIRouter()


ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /backup/
Disallow: /api/
Disallow: /portal/
Disallow: /download
Sitemap: /sitemap.xml
"""


def _ago(minutes: int) -> str:
    if minutes < 60:
        return f"{minutes} min ago"
    if minutes < 48 * 60:
        return f"{minutes // 60} h ago"
    return f"{minutes // 1440} days ago"


def _drift(period_s: int, spread: int) -> int:
    """A small number that changes over time, so 'last sync N minutes ago' looks live."""
    return 1 + int(time.time() // period_s) % spread


@router.get("/")
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {
        "session": current_session(request), "announcements": fixtures.ANNOUNCEMENTS,
        "last_sync": _drift(60, 9), "bait": adaptive_bait(request)})


@router.get("/status")
def status(request: Request):
    return templates.TemplateResponse(request, "status.html", {
        "session": current_session(request), "components": fixtures.STATUS_COMPONENTS,
        "incidents": fixtures.INCIDENTS, "updated": _drift(45, 5), "bait": adaptive_bait(request)})


@router.get("/changelog")
def changelog(request: Request):
    return templates.TemplateResponse(request, "changelog.html", {
        "session": current_session(request), "changelog": fixtures.CHANGELOG})


@router.get("/help")
def help_page(request: Request):
    return templates.TemplateResponse(request, "help.html", {"session": current_session(request)})


@router.get("/robots.txt")
def robots():
    # Classic leak: robots.txt lists exactly the paths an operator wants hidden.
    return PlainTextResponse(ROBOTS)


@router.get("/search")
def search(request: Request, q: str = ""):
    # q is reflected ONLY through Jinja2 autoescaping. No real search runs.
    return templates.TemplateResponse(
        request, "search.html", {"q": q[:200], "session": current_session(request), "bait": adaptive_bait(request)}
    )


@router.get("/portal")
def portal(request: Request):
    sess = current_session(request)
    if sess is None:
        return RedirectResponse("/login", status_code=302)
    shipments = [s for s in fixtures.SHIPMENTS.values() if s["owner_id"] == sess.user_id]
    user = fixtures.USERS[sess.user_id]
    return templates.TemplateResponse(
        request, "portal.html", {"session": sess, "user": user, "shipments": shipments,
                                 "activity": [(_ago(m), text) for m, text in fixtures.ACTIVITY]}
    )


@router.get("/portal/shipments/{shipment_id}")
def shipment(request: Request, shipment_id: str):
    sess = current_session(request)
    if sess is None:
        return RedirectResponse("/login", status_code=302)
    sid = parse_int_id(shipment_id)
    record = fixtures.SHIPMENTS.get(sid) if sid is not None else None
    if record is None:
        return nginx_error(404)
    return templates.TemplateResponse(request, "shipment.html", {"session": sess, "s": record})
