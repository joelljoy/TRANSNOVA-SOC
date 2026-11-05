"""Fake JSON API. Synthetic records only."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import fixtures
from ..deps import current_session, parse_int_id

router = APIRouter()

NOT_FOUND = {"error": "not found"}


@router.get("/api")
@router.get("/api/")
def api_index():
    return fixtures.API_INDEX


@router.get("/api/v1/users")
def list_users(request: Request):
    if current_session(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"users": [{"id": u["id"], "username": u["username"]} for u in fixtures.USERS.values()]}


@router.get("/api/v1/users/{user_id}")
def get_user(request: Request, user_id: str):
    if current_session(request) is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    uid = parse_int_id(user_id)
    user = fixtures.USERS.get(uid) if uid is not None else None
    if user is None:
        return JSONResponse(NOT_FOUND, status_code=404)
    # Deliberately no ownership check: this is the synthetic IDOR bait (detected in Phase 4).
    return user


@router.get("/api/v1/orders")
def list_orders(request: Request):
    sess = current_session(request)
    if sess is None:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return {"orders": [o for o in fixtures.ORDERS.values() if o["owner_id"] == sess.user_id]}


@router.get("/api/v1/preview")
def preview(url: str = ""):
    # SSRF trap: the URL is NEVER fetched. This module imports no HTTP client.
    return {"status": "preview unavailable"}
