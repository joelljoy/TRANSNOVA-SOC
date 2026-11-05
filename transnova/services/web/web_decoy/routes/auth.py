"""Synthetic login. One decoy credential; everything else fails with a generic message."""

from __future__ import annotations

import hmac

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from .. import fixtures
from ..deps import current_session, templates
from ..errors import nginx_error
from ..sessions import COOKIE_NAME

router = APIRouter()

GENERIC_ERROR = "Invalid username or password."
MAX_FIELD = 256


def _form_str(form, name: str) -> str:
    value = form.get(name, "")
    return value[:MAX_FIELD] if isinstance(value, str) else ""


def _check(settings, username: str, password: str) -> bool:
    # Compare both fields in constant time and always evaluate both, so timing
    # does not reveal whether the username exists.
    user_ok = hmac.compare_digest(username.encode(), settings.decoy_user.encode())
    pass_ok = hmac.compare_digest(password.encode(), settings.decoy_password.encode())
    return user_ok and pass_ok


@router.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"realm": "partner", "error": None})


@router.get("/admin/login")
def admin_login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"realm": "admin", "error": None})


@router.get("/admin")
@router.get("/admin/")
def admin(request: Request):
    return RedirectResponse("/admin/login", status_code=302)


LOGIN_CONTENT_TYPE = "application/x-www-form-urlencoded"


@router.post("/login")
async def login_submit(request: Request):
    # Security fix F2: browsers submit this form URL-encoded. Accepting multipart too
    # let input bypass the telemetry middleware's field parsing and the detectors.
    ctype = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if ctype != LOGIN_CONTENT_TYPE:
        request.state.telemetry = {"auth": True, "outcome": "blocked", "action": "login_attempt"}
        return nginx_error(400)
    form = await request.form(max_files=0, max_fields=20)
    username = _form_str(form, "username")
    password = _form_str(form, "password")
    realm = "admin" if _form_str(form, "realm") == "admin" else "partner"
    settings = request.app.state.settings

    ok = _check(settings, username, password)
    # Telemetry gets the username and the result only. The password stays here.
    request.state.telemetry = {"auth": True, "username": username,
                               "outcome": "succeeded" if ok else "failed", "realm": realm}
    if not ok:
        return templates.TemplateResponse(
            request, "login.html", {"realm": realm, "error": GENERIC_ERROR}, status_code=401
        )

    user = fixtures.USER_BY_NAME.get(settings.decoy_user, fixtures.USERS[1001])
    token, sess = request.app.state.sessions.create(user["id"], user["username"])
    request.state.telemetry["session_id"] = sess.session_id
    resp = RedirectResponse("/portal", status_code=302)
    # Secure flag whenever served over HTTPS (the container); local dev runs plain HTTP on loopback.
    resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="lax", path="/", max_age=8 * 3600,
                    secure=settings.tls)
    return resp


@router.post("/logout")
def logout(request: Request):
    if current_session(request) is not None:
        request.app.state.sessions.delete(request.cookies.get(COOKIE_NAME))
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp
