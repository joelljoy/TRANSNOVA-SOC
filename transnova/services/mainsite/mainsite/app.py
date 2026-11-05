"""TransNova Logistics public site.

This is the real service in the story, kept separate from the honeypot (the partner portal,
services/web). It handles no logins and stores nothing a visitor types. Its one security job
here is refusing Tor, VPN and hosting-range visitors (the honeypot, by contrast, lets them in
and labels them). The honeypot is reachable only through "leaks" a curious attacker finds.
"""

from __future__ import annotations

import json
import re
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import content
from .blockfeed import BlockFeed
from .config import Settings

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))  # autoescaping on; never use |safe

SECURITY_HEADERS = {
    "Server": "nginx",
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; "
                                "frame-ancestors 'none'; form-action 'self'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}
TRACK_RE = re.compile(r"[^A-Z0-9]")
MAX_LOG_BYTES = 10 * 1024 * 1024


def load_anon_intel(data_dir: str):
    shared = HERE.parents[1] / "anonintel"
    if (shared / "anonintel.py").is_file() and str(shared) not in sys.path:
        sys.path.append(str(shared))
    try:
        from anonintel import AnonIntel
        return AnonIntel(data_dir or None)
    except Exception:  # missing module or unreadable lists: serve everyone, never crash
        return None


class BlockLog:
    """Append-only JSONL of refused visits, bounded in size. Values are bounded, never raw bodies."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        try:
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > MAX_LOG_BYTES:
                    return
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record) + "\n")
        except OSError:
            pass


def create_app(settings: Settings | None = None, intel=None, feed: BlockFeed | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    if feed is None and settings.blocklist_url and settings.blocklist_token:
        feed = BlockFeed(settings.blocklist_url, settings.blocklist_token, settings.blocklist_poll_s)
        feed.start()
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.state.feed = feed
    app.state.settings = settings
    app.state.anon = intel if intel is not None else load_anon_intel(settings.anon_data_dir)
    app.state.block_log = BlockLog(settings.access_log_path)
    app.state.blocked = 0
    templates.env.globals.update(portal_url=settings.portal_url, year=2026)

    @app.middleware("http")
    async def gatekeeper(request: Request, call_next):
        # 1. Anonymizer block, before any route runs. The TCP peer address only: forwarded
        #    headers are attacker-controlled and are never consulted.
        ip = request.client.host if request.client else None
        verdict = app.state.anon.classify(ip) if app.state.anon is not None else None
        operator_check = request.url.path == "/healthz" and ip == "127.0.0.1"  # the operator's own status check
        soc_blocked = not operator_check and app.state.feed is not None and app.state.feed.blocked(ip)
        if soc_blocked:
            # Caught on the honeypot, refused on the real site. Same generic page: never say why.
            app.state.blocked += 1
            app.state.block_log.write({
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ip": ip, "category": "soc_block",
                "list": "soc_blocklist", "method": request.method[:10], "path": request.url.path[:200]})
            resp = templates.TemplateResponse(request, "blocked.html", {"category": "policy"}, status_code=403)
        elif verdict is not None and verdict.category in settings.block_categories:
            app.state.blocked += 1
            app.state.block_log.write({
                "ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "ip": ip,
                "category": verdict.category, "list": verdict.source, "method": request.method[:10],
                "path": request.url.path[:200]})
            resp = templates.TemplateResponse(request, "blocked.html",
                                              {"category": verdict.category}, status_code=403)
        # 2. Small bodies only: no uploads exist, and chunked bodies are refused outright.
        elif request.method == "POST" and (
                not (request.headers.get("content-length") or "").isdigit()
                or int(request.headers["content-length"]) > settings.max_body_bytes):
            resp = PlainTextResponse("Request too large or missing length", status_code=413)
        else:
            resp = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            resp.headers[k] = v
        return resp

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        code = exc.status_code if exc.status_code in (404, 405) else 400
        return templates.TemplateResponse(request, "error.html", {"code": code}, status_code=code)

    @app.exception_handler(RequestValidationError)
    async def bad_input(request: Request, exc: RequestValidationError):
        return templates.TemplateResponse(request, "error.html", {"code": 400}, status_code=400)

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        return templates.TemplateResponse(request, "error.html", {"code": 500}, status_code=500)

    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")

    def page(request: Request, template: str, **ctx):
        return templates.TemplateResponse(request, template, {"page": template, **ctx})

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return page(request, "index.html", services=content.SERVICES, sailings=content.SAILINGS, loops=content.LOOPS,
                    news=content.NEWS)

    @app.get("/services", response_class=HTMLResponse)
    def services(request: Request):
        return page(request, "services.html", services=content.SERVICES)

    @app.get("/tracking", response_class=HTMLResponse)
    def tracking(request: Request, number: str = ""):
        clean = TRACK_RE.sub("", number.upper())[:20]
        result = content.TRACKING.get(clean) if clean else None
        return page(request, "tracking.html", number=number[:40], clean=clean, result=result)

    @app.get("/about", response_class=HTMLResponse)
    def about(request: Request):
        return page(request, "about.html")

    @app.get("/careers", response_class=HTMLResponse)
    def careers(request: Request):
        return page(request, "careers.html", jobs=content.JOBS)

    @app.get("/contact", response_class=HTMLResponse)
    def contact(request: Request):
        return page(request, "contact.html", sent=False)

    @app.post("/contact", response_class=HTMLResponse)
    def contact_send(request: Request, name: str = Form("", max_length=100),
                     email: str = Form("", max_length=200), message: str = Form("", max_length=2000)):
        # Nothing is stored or sent anywhere: the public site keeps no visitor data.
        return page(request, "contact.html", sent=bool(name.strip() and message.strip()), name=name[:100])

    # ---- the trail to the partner portal (honeypot) -----------------------------------
    @app.get("/admin")
    @app.get("/admin/")
    @app.get("/wp-admin")
    def admin_moved():
        return RedirectResponse(settings.portal_url + "/admin/login", status_code=302)

    @app.get("/partners")
    @app.get("/login")
    def partners():
        return RedirectResponse(settings.portal_url + "/login", status_code=302)

    @app.get("/robots.txt")
    def robots():
        return PlainTextResponse("User-agent: *\nDisallow: /admin\nDisallow: /partners\n"
                                 "Sitemap: /sitemap.xml\n")

    @app.get("/sitemap.xml")
    def sitemap():
        urls = "".join(f"<url><loc>{p}</loc></url>" for p in
                       ("/", "/services", "/tracking", "/about", "/careers", "/contact"))
        return Response('<?xml version="1.0" encoding="UTF-8"?><urlset '
                        'xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">' + urls + "</urlset>",
                        media_type="application/xml")

    @app.get("/.well-known/security.txt")
    def security_txt():
        return PlainTextResponse("Contact: mailto:security@transnova-logistics.example\n"
                                 "Expires: 2027-06-30T00:00:00Z\nPreferred-Languages: en, nl, pl\n")

    @app.get("/js/site.js")
    def site_js():
        # Served as a route so the (deliberately) leftover partner-SSO comment carries the
        # configured portal address.
        body = ("/* TransNova site 2026.10 */\n"
                f"// legacy partner SSO endpoint (moved, see OPS-412): {settings.portal_url}/login\n"
                "document.addEventListener('DOMContentLoaded',function(){var y=document.getElementById('y');"
                "if(y){y.textContent=new Date().getFullYear();}});\n")
        return Response(body, media_type="application/javascript")

    @app.get("/healthz")
    def healthz(request: Request):
        local = request.client is not None and request.client.host == "127.0.0.1"
        if not local:
            return PlainTextResponse("ok")
        anon = app.state.anon.status() if app.state.anon is not None else None
        return {"status": "ok", "blocked": app.state.blocked, "block_categories": list(settings.block_categories),
                "soc_blocklist": app.state.feed.status() if app.state.feed is not None else {"enabled": False},
                "anon_lists": anon, "uptime_s": int(time.monotonic() - started)}

    started = time.monotonic()
    return app


app = create_app()
