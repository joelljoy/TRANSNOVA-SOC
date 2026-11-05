"""One canonical event per request (PLAN.md §4).

Pure ASGI middleware so it can (1) enforce body caps on the bytes actually
received, including chunked bodies, and (2) see the request body once and hand
an identical copy to the app.

Order per request:
  read body under cap -> run app -> run detectors on RAW values (in memory)
  -> redact + bound everything -> validate against the canonical schema -> emit.
Raw values never leave this function; only redacted copies are emitted.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import time
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable
from urllib.parse import parse_qsl

from starlette.requests import Request

from ..config import ip_in
from ..errors import HSTS_VALUE, SECURITY_HEADERS, nginx_error_body
from ..sessions import COOKIE_NAME
from . import redact
from .schema import CanonicalEvent

CAMPAIGN_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
PROBE_STATUSES = {401, 403, 404, 405}
MAX_DETECTIONS = 10
# Fixed-vocabulary keys come from our own rule catalogue: allow a strict charset and
# skip secret-pattern redaction (which would mangle labels like "auth:failed").
VOCAB_KEYS = ("rule", "category", "label", "owasp", "confidence")
TEXT_KEYS = ("field", "rationale")             # free text: always redacted + bounded
ATTACK_VOCAB = ("technique", "status", "confidence")
VOCAB_RE = re.compile(r"[^A-Za-z0-9:._ /-]")


@dataclass
class RequestContext:
    """Raw, in-memory view of a request for detectors. Never emitted as-is."""
    method: str
    path: str
    query: list[tuple[str, str]]
    form: list[tuple[str, str]]
    json_pairs: list[tuple[str, Any]]
    headers: dict[str, str]
    source_ip: str
    status: int
    authenticated: bool
    route: dict[str, Any] = field(default_factory=dict)
    session_user_id: int | None = None


Detector = Callable[[RequestContext], list[dict[str, Any]]]


def _source_ip(scope, headers: dict[str, str], trust_proxy: bool) -> tuple[str, int | None]:
    client = scope.get("client") or ("unknown", None)
    host, port = client[0], client[1]
    if trust_proxy and "x-forwarded-for" in headers:
        # Rightmost valid entry = the address our own proxy saw. Leftmost is attacker-chosen.
        for candidate in reversed(headers["x-forwarded-for"].split(",")):
            try:
                return str(ipaddress.ip_address(candidate.strip())), None
            except ValueError:
                continue
    return str(host), port


def _sanitize_detection(d: dict[str, Any]) -> dict[str, Any]:
    """Detectors can only emit known keys, and every string is redacted/bounded,
    so a detector bug cannot leak a raw value (e.g. a password) into the event."""
    out: dict[str, Any] = {k: _vocab(d[k]) for k in VOCAB_KEYS if k in d}
    out.update({k: redact.safe_value(d[k], 256) for k in TEXT_KEYS if k in d})
    attacks = d.get("attack") or []
    out["attack"] = []
    for a in attacks[:5]:
        if isinstance(a, dict):
            item = {k: _vocab(a[k]) for k in ATTACK_VOCAB if k in a}
            if "rationale" in a:
                item["rationale"] = redact.safe_value(a["rationale"], 256)
            out["attack"].append(item)
    return out


FP_HEADERS = ("user-agent", "accept", "accept-language", "accept-encoding")


def client_fingerprint(headers: dict[str, str]) -> str:
    """Short hash of stable browser headers. Links one client across changing IPs (Tor/VPN
    hopping) without storing the header values themselves. A hint, not proof: identical
    default browsers share a fingerprint, and a careful attacker can change headers."""
    material = "\x1f".join(headers.get(h, "")[:512] for h in FP_HEADERS)
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def _vocab(value: Any) -> str:
    return VOCAB_RE.sub("", str(value))[:80]


class TelemetryMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        fastapi_app = scope["app"]
        settings = fastapi_app.state.settings
        started = datetime.now(timezone.utc)
        raw_headers: list[tuple[bytes, bytes]] = scope.get("headers", [])
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in raw_headers}
        method = scope["method"]
        path = scope["path"]

        # ---- 0. per-source flood limit (F6): refuse before reading the body -------------
        src_ip, _ = _source_ip(scope, headers, settings.trust_proxy)
        allowed, to_log = fastapi_app.state.rate_limiter.check(src_ip)
        if not allowed:
            await self._send_error(send, 429, settings.tls)
            if to_log is not None:  # sampled: one event per source per window, with a count
                limiter = fastapi_app.state.rate_limiter
                self._record(fastapi_app, scope, settings, started, method, path, headers, raw_headers,
                             b"", None, {"_rate_limited": {"suppressed": to_log,
                                                           "limit_per_s": limiter.rate,
                                                           "burst": int(limiter.burst)}}, 429, 429)
            return

        # ---- 1. body cap on bytes actually received --------------------------------
        is_upload = path == "/upload" and method == "POST"
        cap = (settings.max_upload_bytes + settings.multipart_overhead_bytes) if is_upload \
            else settings.max_body_bytes
        reject: int | None = None
        declared = headers.get("content-length")
        if declared is not None and not declared.isdigit():
            reject = 400
        elif declared is not None and int(declared) > cap:
            reject = 413
        body = bytearray()
        timed_out = False
        if reject is None:
            more = True
            # Total deadline for the whole body (security fix F1): a client that sends
            # headers and then trickles or stalls cannot hold a worker slot forever.
            deadline = time.monotonic() + settings.body_timeout_s
            while more:
                try:
                    message = await asyncio.wait_for(receive(), max(0.0, deadline - time.monotonic()))
                except asyncio.TimeoutError:
                    reject, timed_out = 408, True
                    break
                if message["type"] == "http.disconnect":
                    break
                body.extend(message.get("body", b""))
                if len(body) > cap:
                    reject = 413
                    break
                more = message.get("more_body", False)

        # Session as it was BEFORE the app ran (logout deletes it).
        token = Request(scope).cookies.get(COOKIE_NAME)
        session = fastapi_app.state.sessions.get(token)

        state: dict[str, Any] = scope.setdefault("state", {})
        status_holder = {"status": 500}

        if reject is not None:
            await self._send_error(send, reject, settings.tls)
            status_holder["status"] = reject
        else:
            replayed = False

            async def replay_receive():
                nonlocal replayed
                if not replayed:
                    replayed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            async def capture_send(message):
                if message["type"] == "http.response.start":
                    status_holder["status"] = message["status"]
                await send(message)

            try:
                await self.app(scope, replay_receive, capture_send)
            except BaseException:
                self._record(fastapi_app, scope, settings, started, method, path, headers, raw_headers,
                             bytes(body), session, state.get("telemetry", {}), 500, None)
                raise

        route_state = state.get("telemetry", {})
        if timed_out:
            route_state = {**route_state, "_body_timeout": True}
        self._record(fastapi_app, scope, settings, started, method, path, headers, raw_headers,
                     bytes(body), session, route_state, status_holder["status"], reject)

    @staticmethod
    async def _send_error(send, status: int, tls: bool = False) -> None:
        body = nginx_error_body(status).encode()
        hdrs = [(b"content-type", b"text/html; charset=utf-8"), (b"content-length", str(len(body)).encode())]
        hdrs += [(k.lower().encode(), v.encode()) for k, v in SECURITY_HEADERS.items()]
        if tls:
            hdrs.append((b"strict-transport-security", HSTS_VALUE.encode()))
        await send({"type": "http.response.start", "status": status, "headers": hdrs})
        await send({"type": "http.response.body", "body": body})

    # ---- 2. build, redact, validate, emit ---------------------------------------------
    def _record(self, fastapi_app, scope, settings, started, method, path, headers, raw_headers,
                body: bytes, session, route: dict[str, Any], status: int, reject: int | None) -> None:
        try:
            event = self._build(fastapi_app, scope, settings, started, method, path, headers,
                                raw_headers, body, session, route, status, reject)
        except Exception:  # telemetry must never break the decoy
            fastapi_app.state.telemetry_errors += 1
            return
        if event is not None:
            fastapi_app.state.emitter.emit(event)

    def _build(self, fastapi_app, scope, settings, started, method, path, headers, raw_headers,
               body: bytes, session, route, status, reject):
        if route.get("skip"):
            return None
        if path.startswith("/static/") and status == 200 and method in ("GET", "HEAD"):
            return None  # page assets: noise, not attacker behaviour

        source_ip, source_port = _source_ip(scope, headers, settings.trust_proxy)

        # Raw parse (in memory only).
        qs = scope.get("query_string", b"").decode("utf-8", "replace")[:16384]
        query = parse_qsl(qs, keep_blank_values=True)[:200]
        form: list[tuple[str, str]] = []
        json_pairs: list[tuple[str, Any]] = []
        ctype = headers.get("content-type", "").split(";")[0].strip().lower()
        body_note: dict[str, Any] = {}
        if body:
            body_note = {"content_type": redact.safe_value(ctype, 100), "bytes": len(body)}
            if reject is None and ctype == "application/x-www-form-urlencoded":
                form = parse_qsl(body.decode("utf-8", "replace"), keep_blank_values=True)[:200]
            elif reject is None and ctype == "application/json":
                try:
                    json_pairs = redact.flatten_json(json.loads(body))
                except (ValueError, RecursionError):
                    body_note["json_error"] = True

        # Detectors see RAW values; their output is sanitized (PLAN §0.1 P5).
        ctx = RequestContext(method, path, query, form, json_pairs, headers, source_ip, status,
                             session is not None or bool(route.get("session_id")), route,
                             session.user_id if session else None)
        detections: list[dict[str, Any]] = []
        for detector in fastapi_app.state.detectors:
            try:
                detections.extend(_sanitize_detection(d) for d in detector(ctx) if isinstance(d, dict))
            except Exception:
                fastapi_app.state.telemetry_errors += 1

        adaptive = getattr(fastapi_app.state, "adaptive", None)
        if adaptive is not None:
            adaptive.observe(source_ip, {str(d.get("rule")) for d in detections})

        # Redact + bound.
        q_red, q_markup = redact.redact_pairs(query)
        f_red, f_markup = redact.redact_pairs(form)
        j_red, j_markup = redact.redact_pairs(json_pairs)
        evidence: dict[str, Any] = {"headers": redact.filter_headers(raw_headers)}
        if q_red:
            evidence["query"] = q_red
        if f_red:
            evidence["form"] = f_red
        if j_red:
            evidence["json"] = j_red
        if body_note:
            evidence["body"] = body_note
        if route.get("upload"):
            evidence["upload"] = route["upload"]
        if route.get("adaptive"):
            evidence["adaptive"] = {k: route["adaptive"][k] for k in ("stage", "bait") if k in route["adaptive"]}
        if route.get("_rate_limited"):
            evidence["rate_limit"] = route["_rate_limited"]
        intel = getattr(fastapi_app.state, "anon", None)
        verdict = intel.classify(source_ip) if intel is not None else None
        if verdict is not None:
            evidence["anonymizer"] = verdict.as_dict()
        evidence["client_fp"] = client_fingerprint(headers)
        evidence["detections"] = detections[:MAX_DETECTIONS]
        evidence = redact.bound_evidence(evidence)

        request_path = redact.safe_value(path, 2048)
        user_agent = redact.safe_optional(headers.get("user-agent"), 512)
        username = redact.safe_optional(route.get("username"), 64)

        tags: list[str] = []
        session_id = route.get("session_id") or (session.session_id if session else None)
        if session_id:
            tags.append("authenticated_session")
        if q_markup or f_markup or j_markup or any(
            redact.contains_markup(v) for v in (request_path, user_agent or "", username or "")
        ):
            tags.append("contains_markup")

        campaign_id = None
        raw_campaign = headers.get(settings.campaign_header)
        if raw_campaign is not None:
            if CAMPAIGN_RE.fullmatch(raw_campaign) and ip_in(source_ip, settings.simulator_cidrs):
                campaign_id = raw_campaign
            else:
                tags.append("untrusted_campaign_header")
        if route.get("adaptive", {}).get("stage") == "revealed":
            tags.append("adaptive:revealed")
        if route.get("_rate_limited"):
            tags.append("rate_limited")
        elif reject is not None:
            tags.append("body_timeout" if route.get("_body_timeout") else "body_rejected")
        for d in detections[:MAX_DETECTIONS]:
            if d.get("label") and d["label"] not in tags:
                tags.append(d["label"])

        upload = route.get("upload")
        if upload:
            event_type, default_action = "file_transfer", "upload_attempt"
        elif route.get("auth"):
            event_type, default_action = "authentication", "login_attempt"
        else:
            event_type = "http_request"
            default_action = "route_probe" if status in PROBE_STATUSES else "page_view"

        outcome = "blocked" if reject is not None else route.get("outcome", "observed")

        event = CanonicalEvent(
            event_id=str(uuid.uuid4()),
            timestamp=started,
            sensor_id=settings.sensor_id,
            service="web",
            source_ip=source_ip,
            source_port=source_port if isinstance(source_port, int) else None,
            destination_service="web-decoy",
            event_type=event_type,
            action=route.get("action", default_action),
            outcome=outcome,
            username=username,
            session_id=session_id,
            campaign_id=campaign_id,
            request_path=request_path,
            http_method=redact.safe_value(method, 16),
            http_status=status,
            file_name=upload.get("file_name") if upload else None,
            file_direction="upload" if upload else None,
            user_agent=user_agent,
            raw_evidence_redacted=evidence,
            tags=tags,
        )
        return event.model_dump(mode="json")  # ValidationError is caught in _record
