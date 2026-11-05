"""LOCAL DEVELOPMENT RECEIVER - NOT THE PS04 SOC BACKEND.

A tiny HTTP endpoint that accepts what the HTTP sink sends, validates each
record against this component's contract, de-duplicates by record id and
appends to a JSONL file. It exists so the Cowrie component's delivery path
(batching, retry, dead-lettering) can be exercised before the team's real
backend exists. Its routes (/ingest, /records, /health) are this tool's own
and are NOT a proposal for the team API.

Binds to 127.0.0.1 by default.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from cowrie_soc.schema import RECORD_FINDING, record_id, validate_record

log = logging.getLogger(__name__)

MAX_BODY = 10 * 1024 * 1024
BANNER = "LOCAL DEV RECEIVER - not the SOC backend"


class ReceiverState:
    def __init__(self, out_path: str | Path, token: str | None = None) -> None:
        self.out_path = Path(out_path)
        self.out_path.parent.mkdir(parents=True, exist_ok=True)
        self.token = token
        self.lock = threading.Lock()
        self.seen: set[str] = set()
        self.records: list[dict[str, Any]] = []
        self.rejected = 0
        self.duplicates = 0
        if self.out_path.exists():
            for line in self.out_path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self.seen.add(record_id(rec))
                    self.records.append(rec)

    def ingest(self, records: list[Any]) -> dict[str, Any]:
        accepted, errors = 0, []
        with self.lock, self.out_path.open("a", encoding="utf-8") as fh:
            for i, rec in enumerate(records):
                problems = validate_record(rec)
                if problems:
                    self.rejected += 1
                    errors.append({"index": i, "errors": problems})
                    continue
                rid = record_id(rec)
                if rid in self.seen:
                    self.duplicates += 1
                    continue
                self.seen.add(rid)
                self.records.append(rec)
                fh.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")
                accepted += 1
                _print_record(rec)
        return {"accepted": accepted, "duplicates_total": self.duplicates, "rejected": errors}


def _print_record(rec: dict[str, Any]) -> None:
    if rec["record_type"] == RECORD_FINDING:
        techs = ",".join(t["technique_id"] for t in rec["attack"])
        print(f"[finding] {rec['severity'].upper():8} {rec['rule_id']:14} {rec['title']}  [{techs}]", flush=True)
    else:
        detail = rec.get("command") or rec.get("username") or ""
        print(f"[event]   {rec['timestamp']} {rec.get('source_ip')} {rec['session_id']} "
              f"{rec['event_type']} {detail}", flush=True)


def make_handler(state: ReceiverState) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "cowrie-soc-dev-receiver"

        def log_message(self, fmt: str, *args: Any) -> None:
            log.debug("%s " + fmt, self.address_string(), *args)

        def _send(self, code: int, payload: Any) -> None:
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Notice", BANNER)
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            """Reads and writes need the token when one is configured (/health stays open)."""
            if state.token and not hmac.compare_digest(
                self.headers.get("Authorization", ""), f"Bearer {state.token}"
            ):
                self._send(401, {"error": "unauthorized"})
                return False
            return True

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            if url.path == "/health":
                self._send(200, {"status": "ok", "notice": BANNER, "records": len(state.records)})
            elif url.path == "/records":
                if not self._authorized():
                    return
                qs = parse_qs(url.query)
                rtype = qs.get("type", [None])[0]
                try:
                    limit = max(1, min(int(qs.get("limit", ["100"])[0]), 1000))
                except ValueError:
                    self._send(400, {"error": "limit must be an integer"})
                    return
                recs = [r for r in state.records if rtype is None or r["record_type"] == rtype]
                self._send(200, {"notice": BANNER, "records": recs[-limit:]})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            if urlparse(self.path).path != "/ingest":
                self._send(404, {"error": "not found"})
                return
            if not self._authorized():
                return
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length <= 0 or length > MAX_BODY:
                self._send(413 if length > MAX_BODY else 400, {"error": "bad Content-Length"})
                return
            try:
                payload = json.loads(self.rfile.read(length))
            except json.JSONDecodeError as exc:
                self._send(400, {"error": f"invalid JSON: {exc}"})
                return
            records = payload.get("records") if isinstance(payload, dict) else payload
            if not isinstance(records, list):
                self._send(400, {"error": "expected an array or an object with 'records'"})
                return
            try:
                result = state.ingest(records)
            except OSError as exc:
                log.error("cannot store records: %s", exc)
                self._send(500, {"error": "receiver storage failure"})
                return
            self._send(200, result)

    return Handler


class ReceiverConfigError(ValueError):
    pass


def serve(host: str, port: int, out: str, token_env: str | None = None) -> ThreadingHTTPServer:
    """Start the receiver. If token_env is given, that variable must hold a non-empty token."""
    token = os.environ.get(token_env, "") if token_env else ""
    if token_env and not token:
        # Fail closed: the review showed the decoy container can reach this receiver by IP,
        # so an "auth enabled but empty token" setup must not silently accept anything.
        raise ReceiverConfigError(f"--token-env {token_env} is set but ${token_env} is empty")
    state = ReceiverState(out, token or None)
    server = ThreadingHTTPServer((host, port), make_handler(state))
    server.state = state  # type: ignore[attr-defined]
    return server
