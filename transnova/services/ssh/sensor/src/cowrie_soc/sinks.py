"""Delivery targets for normalized records.

- JsonlSink: append-only local JSON Lines file (always available, used for demo
  evidence and as a fallback hand-off format).
- HttpSink: POSTs batches to a configured URL. This is the integration point
  for the team's SOC backend. No backend URL is assumed; it is disabled unless
  one is configured. The payload shape is produced by `cowrie_soc.encoders`.

Sinks raise SinkError(retryable=...) and never drop data themselves; the
Deliverer decides between retry (cursor not advanced) and dead-lettering.

SocDeliverer is the only route to the SOC. It reads validated events from soc_outbox and
never dead-letters: an event stays queued until the SOC accepts it. Temporary errors retry
with capped backoff. Errors that need a person stop delivery until the sensor is restarted.
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol

from cowrie_soc.canonical import validate
from cowrie_soc.encoders import Encoder
from cowrie_soc.store import Store

log = logging.getLogger(__name__)

TRANSIENT = "transient"
AUTH = "auth"
TOKEN = "token"
CONFIG = "config"
REJECTED = "rejected"


class SinkError(Exception):
    def __init__(self, message: str, retryable: bool, kind: str | None = None, status: int | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.kind = kind or (TRANSIENT if retryable else REJECTED)
        self.status = status


class Sink(Protocol):
    name: str
    batch_size: int

    def send(self, records: list[dict[str, Any]]) -> None: ...


class JsonlSink:
    def __init__(self, path: str | Path, max_bytes: int = 50 * 1024 * 1024, batch_size: int = 500) -> None:
        self.name = "jsonl"
        self.path = Path(path)
        self.max_bytes = max_bytes
        self.batch_size = batch_size
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def send(self, records: list[dict[str, Any]]) -> None:
        try:
            if self.path.exists() and self.path.stat().st_size >= self.max_bytes:
                self.path.replace(self.path.with_name(self.path.name + ".1"))
            data = "".join(json.dumps(r, separators=(",", ":"), ensure_ascii=False) + "\n" for r in records)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
        except OSError as exc:
            raise SinkError(f"cannot write {self.path}: {exc}", retryable=True) from exc


# HTTP statuses worth retrying; any other 4xx means the request itself is wrong.
_RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}
MAX_TOKEN_CHARS = 4096
MAX_RESPONSE_BYTES = 4096


def _redact_url(url: str) -> str:
    """Drop user:password@ and the query string (which may carry tokens) for log messages."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    if ":" in host:
        host = f"[{host}]"  # IPv6 literal
    if parts.port:
        host = f"{host}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, host, parts.path, "", ""))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects for ingest POSTs.

    urllib would turn a 301/302 POST into a body-less GET and raises on 307/308, so a
    redirecting URL (e.g. missing trailing slash, http->https) would dead-letter every
    batch. Returning None surfaces the 3xx as an HTTPError, handled in HttpSink.send.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class HttpSink:
    def __init__(
        self,
        url: str,
        encoder: Encoder,
        token_env: str | None = None,
        token_file: str = "",
        timeout: float = 5.0,
        batch_size: int = 100,
        verify_tls: bool = True,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError(f"HTTP sink URL must be http(s): {url!r}")
        self.name = "http"
        self.url = url
        self.display_url = _redact_url(url)  # never log credentials embedded in the URL
        self.encoder = encoder
        self.token_env = token_env
        self.token_file = token_file
        self.timeout = timeout
        self.batch_size = batch_size
        self.extra_headers = dict(extra_headers or {})
        ssl_context = None if verify_tls else ssl._create_unverified_context()  # noqa: S323 - opt-in lab use
        # ProxyHandler({}): never pick up a proxy from the environment.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl_context), _NoRedirect(),
        )

    def _token(self) -> str:
        """Read at send time. Neither the value nor a read error's text is ever stored or logged."""
        if not self.token_file:
            return os.environ.get(self.token_env, "") if self.token_env else ""
        try:
            with open(self.token_file, encoding="utf-8") as fh:
                token = fh.read(MAX_TOKEN_CHARS + 1).strip()
        except (OSError, UnicodeError):
            raise SinkError("cannot read the token file", retryable=True, kind=TOKEN) from None
        if not token or len(token) > MAX_TOKEN_CHARS or any(c in token for c in "\r\n"):
            raise SinkError("the token file is not usable", retryable=True, kind=TOKEN)
        return token

    def send(self, records: list[dict[str, Any]]) -> None:
        body = json.dumps(self.encoder.encode_batch(records), separators=(",", ":"), ensure_ascii=False).encode()
        headers = {"Content-Type": "application/json", "User-Agent": "cowrie-soc/0.1", **self.extra_headers}
        token = self._token()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self.url, data=body, headers=headers, method="POST")
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                resp.read(MAX_RESPONSE_BYTES)  # drained and discarded, never stored
        except urllib.error.HTTPError as exc:
            exc.close()  # status code only: response bodies and headers are not stored
            if 300 <= exc.code < 400:
                # Configuration problem, not a data problem: keep the records queued until the URL is fixed.
                raise SinkError(
                    f"HTTP {exc.code} redirect from {self.display_url}; redirects are not followed - "
                    "set the exact ingest URL", retryable=True, kind=CONFIG, status=exc.code,
                ) from None
            retryable = exc.code in _RETRYABLE_STATUS
            kind = AUTH if exc.code in (401, 403) else TRANSIENT if retryable else REJECTED
            raise SinkError(f"HTTP {exc.code} from {self.display_url}", retryable=retryable, kind=kind,
                            status=exc.code) from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as exc:
            raise SinkError(f"cannot reach {self.display_url}: {type(exc).__name__}", retryable=True) from None


class Deliverer:
    """Moves records from the store outbox to one sink, in order, with backoff."""

    def __init__(
        self,
        sink: Sink,
        store: Store,
        base_backoff: float = 1.0,
        max_backoff: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sink = sink
        self.store = store
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.clock = clock
        self.failures = 0
        self.next_attempt = 0.0
        store.register_sink(sink.name)

    def deliver(self, max_batches: int = 10) -> int:
        """Deliver up to max_batches batches; returns the number of records delivered."""
        if self.clock() < self.next_attempt:
            return 0
        delivered = 0
        for _ in range(max_batches):
            batch = self.store.fetch_pending(self.sink.name, self.sink.batch_size)
            if not batch:
                break
            try:
                self.sink.send([rec for _, rec in batch])
            except SinkError as exc:
                if exc.retryable:
                    self.failures += 1
                    delay = min(self.max_backoff, self.base_backoff * 2 ** (self.failures - 1))
                    self.next_attempt = self.clock() + delay
                    self.store.record_error(self.sink.name, str(exc))
                    log.warning("sink %s: %s (retry %d in %.0fs, %d pending)", self.sink.name, exc,
                                self.failures, delay, self.store.pending_count(self.sink.name))
                    break
                self.store.dead_letter(self.sink.name, batch, str(exc))
                log.error("sink %s REJECTED %d records permanently; moved to dead_letter: %s",
                          self.sink.name, len(batch), exc)
                continue
            self.store.mark_delivered(self.sink.name, batch[-1][0], len(batch))
            delivered += len(batch)
            if self.failures:
                log.info("sink %s recovered after %d failed attempts", self.sink.name, self.failures)
            self.failures = 0
            self.next_attempt = 0.0
        return delivered


class SocDeliverer:
    """Moves validated events from soc_outbox to the SOC, in order.

    State       Cause                                     Behaviour
    retrying    network error, 408, 425, 429, 5xx         backoff doubling up to 60 s, then one try a minute
    unauthorized  401, 403                                stops after AUTH_ATTEMPTS
    token_unavailable  token file missing or unusable     stops after AUTH_ATTEMPTS
    misconfigured  3xx                                    stops at once
    rejected    any other 4xx, or an event failing the    stops at once
                last check before sending

    Events stay queued in every state. A stopped state makes no more requests until the problem
    is fixed and the sensor is restarted. Only status codes are kept, never bodies or tokens.
    """

    AUTH_ATTEMPTS = 3
    AUTH_DELAYS = (5.0, 30.0)
    STOPPED = {"unauthorized", "token_unavailable", "misconfigured", "rejected"}
    _STOP_STATES = {AUTH: "unauthorized", TOKEN: "token_unavailable", CONFIG: "misconfigured", REJECTED: "rejected"}

    def __init__(
        self,
        sink: Sink,
        store: Store,
        sensor_id: str,
        base_backoff: float = 1.0,
        max_backoff: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.sink = sink
        self.store = store
        self.sensor_id = sensor_id
        self.base_backoff = base_backoff
        self.max_backoff = max_backoff
        self.clock = clock
        self.state = "idle"
        self.failures = 0
        self.next_attempt = 0.0
        store.soc_set_state("idle", 0, None)  # a restart is how a person clears a stopped state

    def _set(self, state: str, status: int | None) -> None:
        if state != self.state:
            log.log(logging.ERROR if state in self.STOPPED else logging.INFO, "SOC delivery state: %s (status %s, %d queued)",
                    state, status, self.store.soc_pending())
        self.state = state
        self.store.soc_set_state(state, self.failures, status)

    def _failed(self, exc: SinkError) -> None:
        self.failures += 1
        if exc.kind == TRANSIENT:
            self.next_attempt = self.clock() + min(self.max_backoff, self.base_backoff * 2 ** (self.failures - 1))
            self._set("retrying", exc.status)
        elif exc.kind in (AUTH, TOKEN) and self.failures < self.AUTH_ATTEMPTS:
            self.next_attempt = self.clock() + self.AUTH_DELAYS[self.failures - 1]
            self._set("retrying", exc.status)
        else:
            self._set(self._STOP_STATES[exc.kind], exc.status)

    def deliver(self, max_batches: int = 10) -> int:
        """Deliver up to max_batches batches; returns the number of events delivered."""
        if self.state in self.STOPPED or self.clock() < self.next_attempt:
            return 0
        delivered = 0
        for _ in range(max_batches):
            batch = self.store.soc_fetch(self.sink.batch_size)
            if not batch:
                break
            events = [event for _, event in batch]
            if any(validate(event, self.sensor_id) is not None for event in events):
                self.failures += 1
                self._set("rejected", None)
                break
            try:
                self.sink.send(events)
            except SinkError as exc:
                self._failed(exc)
                break
            self.store.soc_mark_delivered(batch[-1][0], len(batch))
            delivered += len(batch)
            self.failures = 0
            self.next_attempt = 0.0
            self._set("idle", 200)
        return delivered
