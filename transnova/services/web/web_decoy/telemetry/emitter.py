"""Event delivery (PLAN.md §4.2).

- Every event is appended to the JSONL log first (the structured-JSON log).
- If a collector URL is set, events are queued (bounded) and POSTed as JSON arrays.
- Failed batches go to the spool file; `python -m web_decoy.telemetry.replay` resends them.
- Requests never wait on the collector. When the queue is full, events are dropped
  from delivery (they are still in the JSONL log) and `dropped_events` goes up.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ..config import Settings


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def dumps_line(event: dict[str, Any]) -> str:
    # ensure_ascii keeps every line pure ASCII; json escapes \n, so one event = one line.
    return json.dumps(event, ensure_ascii=True, separators=(",", ":")) + "\n"


class JsonlWriter:
    """Append-only JSONL file with a size cap (one rotated backup)."""

    def __init__(self, path: str, max_bytes: int) -> None:
        self.path = Path(path)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.write_errors = 0

    def append(self, lines: list[str]) -> bool:
        data = "".join(lines)
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size + len(data) > self.max_bytes:
                    os.replace(self.path, self.path.with_name(self.path.name + ".1"))
                with open(self.path, "a", encoding="ascii", newline="\n") as fh:
                    fh.write(data)
                return True
            except OSError:
                self.write_errors += 1
                return False

    def count_lines(self) -> int:
        try:
            with open(self.path, "rb") as fh:
                return sum(1 for _ in fh)
        except OSError:
            return 0


class Emitter:
    def __init__(self, settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self.settings = settings
        self.url = settings.collector_url.strip()
        self.headers = {"Authorization": f"Bearer {settings.collector_token}"} if settings.collector_token else {}
        self.log = JsonlWriter(settings.event_log_path, settings.max_log_bytes)
        self.spool = JsonlWriter(settings.spool_path, settings.max_spool_bytes)
        self._transport = transport
        self.queue: asyncio.Queue[dict[str, Any]] | None = None
        self._task: asyncio.Task | None = None
        self._backoff_until = 0.0
        self._backoff_s = 1.0
        # stats for /health
        self.events_emitted_total = 0
        self.dropped_events = 0
        self.spooled_events = 0
        self.delivered_events = 0
        self.detections_total: Counter[str] = Counter()
        self.reachable: bool | None = None
        self.last_success: str | None = None
        self.last_error: str | None = None

    # ---- request path (sync, never blocks on the network) -------------------------
    def emit(self, event: dict[str, Any]) -> None:
        self.events_emitted_total += 1
        for d in event.get("raw_evidence_redacted", {}).get("detections", []):
            if isinstance(d, dict) and "rule" in d:
                self.detections_total[str(d["rule"])] += 1
        self.log.append([dumps_line(event)])
        if not self.url or self.queue is None:
            return
        try:
            self.queue.put_nowait(event)
        except asyncio.QueueFull:
            self.dropped_events += 1

    # ---- lifecycle ------------------------------------------------------------------
    async def start(self) -> None:
        if not self.url or self._task is not None:
            return
        self.queue = asyncio.Queue(maxsize=self.settings.queue_capacity)
        self._task = asyncio.create_task(self._run(), name="web-decoy-emitter")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
        # Never lose queued events on shutdown: spool whatever is left.
        leftover = self._drain_nowait(10**9)
        if leftover:
            self._to_spool(leftover)

    # ---- delivery loop ----------------------------------------------------------------
    def _drain_nowait(self, limit: int) -> list[dict[str, Any]]:
        batch: list[dict[str, Any]] = []
        while self.queue is not None and len(batch) < limit:
            try:
                batch.append(self.queue.get_nowait())
            except asyncio.QueueEmpty:
                break
        return batch

    async def _next_batch(self) -> list[dict[str, Any]]:
        assert self.queue is not None
        first = await self.queue.get()
        batch = [first]
        deadline = time.monotonic() + self.settings.flush_interval_s
        while len(batch) < self.settings.batch_size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                batch.append(await asyncio.wait_for(self.queue.get(), remaining))
            except asyncio.TimeoutError:
                break
        return batch

    async def _run(self) -> None:
        async with self._client() as client:
            while True:
                batch = await self._next_batch()
                if time.monotonic() < self._backoff_until:
                    self._to_spool(batch)  # collector known down: keep the queue empty
                    continue
                await self.send_batch(client, batch)

    def _client(self) -> httpx.AsyncClient:
        # trust_env=False: never route through HTTP(S)_PROXY env vars; no redirects followed.
        return httpx.AsyncClient(
            timeout=self.settings.post_timeout_s,
            trust_env=False,
            follow_redirects=False,
            transport=self._transport,
        )

    async def send_batch(self, client: httpx.AsyncClient, batch: list[dict[str, Any]]) -> bool:
        try:
            resp = await client.post(self.url, json=batch, headers=self.headers)
            ok = 200 <= resp.status_code < 300
            err = None if ok else f"collector returned HTTP {resp.status_code}"
        except httpx.HTTPError as exc:
            ok, err = False, f"{type(exc).__name__}"
        if ok:
            self.delivered_events += len(batch)
            self.reachable = True
            self.last_success = _now_iso()
            self._backoff_s = 1.0
            self._backoff_until = 0.0
            return True
        self.reachable = False
        self.last_error = err
        self._backoff_until = time.monotonic() + self._backoff_s
        self._backoff_s = min(self._backoff_s * 2, 30.0)
        self._to_spool(batch)
        return False

    def _to_spool(self, batch: list[dict[str, Any]]) -> None:
        if self.spool.append([dumps_line(e) for e in batch]):
            self.spooled_events += len(batch)
        else:
            self.dropped_events += len(batch)

    # ---- /health ----------------------------------------------------------------------
    def stats(self) -> dict[str, Any]:
        depth = self.queue.qsize() if self.queue is not None else 0
        degraded = self.reachable is False or self.dropped_events > 0 or self.log.write_errors > 0
        return {
            "status": "degraded" if degraded else "ok",
            "collector": {
                "url": self.url or None,
                "reachable": self.reachable,
                "last_success": self.last_success,
                "last_error": self.last_error,
            },
            "queue": {"depth": depth, "capacity": self.settings.queue_capacity,
                      "dropped_events": self.dropped_events},
            "spool": {"pending_events": self.spool.count_lines()},
            "events_emitted_total": self.events_emitted_total,
            "events_delivered_total": self.delivered_events,
            "log_write_errors": self.log.write_errors,
            "detections_total": dict(self.detections_total),
            "event_log_path": str(self.log.path),
        }
