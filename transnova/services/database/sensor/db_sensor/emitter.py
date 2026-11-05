"""Durable delivery, matching the web decoy's contract (docs/INTEGRATOR_NOTES.md §1).

Each record is first appended to a JSONL log. Failed sends go to a spool file, which is resent
before anything new. A collector outage therefore delays events but cannot lose them. The
collector deduplicates on event_id, so at-least-once delivery is safe.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("db_sensor.emitter")


def dumps_line(record: dict[str, Any]) -> str:
    return json.dumps(record, ensure_ascii=True, separators=(",", ":")) + "\n"


class DurableSender:
    def __init__(self, url: str, log_path: Path, spool_path: Path, batch_size: int, timeout_s: float,
                 max_log_bytes: int, transport: httpx.BaseTransport | None = None) -> None:
        self.url, self.log_path, self.spool_path = url, log_path, spool_path
        self.batch_size, self.max_log_bytes = batch_size, max_log_bytes
        # trust_env=False: never pick up an HTTP proxy from the environment.
        self.client = httpx.Client(timeout=timeout_s, trust_env=False, follow_redirects=False, transport=transport)
        self.pending: list[dict[str, Any]] = []
        self.delivered = 0
        self.reachable: bool | None = None
        self.last_error: str | None = None
        self._backoff_s = 1.0
        self._retry_at = 0.0

    def add(self, record: dict[str, Any]) -> None:
        self._rotate_if_needed()
        with open(self.log_path, "a", encoding="ascii", newline="\n") as fh:
            fh.write(dumps_line(record))
        self.pending.append(record)

    def _rotate_if_needed(self) -> None:
        if self.log_path.exists() and self.log_path.stat().st_size > self.max_log_bytes:
            os.replace(self.log_path, self.log_path.with_name(self.log_path.name + ".1"))

    def _post(self, batch: list[dict[str, Any]]) -> bool:
        try:
            resp = self.client.post(self.url, json=batch)
            ok, err = 200 <= resp.status_code < 300, f"HTTP {resp.status_code}: {resp.text[:200]}"
        except httpx.HTTPError as exc:
            ok, err = False, type(exc).__name__
        self.reachable = ok
        if ok:
            self.delivered += len(batch)
            self.last_error = None
            self._backoff_s = 1.0
        else:
            self.last_error = err
            self._retry_at = time.monotonic() + self._backoff_s
            self._backoff_s = min(self._backoff_s * 2, 30.0)
            log.warning("delivery to %s failed: %s; next retry in %.0fs", self.url, err, self._backoff_s)
        return ok

    def _spool(self, records: list[dict[str, Any]]) -> None:
        with open(self.spool_path, "a", encoding="ascii", newline="\n") as fh:
            fh.writelines(dumps_line(r) for r in records)

    def _read_spool(self) -> list[dict[str, Any]]:
        if not self.spool_path.exists():
            return []
        records = []
        with open(self.spool_path, encoding="ascii") as fh:
            for line in fh:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    log.error("skipping a torn spool line (%d chars); it is still in %s", len(line), self.log_path)
        return records

    def _rewrite_spool(self, records: list[dict[str, Any]]) -> None:
        tmp = self.spool_path.with_name(self.spool_path.name + ".tmp")
        with open(tmp, "w", encoding="ascii", newline="\n") as fh:
            fh.writelines(dumps_line(r) for r in records)
        os.replace(tmp, self.spool_path)

    def flush(self) -> None:
        if time.monotonic() < self._retry_at:
            self._spool(self.pending)
            self.pending = []
            return
        queue = self._read_spool() + self.pending
        self.pending = []
        sent = 0
        while sent < len(queue):
            batch = queue[sent:sent + self.batch_size]
            if not self._post(batch):
                break
            sent += len(batch)
        remaining = queue[sent:]
        if remaining or self.spool_path.exists():
            self._rewrite_spool(remaining)

    def spool_depth(self) -> int:
        try:
            with open(self.spool_path, "rb") as fh:
                return sum(1 for _ in fh)
        except FileNotFoundError:
            return 0
