"""Pulls the SOC's blocklist so attackers caught by the honeypot are refused here too (USP 1).

The collector (on the dashboard laptop) decides who is blocked; this site only enforces it. A
background thread polls POST /api/blocklist/feed every few seconds with the web ingest token.
Fail-safe choices: if the collector is unreachable the last good list stays in force (an attacker
cannot unblock themselves by cutting the link), and a malformed answer is ignored. Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
import urllib.request
from typing import Callable

MAX_FEED_BYTES = 1 << 20
MAX_IPS = 50_000


def _parse(raw: bytes) -> set[str] | None:
    try:
        data = json.loads(raw)
        ips = data["ips"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(ips, list) or len(ips) > MAX_IPS:
        return None
    out = set()
    for ip in ips:
        try:
            out.add(str(ipaddress.ip_address(str(ip))))
        except ValueError:
            continue
    return out


def http_fetch(url: str, token: str, timeout: float = 3.0) -> bytes:
    req = urllib.request.Request(url, data=b"{}", method="POST",
                                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                          "User-Agent": "transnova-mainsite/1.0"})
    # Direct connection only: the collector is on the same LAN, and a system proxy would break that.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as resp:  # noqa: S310 (operator-configured URL)
        return resp.read(MAX_FEED_BYTES + 1)


class BlockFeed:
    def __init__(self, url: str, token: str, interval_s: float = 5.0,
                 fetch: Callable[[str, str], bytes] = http_fetch) -> None:
        self.url, self.token, self.interval_s, self._fetch = url, token, interval_s, fetch
        self.ips: frozenset[str] = frozenset()
        self.last_ok: float | None = None
        self.last_error: str | None = None
        self.polls = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def poll_once(self) -> None:
        self.polls += 1
        try:
            raw = self._fetch(self.url, self.token)
        except Exception as exc:  # noqa: BLE001 - network errors must never reach a visitor
            self.last_error = exc.__class__.__name__
            return
        parsed = _parse(raw) if len(raw) <= MAX_FEED_BYTES else None
        if parsed is None:
            self.last_error = "bad feed"
            return
        self.ips, self.last_ok, self.last_error = frozenset(parsed), time.time(), None

    def start(self) -> None:
        if self._thread is None:
            self._thread = threading.Thread(target=self._run, name="blockfeed", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.poll_once()
            self._stop.wait(self.interval_s)

    def blocked(self, ip: str | None) -> bool:
        return bool(ip) and ip in self.ips

    def status(self) -> dict:
        return {"enabled": True, "blocked_ips": len(self.ips), "last_ok": self.last_ok, "last_error": self.last_error,
                "polls": self.polls}
