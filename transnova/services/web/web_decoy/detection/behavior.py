"""Stateful, per-source behaviour rules (PLAN.md §5.2).

State is in memory, per process, bounded by an LRU of sources. A restart resets
it (documented limitation). Thresholds and windows are constants here and are
written into every rationale, so the SOC can see exactly why something fired.

Once a behaviour threshold is crossed, EVERY qualifying request from that source
carries the rule (with the running count) for as long as the count stays at or
above the threshold inside the sliding window. A sustained attack therefore
keeps showing at its current severity instead of going quiet after one alert.
The collector/dashboard should group alerts by (source_ip, rule_id) if it wants
one incident per attack.
Cross-sensor correlation belongs to the collector, not this module.
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from .. import fixtures
from .mappings import make
from .signatures import SENSITIVE_EXACT, SENSITIVE_PREFIX

# Thresholds (PLAN.md §5.2)
SCAN_DISTINCT_PATHS = 8
SCAN_WINDOW_S = 60.0
BRUTE_FAILS = 5
BRUTE_FAILS_HIGH = 15
BRUTE_WINDOW_S = 60.0
SPRAY_USERS = 4
SPRAY_MAX_TRIES_PER_USER = 2
SPRAY_WINDOW_S = 300.0
MAX_SOURCES = 10_000
MAX_EVENTS_PER_SOURCE = 500

USER_PATH = re.compile(r"^/api/v1/users/(\d{1,9})$")
SHIPMENT_PATH = re.compile(r"^/portal/shipments/(\d{1,9})$")


@dataclass
class SourceState:
    paths: deque = field(default_factory=deque)          # (ts, path) of 403/404/405/bait hits
    fails: deque = field(default_factory=deque)          # (ts, username) failed logins


def _prune(dq: deque, now: float, window: float) -> None:
    while dq and now - dq[0][0] > window:
        dq.popleft()


class BehaviorEngine:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.clock = clock
        self._sources: OrderedDict[str, SourceState] = OrderedDict()
        self._lock = threading.Lock()

    def _state(self, source: str) -> SourceState:
        st = self._sources.get(source)
        if st is None:
            st = SourceState()
            self._sources[source] = st
            while len(self._sources) > MAX_SOURCES:
                self._sources.popitem(last=False)
        else:
            self._sources.move_to_end(source)
        return st

    def __len__(self) -> int:
        return len(self._sources)

    def detect(self, ctx) -> list[dict[str, Any]]:
        now = self.clock()
        out: list[dict[str, Any]] = []
        route = ctx.route or {}
        with self._lock:
            st = self._state(ctx.source_ip)
            out += self._route_scan(ctx, st, now)
            if route.get("auth"):
                out += self._auth(route, st, now)
        out += self._idor(ctx)
        return out

    # ---- W-ENUM-02 ----------------------------------------------------------------
    def _route_scan(self, ctx, st: SourceState, now: float) -> list[dict[str, Any]]:
        path = ctx.path[:256]
        bait = path in SENSITIVE_EXACT or path.startswith(SENSITIVE_PREFIX)
        if ctx.status not in (403, 404, 405) and not bait:
            return []
        st.paths.append((now, path))
        if len(st.paths) > MAX_EVENTS_PER_SOURCE:
            st.paths.popleft()
        _prune(st.paths, now, SCAN_WINDOW_S)
        distinct = len({p for _, p in st.paths})
        if distinct >= SCAN_DISTINCT_PATHS:
            return [make("W-ENUM-02", "path",
                         f"{distinct} distinct missing/forbidden/bait paths from this source within "
                         f"{int(SCAN_WINDOW_S)}s (threshold {SCAN_DISTINCT_PATHS}); tagged on every "
                         f"qualifying request while at or above threshold")]
        return []

    # ---- W-AUTH-01..04 --------------------------------------------------------------
    def _auth(self, route: dict, st: SourceState, now: float) -> list[dict[str, Any]]:
        username = str(route.get("username") or "")[:64]
        out: list[dict[str, Any]] = []
        _prune(st.fails, now, SPRAY_WINDOW_S)

        if route.get("outcome") == "succeeded":
            prior = sum(1 for _, u in st.fails if u == username)
            why = "synthetic decoy credential accepted; all later activity in this session is attacker activity"
            if prior:
                why += f" (after {prior} failed attempts for this username within {int(SPRAY_WINDOW_S)}s)"
            return [make("W-AUTH-04", "form.username", why)]

        if route.get("outcome") != "failed":
            return []
        st.fails.append((now, username))
        if len(st.fails) > MAX_EVENTS_PER_SOURCE:
            st.fails.popleft()
        out.append(make("W-AUTH-01", "form.username", "failed login attempt"))

        # Brute force: same username, short window.
        recent_same = sum(1 for ts, u in st.fails if u == username and now - ts <= BRUTE_WINDOW_S)
        if recent_same >= BRUTE_FAILS:
            conf = "high" if recent_same >= BRUTE_FAILS_HIGH else "medium"
            out.append(make("W-AUTH-02", "form.username",
                            f"{recent_same} failed logins for one username from this source within "
                            f"{int(BRUTE_WINDOW_S)}s (threshold {BRUTE_FAILS} medium / {BRUTE_FAILS_HIGH} high)",
                            confidence=conf, attack_confidence=conf))

        # Spraying: many usernames, few tries each, longer window.
        per_user: dict[str, int] = {}
        for _, u in st.fails:
            per_user[u] = per_user.get(u, 0) + 1
        light = [u for u, n in per_user.items() if n <= SPRAY_MAX_TRIES_PER_USER]
        if len(light) >= SPRAY_USERS:
            out.append(make("W-AUTH-03", "form.username",
                            f"{len(light)} distinct usernames with <= {SPRAY_MAX_TRIES_PER_USER} tries each from "
                            f"this source within {int(SPRAY_WINDOW_S)}s (threshold {SPRAY_USERS}); tagged on every failed "
                            f"login while at or above threshold"))
        return out

    # ---- W-IDOR-01 ----------------------------------------------------------------
    @staticmethod
    def _idor(ctx) -> list[dict[str, Any]]:
        uid = ctx.session_user_id
        if uid is None or ctx.method != "GET":
            return []
        m = USER_PATH.match(ctx.path)
        if m and int(m.group(1)) in fixtures.USERS and int(m.group(1)) != uid:
            return [make("W-IDOR-01", "path", "logged-in user requested another user's record "
                                              "(synthetic data; object-level authorization bait)")]
        m = SHIPMENT_PATH.match(ctx.path)
        if m:
            ship = fixtures.SHIPMENTS.get(int(m.group(1)))
            if ship and ship["owner_id"] != uid:
                return [make("W-IDOR-01", "path", "logged-in user requested another partner's shipment "
                                                  "(synthetic data; object-level authorization bait)")]
        return []
