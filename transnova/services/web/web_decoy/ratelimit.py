"""Per-source request rate limit (token bucket), with sampled logging.

Stops one source from flooding the decoy with fast requests. Over the limit, a
request gets 429 without its body being read. To keep a flood from flooding the
event log too, only ONE "rate_limited" event per source per `log_every_s` is
recorded, carrying the number of requests suppressed since the last one.
Memory is bounded by an LRU of sources.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable

MAX_SOURCES = 10_000


class RateLimiter:
    def __init__(self, rate_per_s: float, burst: int, log_every_s: float = 10.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.rate = float(rate_per_s)
        self.burst = float(burst)
        self.log_every_s = log_every_s
        self.clock = clock
        # source -> [tokens, last_refill, last_logged, suppressed_since_log]
        self._state: OrderedDict[str, list] = OrderedDict()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.rate > 0 and self.burst > 0

    def check(self, source: str) -> tuple[bool, int | None]:
        """Returns (allowed, suppressed_count_to_log).

        suppressed_count_to_log is None when this rejection should NOT be logged
        (it is counted instead); otherwise it is the number of rejections being
        reported by this event, including this one."""
        if not self.enabled:
            return True, None
        now = self.clock()
        with self._lock:
            st = self._state.get(source)
            if st is None:
                st = [self.burst, now, None, 0]
                self._state[source] = st
                while len(self._state) > MAX_SOURCES:
                    self._state.popitem(last=False)
            else:
                self._state.move_to_end(source)
            tokens, last, last_logged, suppressed = st
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            st[1] = now
            if tokens >= 1:
                st[0] = tokens - 1
                return True, None
            st[0] = tokens
            st[3] = suppressed + 1
            if last_logged is None or now - last_logged >= self.log_every_s:
                st[2] = now
                count, st[3] = st[3], 0
                return False, count
            return False, None
