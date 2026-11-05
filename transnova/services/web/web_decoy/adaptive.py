"""Adaptive web deception (USP 6).

Ordinary visitors see an ordinary portal. Once a source shows attack intent (scanning, injection,
traversal, SSRF, brute force, web-shell probing, suspicious upload), the portal starts showing it one
extra, juicy breadcrumb: a "nightly ERP replica export" under /backup/. Nobody else is ever shown that
link, so opening it is a near-certain attacker signal (W-ADAPT-01, high). The file is synthetic and its
credentials are fake honeytokens; nothing real is served.

In memory, bounded, per process (like the behaviour windows). Pure bookkeeping: no I/O.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict

INTENT_RULES = frozenset({"W-SQLI-01", "W-XSS-01", "W-PATH-01", "W-SSRF-01", "W-ENUM-02", "W-AUTH-02", "W-AUTH-03",
                          "W-SHELL-01", "W-UPL-01"})
BAIT_PATH = "/backup/erp-replica-2026-10-31.sql"
ENGAGED_TTL_S = 3600.0
MAX_SOURCES = 10_000

BAIT_BODY = """-- MariaDB dump 10.19  Distrib 11.4.9-MariaDB, for debian-linux-gnu (x86_64)
-- Host: db-replica.transnova.internal    Database: tnl_erp_report
-- Server version	11.4.9-MariaDB-log
-- Nightly partner-reporting export (ops only). Restore with: mysql -u erp_report -p tnl_erp_report < file
-- connection used by the export job: erp_report / Rpt#Replica2026!   (rotate after OPS-412)

DROP TABLE IF EXISTS `partner_accounts`;
CREATE TABLE `partner_accounts` (
  `id` int NOT NULL, `username` varchar(64), `company` varchar(128), `api_key` char(40), PRIMARY KEY (`id`)
);
INSERT INTO `partner_accounts` VALUES
 (1001,'j.miller','Brightwater Imports','tnl_live_7f3a9c2e1b8d4f60a5e2c9b7d1f3a8e6c4b2d0f9'),
 (1002,'a.okafor','Okafor Textiles','tnl_live_2b9e4d7a1c6f8e3b5d0a9c7e2f4b6d8a1c3e5f70'),
 (1004,'m.kowalski','Vistula Agro Export','tnl_live_9c1e7b3d5f2a8c4e6b0d2f9a7c5e3b1d8f6a4c20');
-- (export truncated: 41,882 rows omitted)
"""


class AdaptiveDeception:
    def __init__(self, clock=time.monotonic) -> None:
        self.clock = clock
        self._engaged: OrderedDict[str, float] = OrderedDict()   # source -> when intent was last seen
        self._revealed: OrderedDict[str, float] = OrderedDict()  # source -> when the bait was first shown
        self._lock = threading.Lock()

    def _put(self, table: OrderedDict, source: str, value: float) -> None:
        table[source] = value
        table.move_to_end(source)
        while len(table) > MAX_SOURCES:
            table.popitem(last=False)

    def observe(self, source: str, rules: set[str]) -> None:
        """Called after detection for every request."""
        if rules & INTENT_RULES:
            with self._lock:
                self._put(self._engaged, source, self.clock())

    def engaged(self, source: str | None) -> bool:
        if not source:
            return False
        with self._lock:
            ts = self._engaged.get(source)
            return ts is not None and self.clock() - ts <= ENGAGED_TTL_S

    def reveal(self, source: str) -> bool:
        """Mark the bait as shown to this source. Returns True the first time."""
        with self._lock:
            first = source not in self._revealed
            if first:
                self._put(self._revealed, source, self.clock())
            return first

    def was_revealed(self, source: str | None) -> bool:
        if not source:
            return False
        with self._lock:
            return source in self._revealed
