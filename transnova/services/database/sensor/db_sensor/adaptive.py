"""Adaptive deception: observed behaviour → predefined rule → a real table-level GRANT.

Safety properties:
- Only names listed in rules.json, and validated at load time, ever reach a GRANT. Nothing
  taken from the audit log (query text, usernames) is placed in SQL.
- Each table is checked in mysql.tables_priv before and after, so the record states the actual
  privilege change, not the intent.
- A rule fires once per source, a table is granted once, and a failed grant retries a bounded
  number of times.
- The rule fires on the attacker's behaviour; the deterministic thresholds live in rules.json.

MariaDB grants belong to an account, not a connection. A reveal therefore applies to everyone
using decoy_user, not only to the source that triggered it (documented in the README).
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import pymysql

from .config import Settings
from .state import SensorState, SourceTracker

log = logging.getLogger("db_sensor.adaptive")
SAFE_IDENT = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
MAX_ATTEMPTS = 5


class GrantBackend:
    """The only code that holds the controller credential."""

    def __init__(self, s: Settings) -> None:
        self.s = s

    def _connect(self) -> pymysql.connections.Connection:
        return pymysql.connect(host=self.s.db_host, port=self.s.db_port, user=self.s.controller_user,
                               password=self.s.controller_password, database=self.s.db_name, connect_timeout=3,
                               read_timeout=5, write_timeout=5, autocommit=True)

    def has_grant(self, table: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT Table_priv FROM mysql.tables_priv WHERE Db=%s AND User=%s AND Host=%s AND Table_name=%s",
                        (self.s.db_name, self.s.attacker_account, self.s.attacker_host, table))
            row = cur.fetchone()
            return bool(row) and "Select" in str(row[0])

    def grant(self, table: str) -> str:
        return self._apply("GRANT SELECT ON `{db}`.`{table}` TO '{user}'@'{host}'", table)

    def revoke(self, table: str) -> str:
        return self._apply("REVOKE SELECT ON `{db}`.`{table}` FROM '{user}'@'{host}'", table)

    def _apply(self, template: str, table: str) -> str:
        if not SAFE_IDENT.match(table):
            raise ValueError("unsafe table identifier refused")
        sql = template.format(db=self.s.db_name, table=table, user=self.s.attacker_account, host=self.s.attacker_host)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(sql)
        return sql

    def ping(self) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute("SELECT 1")
            return cur.fetchone() == (1,)


class AdaptiveEngine:
    def __init__(self, settings: Settings, rules: dict[str, Any], state: SensorState, backend: GrantBackend,
                 emit: Callable[[dict[str, Any]], None]) -> None:
        self.s, self.rules, self.state, self.backend, self.emit = settings, rules, state, backend, emit
        self.sensitive_group = set(rules["sensitive_tables"]) | set(rules["adaptive_tables"])
        self.attempts: dict[str, int] = {}

    def _matches(self, rule: dict[str, Any], t: SourceTracker) -> str | None:
        group = self.sensitive_group if rule.get("tables_group") == "sensitive_and_adaptive" else set(rule["tables"])
        hits = {k: v for k, v in t.table_hits.items() if k in group}
        queries, distinct = sum(hits.values()), len(hits)
        if queries < rule["min_queries"] or distinct < rule["min_distinct_tables"]:
            return None
        if len(t.rules_fired) < rule.get("requires_rules_fired", 0):
            return None
        return (f"{rule['description']}: {queries} successful reads across {distinct} table(s) "
                f"({', '.join(sorted(hits))}); threshold {rule['min_queries']} reads, "
                f"{rule['min_distinct_tables']} table(s)")

    def evaluate(self, tracker_key: str, event: dict[str, Any]) -> list[dict[str, Any]]:
        if not self.s.adaptive_enabled or event.get("event_type") != "sql_query" or event.get("outcome") != "succeeded":
            return []
        tracker = self.state.tracker(tracker_key)
        results = []
        for rule in self.rules["adaptive_rules"]:
            if rule["id"] in tracker.rules_fired:
                continue
            reason = self._matches(rule, tracker)
            if reason is None:
                continue
            records = [self._reveal(rule, tracker, table, reason, event) for table in rule["reveal"]]
            results.extend(records)
            if all(r["status"] in ("applied", "already_present") for r in records):
                tracker.rules_fired.append(rule["id"])
                self.state.dirty_trackers.add(tracker_key)
            else:
                count = self.attempts[rule["id"]] = self.attempts.get(rule["id"], 0) + 1
                if count >= MAX_ATTEMPTS:
                    log.error("rule %s gave up after %d failed attempts", rule["id"], count)
                    tracker.rules_fired.append(rule["id"])
        return results

    def _reveal(self, rule: dict[str, Any], tracker: SourceTracker, table: str, reason: str,
                event: dict[str, Any]) -> dict[str, Any]:
        record: dict[str, Any] = {
            "adaptation_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sensor_id": self.s.sensor_id, "service": "database", "rule_id": rule["id"], "stage": rule["stage"],
            "trigger_event_id": event["event_id"], "trigger_session_id": event["session_id"],
            "trigger_reason": reason, "adaptation_type": "table_select_grant", "asset_revealed": table,
            "source_ip": event["source_ip"], "tracker_key": tracker.key,
            "target_account": f"{self.s.attacker_account}@{self.s.attacker_host}",
            "privilege_before": None, "privilege_after": None, "statement": None, "status": "failed", "error": None,
        }
        try:
            before = self.backend.has_grant(table)
            record["privilege_before"] = before
            if before:
                record["status"] = "already_present"  # idempotent: no second GRANT
                record["privilege_after"] = True
            else:
                record["statement"] = self.backend.grant(table)
                after = self.backend.has_grant(table)
                record["privilege_after"] = after
                record["status"] = "applied" if after else "failed"
        except pymysql.MySQLError as exc:
            record["error"] = f"{type(exc).__name__}: {exc.args[0] if exc.args else ''}"
            log.error("reveal of %s failed: %s", table, record["error"])
        self.state.record_reveal(record)
        self.emit(record)
        log.info("adaptation rule=%s asset=%s status=%s", rule["id"], table, record["status"])
        return record
