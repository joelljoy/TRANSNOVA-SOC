"""SQLite persistence. Documents are stored as JSON, with a few indexed columns for filtering.

Events are evidence and are never updated or deleted here. Everything an analyst decides lives in
its own table (alert_state, alert_history, event_annotations, explanations) and points at the
event or alert, so the original observation always survives a reclassification.

Migrations are additive only: virtual generated columns read the stored JSON, so adding one
rewrites no row and an older database opens unchanged.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

# One read loads at most this much stored text, newest first. Rows stay stored, but a result may be
# incomplete. Unauthenticated senders can store large rows, and without this a dashboard read of
# them can exhaust memory again after every restart.
MAX_READ_BYTES = 64 << 20

_EVENT_COLUMNS = {
    "event_type": "json_extract(doc, '$.event_type')",
    "action": "json_extract(doc, '$.action')",
    "outcome": "json_extract(doc, '$.outcome')",
    "sensor_id": "json_extract(doc, '$.sensor_id')",
    "username": "json_extract(doc, '$.username')",
    "request_path": "json_extract(doc, '$.request_path')",
    "command": "json_extract(doc, '$.command')",
    "campaign_id": "json_extract(doc, '$.campaign_id')",
    "n_detections": "coalesce(json_array_length(doc, '$.raw_evidence_redacted.detections'), 0)",
}
_ALERT_COLUMNS = {
    "rule": "json_extract(doc, '$.rule')",
    "a_source_ip": "json_extract(doc, '$.source_ip')",
    "severity": "json_extract(doc, '$.severity')",
    "a_service": "json_extract(doc, '$.service')",
    "first_seen": "json_extract(doc, '$.first_seen')",
}
SEVERITY_RANK = "CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Store:
    def __init__(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.lock = threading.Lock()
        self.read_capped_at: str | None = None
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY, ts TEXT NOT NULL, service TEXT NOT NULL,
                source_ip TEXT NOT NULL, session_id TEXT, doc TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_src ON events(source_ip);
            CREATE TABLE IF NOT EXISTS alerts (
                dedupe_key TEXT PRIMARY KEY, alert_id TEXT NOT NULL, last_seen TEXT NOT NULL, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS adaptations (
                adaptation_id TEXT PRIMARY KEY, ts TEXT NOT NULL, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sensors (
                sensor_id TEXT PRIMARY KEY, last_seen TEXT NOT NULL, doc TEXT NOT NULL);
        """)
        self._migrate()

    def _migrate(self) -> None:
        with self.lock, self.db:
            for table, columns in (("events", _EVENT_COLUMNS), ("alerts", _ALERT_COLUMNS)):
                have = {row[1] for row in self.db.execute(f"PRAGMA table_xinfo({table})")}
                for name, expr in columns.items():
                    if name not in have:
                        self.db.execute(f"ALTER TABLE {table} ADD COLUMN {name} GENERATED ALWAYS AS ({expr}) VIRTUAL")
            self.db.executescript("""
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
                CREATE INDEX IF NOT EXISTS idx_events_outcome ON events(outcome);
                CREATE INDEX IF NOT EXISTS idx_events_sensor ON events(sensor_id, ts);
                CREATE INDEX IF NOT EXISTS idx_events_service_ts ON events(service, ts);
                CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_id ON alerts(alert_id);
                CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(a_source_ip);
                CREATE TABLE IF NOT EXISTS alert_events (
                    alert_id TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (alert_id, event_id));
                CREATE INDEX IF NOT EXISTS idx_alert_events_event ON alert_events(event_id);
                CREATE TABLE IF NOT EXISTS alert_state (
                    alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, updated_at TEXT NOT NULL, updated_by TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS alert_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, ts TEXT NOT NULL, actor TEXT NOT NULL,
                    action TEXT NOT NULL, from_status TEXT, to_status TEXT, note TEXT);
                CREATE INDEX IF NOT EXISTS idx_alert_history ON alert_history(alert_id, id);
                CREATE TABLE IF NOT EXISTS event_annotations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL, ts TEXT NOT NULL, actor TEXT NOT NULL,
                    classification TEXT NOT NULL, previous TEXT, reason TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_event_annotations ON event_annotations(event_id, id);
                CREATE TABLE IF NOT EXISTS explanations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id TEXT NOT NULL, ts TEXT NOT NULL, actor TEXT NOT NULL,
                    model TEXT NOT NULL, evidence_digest TEXT NOT NULL, doc TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_explanations ON explanations(alert_id, id);
                CREATE TABLE IF NOT EXISTS blocklist (
                    ip TEXT PRIMARY KEY, created_at TEXT NOT NULL, expires_at TEXT NOT NULL, actor TEXT NOT NULL,
                    rule TEXT, alert_id TEXT, reason TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS block_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, ip TEXT NOT NULL, action TEXT NOT NULL,
                    actor TEXT NOT NULL, rule TEXT, alert_id TEXT, reason TEXT);
            """)
            # Alerts raised before this table existed still get their event links.
            if not self.db.execute("SELECT 1 FROM alert_events LIMIT 1").fetchone():
                for alert_id, doc in self.db.execute("SELECT alert_id, doc FROM alerts").fetchall():
                    ids = json.loads(doc).get("related_event_ids") or []
                    self.db.executemany("INSERT OR IGNORE INTO alert_events VALUES (?, ?)", [(alert_id, i) for i in ids])

    def _read(self, sql: str, args: tuple[Any, ...]) -> list[dict[str, Any]]:
        docs: list[str] = []
        total = 0
        with self.lock:
            cursor = self.db.execute(sql, args)
            try:
                for (doc,) in cursor:
                    total += len(doc)
                    if docs and total > MAX_READ_BYTES:
                        self.read_capped_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                        break
                    docs.append(doc)
            finally:
                cursor.close()
        return [json.loads(doc) for doc in docs]

    def _rows(self, sql: str, args: Iterable[Any] = ()) -> list[tuple[Any, ...]]:
        with self.lock:
            return self.db.execute(sql, tuple(args)).fetchall()

    # ---- events -------------------------------------------------------------------------------

    def insert_event(self, event: dict[str, Any]) -> bool:
        """False when event_id was already stored: resends are expected (INTEGRATOR_NOTES §1)."""
        with self.lock, self.db:
            cur = self.db.execute(
                "INSERT OR IGNORE INTO events (event_id, ts, service, source_ip, session_id, doc) VALUES (?, ?, ?, ?, ?, ?)",
                (event["event_id"], event["timestamp"], event["service"], event["source_ip"], event["session_id"],
                 json.dumps(event)))
        return cur.rowcount == 1

    def events(self, limit: int, offset: int = 0, service: str | None = None, source_ip: str | None = None,
               session_id: str | None = None) -> list[dict[str, Any]]:
        where, args = [], []
        for col, val in (("service", service), ("source_ip", source_ip), ("session_id", session_id)):
            if val:
                where.append(f"{col} = ?")
                args.append(val)
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        return self._read(f"SELECT doc FROM events {clause} ORDER BY ts DESC, rowid DESC LIMIT ? OFFSET ?",
                          (*args, limit, offset))

    def query_events(self, where: list[str], args: list[Any], limit: int, offset: int,
                     ascending: bool = False) -> tuple[list[dict[str, Any]], int]:
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        order = "ASC" if ascending else "DESC"
        docs = self._read(f"SELECT doc FROM events {clause} ORDER BY ts {order}, rowid {order} LIMIT ? OFFSET ?",
                          (*args, limit, offset))
        total = self._rows(f"SELECT COUNT(*) FROM events {clause}", args)[0][0]
        return docs, total

    def events_by_ids(self, ids: list[str]) -> list[dict[str, Any]]:
        if not ids:
            return []
        marks = ",".join("?" * len(ids))
        return self._read(f"SELECT doc FROM events WHERE event_id IN ({marks}) ORDER BY ts ASC, rowid ASC", tuple(ids))

    def event(self, event_id: str) -> dict[str, Any] | None:
        found = self._read("SELECT doc FROM events WHERE event_id = ?", (event_id,))
        return found[0] if found else None

    def count_events(self) -> int:
        with self.lock:
            return self.db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def latest_rowid(self) -> int:
        return self._rows("SELECT coalesce(max(rowid), 0) FROM events")[0][0]

    def services_for_source(self, source_ip: str, since: str) -> set[str]:
        with self.lock:
            rows = self.db.execute("SELECT DISTINCT service FROM events WHERE source_ip = ? AND ts >= ? AND service != 'soc'",
                                   (source_ip, since)).fetchall()
        return {r[0] for r in rows}

    def latest_per_service(self, source_ip: str, since: str) -> dict[str, str]:
        """The newest event ID from each decoy service for one source since a time."""
        rows = self._rows("SELECT service, event_id FROM events WHERE source_ip = ? AND ts >= ? AND service != 'soc' "
                          "ORDER BY ts", (source_ip, since))
        return {service: event_id for service, event_id in rows}

    def recent_auth_failures(self, service: str, since: str, *, source_ip: str | None = None,
                             username: str | None = None) -> list[str]:
        """Event IDs of failed authentication events for one service since a time, by source or username."""
        where = ["service = ?", "event_type = 'authentication'", "outcome = 'failed'", "ts >= ?"]
        args: list[Any] = [service, since]
        if source_ip is not None:
            where.append("source_ip = ?")
            args.append(source_ip)
        if username is not None:
            where.append("username = ?")
            args.append(username)
        return [r[0] for r in self._rows(f"SELECT event_id FROM events WHERE {' AND '.join(where)} ORDER BY ts", args)]

    def recent_rule_events(self, source_ip: str, rule: str, since: str, until: str,
                           username: str | None = None) -> list[str]:
        """Event IDs from one source carrying a rule match in a time window, oldest first."""
        where = ["source_ip = ?", "ts >= ?", "ts <= ?", "EXISTS (SELECT 1 FROM json_each(events.doc, "
                 "'$.raw_evidence_redacted.detections') d WHERE json_extract(d.value, '$.rule') = ?)"]
        args: list[Any] = [source_ip, since, until, rule]
        if username is not None:
            where.append("username = ?")
            args.append(username)
        return [r[0] for r in self._rows(f"SELECT event_id FROM events WHERE {' AND '.join(where)} ORDER BY ts LIMIT 200", args)]

    # ---- annotations (classification changes; the event itself never changes) ----------------

    def annotate_event(self, event_id: str, actor: str, classification: str, reason: str) -> dict[str, Any]:
        previous = self.event_classification(event_id)
        ts = now_iso()
        with self.lock, self.db:
            self.db.execute("INSERT INTO event_annotations (event_id, ts, actor, classification, previous, reason) "
                            "VALUES (?, ?, ?, ?, ?, ?)", (event_id, ts, actor, classification,
                                                          previous["classification"] if previous else None, reason))
        return {"event_id": event_id, "ts": ts, "actor": actor, "classification": classification,
                "previous": previous["classification"] if previous else None, "reason": reason}

    def event_annotations(self, event_id: str) -> list[dict[str, Any]]:
        rows = self._rows("SELECT ts, actor, classification, previous, reason FROM event_annotations "
                          "WHERE event_id = ? ORDER BY id", (event_id,))
        return [dict(zip(("ts", "actor", "classification", "previous", "reason"), r)) for r in rows]

    def event_classification(self, event_id: str) -> dict[str, Any] | None:
        notes = self.event_annotations(event_id)
        return notes[-1] if notes else None

    def classifications_for(self, ids: list[str]) -> dict[str, str]:
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        rows = self._rows(f"SELECT event_id, classification FROM event_annotations WHERE event_id IN ({marks}) "
                          "ORDER BY id", ids)
        return {event_id: label for event_id, label in rows}

    # ---- alerts -------------------------------------------------------------------------------

    def get_alert(self, key: str) -> dict[str, Any] | None:
        with self.lock:
            row = self.db.execute("SELECT doc FROM alerts WHERE dedupe_key = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def alert_by_id(self, alert_id: str) -> dict[str, Any] | None:
        found = self._read("SELECT doc FROM alerts WHERE alert_id = ?", (alert_id,))
        return found[0] if found else None

    def put_alert(self, key: str, alert: dict[str, Any], event_ids: Iterable[str] = ()) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO alerts (dedupe_key, alert_id, last_seen, doc) VALUES (?, ?, ?, ?)",
                            (key, alert["alert_id"], alert["last_seen"], json.dumps(alert)))
            self.db.executemany("INSERT OR IGNORE INTO alert_events VALUES (?, ?)",
                                [(alert["alert_id"], event_id) for event_id in event_ids])

    def alerts(self, limit: int) -> list[dict[str, Any]]:
        return self._read("SELECT doc FROM alerts ORDER BY last_seen DESC LIMIT ?", (limit,))

    def query_alerts(self, where: list[str], args: list[Any], limit: int, offset: int,
                     sort: str = "recent") -> tuple[list[dict[str, Any]], int]:
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        order = f"{SEVERITY_RANK}, last_seen DESC" if sort == "severity" else "last_seen DESC"
        base = f"FROM alerts LEFT JOIN alert_state USING (alert_id) {clause}"
        docs = self._read(f"SELECT doc {base} ORDER BY {order} LIMIT ? OFFSET ?", (*args, limit, offset))
        total = self._rows(f"SELECT COUNT(*) {base}", args)[0][0]
        return docs, total

    def alert_ids_for_events(self, ids: list[str]) -> dict[str, list[str]]:
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        out: dict[str, list[str]] = {}
        for event_id, alert_id in self._rows(f"SELECT event_id, alert_id FROM alert_events WHERE event_id IN ({marks})", ids):
            out.setdefault(event_id, []).append(alert_id)
        return out

    def alert_event_ids(self, alert_id: str) -> list[str]:
        return [r[0] for r in self._rows("SELECT event_id FROM alert_events WHERE alert_id = ?", (alert_id,))]

    def alert_status(self, alert_id: str) -> dict[str, Any] | None:
        rows = self._rows("SELECT status, updated_at, updated_by FROM alert_state WHERE alert_id = ?", (alert_id,))
        return dict(zip(("status", "updated_at", "updated_by"), rows[0])) if rows else None

    def statuses_for(self, ids: list[str]) -> dict[str, dict[str, Any]]:
        if not ids:
            return {}
        marks = ",".join("?" * len(ids))
        rows = self._rows(f"SELECT alert_id, status, updated_at, updated_by FROM alert_state WHERE alert_id IN ({marks})", ids)
        return {r[0]: {"status": r[1], "updated_at": r[2], "updated_by": r[3]} for r in rows}

    def set_alert_status(self, alert_id: str, actor: str, action: str, from_status: str, to_status: str,
                         note: str | None) -> dict[str, Any]:
        ts = now_iso()
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO alert_state VALUES (?, ?, ?, ?)", (alert_id, to_status, ts, actor))
            self.db.execute("INSERT INTO alert_history (alert_id, ts, actor, action, from_status, to_status, note) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?)", (alert_id, ts, actor, action, from_status, to_status, note))
        return {"ts": ts, "actor": actor, "action": action, "from_status": from_status, "to_status": to_status,
                "note": note}

    def add_alert_note(self, alert_id: str, actor: str, note: str) -> dict[str, Any]:
        ts = now_iso()
        with self.lock, self.db:
            self.db.execute("INSERT INTO alert_history (alert_id, ts, actor, action, note) VALUES (?, ?, ?, 'note', ?)",
                            (alert_id, ts, actor, note))
        return {"ts": ts, "actor": actor, "action": "note", "from_status": None, "to_status": None, "note": note}

    def alert_history(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self._rows("SELECT ts, actor, action, from_status, to_status, note FROM alert_history "
                          "WHERE alert_id = ? ORDER BY id", (alert_id,))
        return [dict(zip(("ts", "actor", "action", "from_status", "to_status", "note"), r)) for r in rows]

    def alert_change_marker(self) -> tuple[str | None, int]:
        last = self._rows("SELECT max(last_seen) FROM alerts")[0][0]
        history = self._rows("SELECT coalesce(max(id), 0) FROM alert_history")[0][0]
        return last, history

    # ---- explanations (AI output is stored as interpretation, apart from evidence) ------------

    def add_explanation(self, alert_id: str, actor: str, model: str, digest: str, doc: dict[str, Any]) -> dict[str, Any]:
        ts = now_iso()
        with self.lock, self.db:
            self.db.execute("INSERT INTO explanations (alert_id, ts, actor, model, evidence_digest, doc) VALUES (?, ?, ?, ?, ?, ?)",
                            (alert_id, ts, actor, model, digest, json.dumps(doc)))
        return {"ts": ts, "actor": actor, "model": model, "evidence_digest": digest, "explanation": doc}

    def explanations(self, alert_id: str) -> list[dict[str, Any]]:
        rows = self._rows("SELECT ts, actor, model, evidence_digest, doc FROM explanations WHERE alert_id = ? ORDER BY id",
                          (alert_id,))
        return [{"ts": r[0], "actor": r[1], "model": r[2], "evidence_digest": r[3], "explanation": json.loads(r[4])}
                for r in rows]

    # ---- adaptations and sensors --------------------------------------------------------------

    # ---- response: main-site blocklist (USP 1) ---------------------------------------------------
    def add_block(self, ip: str, *, actor: str, reason: str, ttl_s: int, rule: str | None = None,
                  alert_id: str | None = None) -> dict[str, Any]:
        now = datetime.now(timezone.utc)
        created = now.isoformat(timespec="seconds").replace("+00:00", "Z")
        expires = (now + timedelta(seconds=ttl_s)).isoformat(timespec="seconds").replace("+00:00", "Z")
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO blocklist VALUES (?, ?, ?, ?, ?, ?, ?)",
                            (ip, created, expires, actor, rule, alert_id, reason))
            self.db.execute("INSERT INTO block_history (ts, ip, action, actor, rule, alert_id, reason) "
                            "VALUES (?, ?, 'block', ?, ?, ?, ?)", (created, ip, actor, rule, alert_id, reason))
        return {"ip": ip, "created_at": created, "expires_at": expires, "actor": actor, "rule": rule,
                "alert_id": alert_id, "reason": reason}

    def remove_block(self, ip: str, *, actor: str, reason: str) -> bool:
        with self.lock, self.db:
            gone = self.db.execute("DELETE FROM blocklist WHERE ip = ?", (ip,)).rowcount
            if gone:
                self.db.execute("INSERT INTO block_history (ts, ip, action, actor, reason) VALUES (?, ?, 'unblock', ?, ?)",
                                (now_iso(), ip, actor, reason))
        return bool(gone)

    def active_blocks(self) -> list[dict[str, Any]]:
        stamp = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
        cols = ("ip", "created_at", "expires_at", "actor", "rule", "alert_id", "reason")
        rows = self._rows("SELECT ip, created_at, expires_at, actor, rule, alert_id, reason FROM blocklist "
                          "WHERE expires_at > ? ORDER BY created_at DESC", (stamp,))
        return [dict(zip(cols, r)) for r in rows]

    def is_blocked(self, ip: str) -> bool:
        return any(b["ip"] == ip for b in self.active_blocks())

    def block_history(self, limit: int = 100) -> list[dict[str, Any]]:
        cols = ("ts", "ip", "action", "actor", "rule", "alert_id", "reason")
        rows = self._rows("SELECT ts, ip, action, actor, rule, alert_id, reason FROM block_history ORDER BY id DESC LIMIT ?",
                          (limit,))
        return [dict(zip(cols, r)) for r in rows]

    def put_adaptation(self, record: dict[str, Any]) -> bool:
        with self.lock, self.db:
            cur = self.db.execute("INSERT OR IGNORE INTO adaptations VALUES (?, ?, ?)",
                                  (record["adaptation_id"], record["timestamp"], json.dumps(record)))
        return cur.rowcount == 1

    def adaptations(self, limit: int) -> list[dict[str, Any]]:
        return self._read("SELECT doc FROM adaptations ORDER BY ts DESC LIMIT ?", (limit,))

    def put_sensor(self, sensor_id: str, last_seen: str, doc: dict[str, Any]) -> None:
        with self.lock, self.db:
            self.db.execute("INSERT OR REPLACE INTO sensors VALUES (?, ?, ?)", (sensor_id, last_seen, json.dumps(doc)))

    def sensors(self) -> list[dict[str, Any]]:
        return self._read("SELECT doc FROM sensors ORDER BY sensor_id", ())

    def sensor_event_stats(self, since_5m: str, since_1h: str) -> dict[str, dict[str, Any]]:
        rows = self._rows("SELECT sensor_id, service, max(ts), count(*), sum(ts >= ?), sum(ts >= ?) FROM events "
                          "GROUP BY sensor_id, service", (since_5m, since_1h))
        return {r[0]: {"service": r[1], "last_event_at": r[2], "events_total": r[3], "events_5m": r[4] or 0,
                       "events_1h": r[5] or 0} for r in rows}

    # ---- aggregates ---------------------------------------------------------------------------

    def rows(self, sql: str, args: Iterable[Any] = ()) -> list[tuple[Any, ...]]:
        """Read-only aggregate helper for the API layer. Callers pass fixed SQL and bound values only."""
        return self._rows(sql, args)
