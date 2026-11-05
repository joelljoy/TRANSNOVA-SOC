"""Durable sensor state in one SQLite file: log position, per-source behaviour, per-session
profiles and the reveal audit trail. It survives restarts, so a sensor restart neither
re-reports old lines nor forgets what a source has already done.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from .tailer import Position


@dataclass
class SourceTracker:
    """Behaviour of one (username, source IP) across sessions. Adaptive rules read this."""
    key: str
    table_hits: dict[str, int] = field(default_factory=dict)
    enumeration_count: int = 0
    denied_count: int = 0
    failed_logins: list[float] = field(default_factory=list)      # epoch seconds, pruned to the window
    failed_usernames: list[str] = field(default_factory=list)
    rules_fired: list[str] = field(default_factory=list)

    @property
    def distinct_tables(self) -> int:
        return len(self.table_hits)


@dataclass
class SessionProfile:
    session_id: str
    source_ip: str
    username: str
    connection_id: int
    first_seen: str
    last_seen: str
    query_count: int = 0
    tables: list[str] = field(default_factory=list)
    sensitive_tables: list[str] = field(default_factory=list)
    restricted_attempts: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    reveal_rules: list[str] = field(default_factory=list)
    risk_score: int = 0
    campaign_id: str | None = None
    open: bool = True


class SensorState:
    def __init__(self, data_dir: str) -> None:
        Path(data_dir).mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(Path(data_dir) / "sensor-state.db")
        self.db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS trackers (key TEXT PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS sessions (conn INTEGER PRIMARY KEY, doc TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS reveals (
                adaptation_id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, tracker_key TEXT NOT NULL,
                asset TEXT NOT NULL, status TEXT NOT NULL, doc TEXT NOT NULL);
        """)
        self.trackers: dict[str, SourceTracker] = {}
        self.sessions: dict[int, SessionProfile] = {}
        for key, doc in self.db.execute("SELECT key, doc FROM trackers"):
            self.trackers[key] = SourceTracker(**json.loads(doc))
        for conn, doc in self.db.execute("SELECT conn, doc FROM sessions"):
            self.sessions[conn] = SessionProfile(**json.loads(doc))
        self.dirty_trackers: set[str] = set()
        self.dirty_sessions: set[int] = set()

    def load_position(self) -> Position:
        row = self.db.execute("SELECT v FROM kv WHERE k='position'").fetchone()
        return Position(**json.loads(row[0])) if row else Position()

    def tracker(self, key: str) -> SourceTracker:
        self.dirty_trackers.add(key)
        return self.trackers.setdefault(key, SourceTracker(key=key))

    def session(self, connection_id: int, source_ip: str, username: str, when: datetime, sensor_id: str,
                fresh: bool = False) -> SessionProfile:
        """A connection id repeats after a server restart, so the session id also carries the
        time it was first seen, and a new CONNECT always starts a new session."""
        self.dirty_sessions.add(connection_id)
        found = self.sessions.get(connection_id)
        if fresh or found is None or found.source_ip != source_ip:
            stamp = when.strftime("%Y%m%d%H%M%S")
            found = SessionProfile(session_id=f"{sensor_id}-{stamp}-{connection_id}", source_ip=source_ip,
                                   username=username, connection_id=connection_id,
                                   first_seen=when.isoformat(), last_seen=when.isoformat())
            self.sessions[connection_id] = found
        return found

    def commit(self, position: Position) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO kv VALUES ('position', ?)", (json.dumps(asdict(position)),))
            for key in self.dirty_trackers:
                self.db.execute("INSERT OR REPLACE INTO trackers VALUES (?, ?)",
                                (key, json.dumps(asdict(self.trackers[key]))))
            for conn in self.dirty_sessions:
                self.db.execute("INSERT OR REPLACE INTO sessions VALUES (?, ?)",
                                (conn, json.dumps(asdict(self.sessions[conn]))))
        self.dirty_trackers.clear()
        self.dirty_sessions.clear()

    def record_reveal(self, doc: dict[str, Any]) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO reveals VALUES (?, ?, ?, ?, ?, ?)",
                            (doc["adaptation_id"], doc["rule_id"], doc["tracker_key"], doc["asset_revealed"],
                             doc["status"], json.dumps(doc)))

    def revealed_assets(self) -> set[str]:
        return {row[0] for row in self.db.execute("SELECT asset FROM reveals WHERE status IN ('applied','already_present')")}

    def reset_deception(self) -> None:
        with self.db:
            self.db.execute("DELETE FROM reveals")
            self.db.execute("DELETE FROM trackers")
            self.db.execute("DELETE FROM sessions")
        self.trackers.clear()
        self.sessions.clear()
