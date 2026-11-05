"""Turn an audit record into a canonical event (HANDOFF_FINAL.md §6).

The canonical envelope forbids extra fields, so everything the envelope has no field for
(risk, severity, ATT&CK, classification, raw line) goes in `raw_evidence_redacted`, using the
same `detections[]` shape the web decoy uses (docs/INTEGRATOR_NOTES.md §2).
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from .audit import TABLE_OPERATIONS, AuditRecord
from .classify import Classification, apply_server_tables, classify, outcome_for, redact
from .config import Settings, ip_in
from .risk import Assessment, assess_auth_failure, assess_query, severity_for
from .state import SensorState, SessionProfile, SourceTracker

NAMESPACE = uuid.UUID("7d9c3e52-3a56-4d2a-9c7b-5b1f3d1e4a10")
CAMPAIGN = re.compile(r"^\s*set\s+@campaign_id\s*=\s*'([A-Za-z0-9_-]{1,64})'\s*;?\s*$", re.I)
RETCODE_NAMES = {1044: "ER_DBACCESS_DENIED", 1045: "ER_ACCESS_DENIED", 1064: "ER_PARSE_ERROR",
                 1142: "ER_TABLEACCESS_DENIED", 1143: "ER_COLUMNACCESS_DENIED", 1146: "ER_NO_SUCH_TABLE",
                 1227: "ER_SPECIFIC_ACCESS_DENIED", 1370: "ER_PROCACCESS_DENIED",
                 3024: "ER_QUERY_TIMEOUT", 1969: "ER_STATEMENT_TIMEOUT"}
RULE_IDS = {"sensitive_access": "D-SENS-01", "adaptive_decoy_access": "D-ADAPT-01", "restricted_access": "D-RESTR-01",
            "modification_attempt": "D-MOD-01", "schema_change_attempt": "D-DDL-01", "privilege_attempt": "D-PRIV-01",
            "file_access_attempt": "D-FILE-01", "reconnaissance": "D-RECON-01", "authentication_failed": "D-AUTH-01",
            "data_exploration": "D-DATA-01", "log_injection_attempt": "D-INJ-01", "log_tampering": "D-INJ-02"}
OPTIMIZER_TABLES = {"mysql.table_stats", "mysql.column_stats", "mysql.index_stats"}
ALERT_SEVERITIES = {"MEDIUM", "HIGH", "CRITICAL"}
CONFIDENCE = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high", "CRITICAL": "high"}


def event_id_for(session_id: str, rec: AuditRecord) -> str:
    """Stable across a re-read, so a replay cannot create a second copy at the collector."""
    digest = hashlib.sha256(rec.raw.encode("utf-8", "replace")).hexdigest()
    return str(uuid.uuid5(NAMESPACE, f"{session_id}:{rec.query_id}:{rec.operation}:{digest}"))


class EventBuilder:
    def __init__(self, settings: Settings, rules: dict[str, Any], state: SensorState) -> None:
        self.s, self.rules, self.state = settings, rules, state
        self.opened: dict[int, tuple[int, set[str]]] = {}  # connection id -> (query id, tables)

    def is_internal(self, rec: AuditRecord) -> bool:
        """Our own traffic. A failed login is never internal: it may be someone guessing."""
        if rec.operation == "FAILED_CONNECT":
            return False
        # Accounts only, never a whole host: decoy_user on the local socket is still the decoy.
        return (rec.user, rec.host) in self.s.internal_accounts

    def _envelope(self, rec: AuditRecord, session: SessionProfile, event_type: str, action: str, outcome: str,
                  evidence: dict[str, Any], tags: list[str], **fields: Any) -> dict[str, Any]:
        return {
            "event_id": event_id_for(session.session_id, rec),
            "timestamp": rec.timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "sensor_id": self.s.sensor_id, "service": "database",
            "source_ip": rec.host or "unknown", "source_port": None,
            "destination_service": "database-honeypot", "event_type": event_type, "action": action,
            "outcome": outcome, "username": rec.user or None, "session_id": session.session_id,
            "campaign_id": session.campaign_id, "request_path": None, "http_method": None, "http_status": None,
            "command": None, "query_type": None, "database_name": rec.database or None, "table_names": [],
            "rows_returned": None, "file_name": None, "file_direction": None, "user_agent": None,
            "raw_evidence_redacted": evidence, "tags": tags, **fields,
        }

    def _evidence(self, rec: AuditRecord, category: str, a: Assessment, target: str | None) -> dict[str, Any]:
        detections = []
        if a.severity in ALERT_SEVERITIES and category in RULE_IDS:
            detections.append({
                "rule": RULE_IDS[category], "category": category, "label": f"db:{category}",
                "field": "command", "severity": a.severity, "confidence": CONFIDENCE[a.severity],
                "risk_score": a.risk_score, "rationale": "; ".join(a.reasons),
                "attack": a.mitre,
            })
        return {
            "source": "database-honeypot", "honeypot_type": "database",
            "destination_ip": self.s.destination_ip, "destination_port": self.s.db_port,
            "server_retcode": rec.retcode, "server_error": RETCODE_NAMES.get(rec.retcode),
            "audit_operation": rec.operation, "audit_connection_id": rec.connection_id, "audit_query_id": rec.query_id,
            "raw_event": redact(rec.raw)[: self.s.max_query_chars + 200],
            "classification": category, "severity": a.severity, "risk_score": a.risk_score,
            "attack_stage": a.attack_stage, "risk_reasons": a.reasons, "target_table": target,
            "mitre": a.mitre, "detections": detections,
        }

    def build(self, rec: AuditRecord) -> tuple[dict[str, Any] | None, Classification | None, str]:
        """Returns (event, classification, tracker key). Session close produces a low event too."""
        key = f"{rec.user}@{rec.host}"
        known = self.state.sessions.get(rec.connection_id)
        if rec.operation == "DISCONNECT" and known is not None and not known.open:
            return None, None, key  # the close that follows a failed login is not a new session
        fresh = rec.operation in ("CONNECT", "CHANGEUSER", "FAILED_CONNECT")
        if rec.operation in TABLE_OPERATIONS:
            if self._bound(rec):  # no matching login: a forged line, so it counts for nothing
                self._note_table(rec)
            return None, None, key
        if rec.operation in ("QUERY", "DISCONNECT") and not self._bound(rec):
            return self._unbound(rec), None, key
        session = self.state.session(rec.connection_id, rec.host, rec.user, rec.timestamp, self.s.sensor_id, fresh)
        session.last_seen = rec.timestamp.isoformat()
        tracker = self.state.tracker(key)
        if rec.operation in ("CONNECT", "CHANGEUSER"):
            return self._login_ok(rec, session), None, key
        if rec.operation == "FAILED_CONNECT":
            return self._login_failed(rec, session, key), None, key
        if rec.operation == "DISCONNECT":
            session.open = False
            return self._disconnect(rec, session), None, key
        if rec.operation == "QUERY":
            event, c = self._query(rec, session, tracker)
            return event, c, key
        return None, None, key

    def _note_table(self, rec: AuditRecord) -> None:
        """READ lines precede the QUERY line of the same query id."""
        name = rec.query.lower() if rec.database.lower() == self.rules["database"] \
            else f"{rec.database}.{rec.query}".lower()
        if name in OPTIMIZER_TABLES:
            return  # the server reading its own statistics, not the attacker
        query_id, tables = self.opened.get(rec.connection_id, (None, set()))
        if query_id != rec.query_id:
            tables = set()
        tables.add(name)
        self.opened[rec.connection_id] = (rec.query_id, tables)

    def _bound(self, rec: AuditRecord) -> bool:
        """Every real statement belongs to a connection that logged in as that user and host.
        A line with no such login cannot be trusted: see audit.LineAssembler."""
        known = self.state.sessions.get(rec.connection_id)
        return known is not None and known.open and (known.username, known.source_ip) == (rec.user, rec.host)

    def _unbound(self, rec: AuditRecord) -> dict[str, Any]:
        """Reported as tampering. It updates no profile, so it cannot trigger an adaptive rule."""
        session = SessionProfile(session_id=f"{self.s.sensor_id}-unbound", source_ip="unverified", username="",
                                 connection_id=rec.connection_id, first_seen="", last_seen="")
        base = self.rules["categories"]["log_tampering"]["base"]
        a = Assessment(base, severity_for(base, self.rules), self.rules["categories"]["log_tampering"]["stage"],
                       [f"+{base} audit line has no matching login, so its fields cannot be trusted"])
        return self._envelope(rec, session, "sql_query", "log_tampering", "observed",
                              self._evidence(rec, "log_tampering", a, None), ["db:unbound_audit_line"],
                              command=redact(rec.query)[: self.s.max_query_chars] or None, username=None,
                              source_ip="unverified", database_name=None)

    def _login_ok(self, rec: AuditRecord, session: SessionProfile) -> dict[str, Any]:
        base = self.rules["categories"]["connection"]["base"]
        a = Assessment(base, "LOW", self.rules["categories"]["connection"]["stage"],
                       [f"+{base} successful login to a decoy account"])
        return self._envelope(rec, session, "authentication", "db_login", "succeeded",
                              self._evidence(rec, "connection", a, None), ["db:login_success"])

    def _login_failed(self, rec: AuditRecord, session: SessionProfile, key: str) -> dict[str, Any]:
        # Keyed on the IP alone so that spraying across usernames adds up.
        ip_tracker = self.state.tracker(f"*@{rec.host}")
        window = self.rules["modifiers"]["brute_force"]["window_seconds"]
        now = rec.timestamp.timestamp()
        pairs = [(t, u) for t, u in zip(ip_tracker.failed_logins, ip_tracker.failed_usernames) if now - t <= window]
        pairs.append((now, rec.user))
        ip_tracker.failed_logins = [p[0] for p in pairs]
        ip_tracker.failed_usernames = [p[1] for p in pairs]
        a = assess_auth_failure(ip_tracker, self.rules)
        session.open = False
        category, tags = "authentication_failed", ["db:login_failed"]
        if "\n" in rec.user or "\r" in rec.user:
            base = self.rules["categories"]["log_injection_attempt"]["base"]
            a = Assessment(max(a.risk_score, base), severity_for(max(a.risk_score, base), self.rules),
                           self.rules["categories"]["log_injection_attempt"]["stage"],
                           a.reasons + [f"+{base} login username contains a line break, which forges audit log lines"],
                           a.mitre)
            category, tags = "log_injection_attempt", tags + ["db:log_injection_attempt"]
        session.risk_score = max(session.risk_score, a.risk_score)
        return self._envelope(rec, session, "authentication", "db_login", "failed",
                              self._evidence(rec, category, a, None), tags)

    def _disconnect(self, rec: AuditRecord, session: SessionProfile) -> dict[str, Any]:
        a = Assessment(0, "LOW", None, ["connection closed"])
        return self._envelope(rec, session, "connection", "db_disconnect", "observed",
                              self._evidence(rec, "connection", a, None), [])

    def _query(self, rec: AuditRecord, session: SessionProfile, tracker: SourceTracker) -> tuple[dict[str, Any], Classification]:
        campaign = CAMPAIGN.match(rec.query)
        if campaign and ip_in(rec.host, self.s.simulator_cidrs):
            session.campaign_id = campaign.group(1)
        c = classify(rec.query, rec.retcode, rec.database, self.rules)
        query_id, opened = self.opened.pop(rec.connection_id, (None, set()))
        if query_id == rec.query_id and opened:
            apply_server_tables(c, rec.query, rec.retcode, opened, self.rules)
        outcome = outcome_for(rec.retcode)
        if c.category == "file_access_attempt" and outcome == "succeeded":
            # LOAD_FILE returns NULL with retcode 0 when the account has no FILE privilege.
            outcome, tags_extra = "blocked", ["db:no_file_privilege"]
        else:
            tags_extra = []

        # Update behaviour first, so this statement counts toward its own score.
        if c.category == "reconnaissance":
            tracker.enumeration_count += 1
        if outcome == "blocked":
            tracker.denied_count += 1
            session.restricted_attempts += 1
        if outcome == "succeeded" and c.category in ("data_exploration", "sensitive_access", "adaptive_decoy_access"):
            for table in c.tables:
                tracker.table_hits[table] = tracker.table_hits.get(table, 0) + 1

        a = assess_query(c, outcome, tracker, self.rules)
        if rec.truncated:
            a.reasons.append("audit log truncated this statement at server_audit_query_log_limit")

        session.query_count += 1
        session.categories[c.category] = session.categories.get(c.category, 0) + 1
        session.tables = sorted(set(session.tables) | set(c.tables))
        sensitive = set(self.rules["sensitive_tables"]) | set(self.rules["adaptive_tables"])
        session.sensitive_tables = sorted(set(session.sensitive_tables) | (set(c.tables) & sensitive))
        session.risk_score = max(session.risk_score, a.risk_score)

        tags = [f"db:{c.category}", f"db:{outcome}"] + c.tags + tags_extra
        if rec.truncated:
            tags.append("db:truncated")
        if len(rec.query) > self.s.max_query_chars:
            tags.append("db:command_bounded")  # the full statement stays in the audit log
        target = c.tables[0] if c.tables else None
        event = self._envelope(rec, session, "sql_query", c.category, outcome,
                               self._evidence(rec, c.category, a, target), tags,
                               command=redact(rec.query)[: self.s.max_query_chars], query_type=c.query_type,
                               table_names=c.tables)
        return event, c


def malformed_event(line: str, settings: Settings, offset_hint: str) -> dict[str, Any]:
    """An unparseable line is still evidence: forward it rather than dropping it."""
    digest = hashlib.sha256(f"{offset_hint}:{line}".encode("utf-8", "replace")).hexdigest()
    return {
        "event_id": str(uuid.uuid5(NAMESPACE, digest)),
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "sensor_id": settings.sensor_id, "service": "database", "source_ip": "unknown", "source_port": None,
        "destination_service": "database-honeypot", "event_type": "sql_query", "action": "unparsed_audit_line",
        "outcome": "observed", "username": None, "session_id": None, "campaign_id": None, "request_path": None,
        "http_method": None, "http_status": None, "command": None, "query_type": None, "database_name": None,
        "table_names": [], "rows_returned": None, "file_name": None, "file_direction": None, "user_agent": None,
        "raw_evidence_redacted": {"source": "database-honeypot", "raw_event": redact(line)[:2048],
                                  "classification": "unparsed", "severity": "LOW", "risk_score": 0, "detections": []},
        "tags": ["db:unparsed_audit_line"],
    }
