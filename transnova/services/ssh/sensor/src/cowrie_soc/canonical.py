"""Translate clean SSH records into the shared SOC event format.

The format is `CanonicalEvent` in collector/schema.py. tests/integration checks this module
against that real model, so a schema change fails a test here instead of a live delivery.

Nothing is copied by default. Every output value comes from a fixed table, a strict check or a
cleaning step, and each record is cleaned again here, so an older or tampered stored record
cannot pass raw text through. A record that does not translate cleanly is skipped: it is never
sent, and only a safe identifier and a fixed reason are kept.

Finding titles, explanations and observed values can quote attacker input, so they are never
read. Rule text comes from RULES, and technique details from the sensor's own catalogue.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any

from cowrie_soc import attack
from cowrie_soc.redact import R, redact_line, safe_username, sanitize_event

SERVICE = "ssh"
DESTINATION_SERVICE = "ssh-honeypot"
MAX_COMMAND_CHARS = 2048
MAX_EVIDENCE_BYTES = 8192
MAX_DETECTIONS = 10
MAX_EVIDENCE_IDS = 50
MAX_TEXT_CHARS = 256

FIELDS = (
    "event_id", "timestamp", "sensor_id", "service", "source_ip", "source_port", "destination_service",
    "event_type", "action", "outcome", "username", "session_id", "campaign_id", "request_path", "http_method",
    "http_status", "command", "query_type", "database_name", "table_names", "rows_returned", "file_name",
    "file_direction", "user_agent", "raw_evidence_redacted", "tags",
)
REQUIRED_TEXT = ("event_id", "timestamp", "sensor_id", "service", "source_ip", "destination_service", "event_type",
                 "action", "outcome")
OPTIONAL_TEXT = ("username", "session_id", "command", "file_name", "file_direction")
ALWAYS_NULL = ("campaign_id", "request_path", "http_method", "http_status", "query_type", "database_name",
               "rows_returned", "user_agent")
ALLOWED_SERVICES = ("ssh", "web", "database")
ALLOWED_EVENT_TYPES = ("connection", "authentication", "command", "http_request", "sql_query", "file_transfer")
ALLOWED_OUTCOMES = ("observed", "succeeded", "failed", "blocked", "simulated")

# Fixed reasons: the only text kept about a skipped record.
BAD_RECORD = "bad_record"
BAD_EVENT_ID = "bad_event_id"
BAD_TIMESTAMP = "bad_timestamp"
BAD_SENSOR_ID = "bad_sensor_id"
BAD_SESSION = "bad_session"
BAD_TYPE = "bad_type"
TRANSLATOR_ERROR = "translator_error"
FAILED_VALIDATION = "failed_validation"
OVERSIZED = "oversized"
QUEUE_FULL = "queue_full"

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_SESSION = re.compile(r"^[0-9a-f]{1,32}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_LOG_FILE = re.compile(r"^cowrie\.json(?:\.[A-Za-z0-9_.\-]{1,32})?$")
_NO_ADDRESS = re.compile(r"^unknown-ssh-[0-9a-f]{1,32}$")
_KEPT_ENV_NAME = re.compile(r"^(?:LANG|LC_[A-Z]+|TERM)$")

# Outcomes follow what the Cowrie source proves; docs/canonical-mapping.md has the evidence.
# Upload and download events do not prove a stored or completed transfer, so they stay "observed".
EVENTS: dict[str, tuple[str, str, str]] = {
    "cowrie.session.connect": ("connection", "ssh_connect", "observed"),
    "cowrie.session.closed": ("connection", "ssh_disconnect", "observed"),
    "cowrie.client.version": ("connection", "ssh_client_version", "observed"),
    "cowrie.client.kex": ("connection", "ssh_client_kex", "observed"),
    "cowrie.client.size": ("connection", "ssh_terminal_size", "observed"),
    "cowrie.client.var": ("connection", "ssh_client_env", "observed"),
    "cowrie.session.params": ("connection", "ssh_session_params", "observed"),
    "cowrie.client.fingerprint": ("authentication", "ssh_publickey_offered", "observed"),
    "cowrie.login.failed": ("authentication", "ssh_login", "failed"),
    "cowrie.login.success": ("authentication", "ssh_login", "succeeded"),
    "cowrie.command.input": ("command", "shell_command", "observed"),
    "cowrie.command.failed": ("command", "shell_command_not_found", "failed"),
    "cowrie.command.success": ("command", "typed_input_hidden", "observed"),
    "cowrie.session.input": ("command", "typed_input_hidden", "observed"),
    "cowrie.command.chpasswd": ("command", "password_change_attempt", "observed"),
    "cowrie.session.file_download": ("file_transfer", "file_download", "observed"),
    "cowrie.session.file_download.failed": ("file_transfer", "file_download", "failed"),
    "cowrie.session.file_upload": ("file_transfer", "file_upload", "observed"),
}
OTHER_EVENT = ("connection", "cowrie_other", "observed")
CAPTURED_INPUT_ACTION = "input_captured"
_SHOWS_COMMAND = ("cowrie.command.input", "cowrie.command.failed")
_DETAIL_FIELDS: dict[str, tuple[str, ...]] = {
    "cowrie.session.closed": ("duration_ms",),
    "cowrie.client.version": ("version",),
    "cowrie.client.kex": ("hassh",),
    "cowrie.client.size": ("width", "height"),
    "cowrie.client.var": ("name", "value"),
    "cowrie.session.params": ("arch",),
    "cowrie.client.fingerprint": ("fingerprint", "type"),
    "cowrie.login.failed": ("fingerprint", "type"),
    "cowrie.login.success": ("fingerprint", "type"),
    "cowrie.session.file_download": ("url", "shasum", "outfile", "duplicate"),
    "cowrie.session.file_download.failed": ("url",),
    "cowrie.session.file_upload": ("url", "shasum", "outfile", "duplicate"),
}

# rule id -> (category, attack stage, rationale). Fixed text only.
RULES: dict[str, tuple[str, str, str]] = {
    "SSH-BRUTE-001": ("behavior_detected", "credential_access", "Repeated failed SSH logins from one source."),
    "SSH-AUTH-002": ("decoy_interaction", "initial_access", "A login to a decoy SSH account succeeded."),
    "SSH-EXEC-001": ("decoy_interaction", "execution", "Commands ran in the emulated shell."),
    "SSH-DISC-001": ("behavior_detected", "discovery", "Several discovery techniques in one SSH session."),
    "SSH-CRED-001": ("decoy_interaction", "credential_access", "A credential file or honeytoken was read."),
    "SSH-TOOL-001": ("probe_detected", "command_and_control", "A remote file download was attempted."),
    "SSH-SEQ-001": ("behavior_detected", "execution", "A download, chmod and execute sequence ran in one session."),
    "SSH-EVADE-001": ("behavior_detected", "defense_evasion", "Shell history was cleared or disabled."),
}
_ATTEMPT_ONLY = {"T1105"}  # Cowrie's outbound connections are confined, so a transfer is not proven
_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
_CONFIDENCES = ("low", "medium", "high")


class Skip(Exception):
    """A record that must not be delivered. `reason` is one of the fixed reasons above."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def safe_id(record: Any, raw_sha256: str | None = None) -> str:
    """Identify a skipped record without keeping anything it contains."""
    event_id = record.get("event_id") if isinstance(record, dict) else None
    if isinstance(event_id, str) and _UUID.fullmatch(event_id):
        return event_id
    if isinstance(raw_sha256, str) and _HASH.fullmatch(raw_sha256):
        return f"sha256:{raw_sha256}"
    return "unidentified"


def source_address(value: Any, session_id: str) -> str:
    """The real address, or a label unique to this session.

    The collector groups and correlates on this exact string, and the database sensor already
    sends "unknown". Sharing that word would link unrelated events, so it is never used.
    """
    try:
        if isinstance(value, str):
            return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    return f"unknown-ssh-{session_id}"


def _attack_entry(technique_id: Any, confidence: str) -> dict[str, str] | None:
    technique = attack.TECHNIQUES.get(technique_id) if isinstance(technique_id, str) else None
    if technique is None:
        return None
    attempted = technique.technique_id in _ATTEMPT_ONLY
    return {
        "technique": technique.technique_id,
        "name": technique.name,
        "tactic": technique.tactic.replace("-", " ").title(),
        "status": "attempted" if attempted else "observed",
        "confidence": "low" if attempted else confidence,
        "rationale": "Attempt observed; no evidence of a completed transfer." if attempted
        else "Mapped from the matching SSH detection rule.",
    }


def _detection(finding: Any) -> dict[str, Any] | None:
    """Rule, severity and technique IDs are read and checked. No finding text is read."""
    if not isinstance(finding, dict):
        return None
    rule = finding.get("rule_id")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    finding_id = finding.get("finding_id")
    if (rule not in RULES or severity not in _SEVERITY_ORDER or confidence not in _CONFIDENCES
            or not isinstance(finding_id, str) or not _UUID.fullmatch(finding_id)):
        return None
    category, _stage, rationale = RULES[rule]
    evidence = finding.get("evidence")
    event_ids = evidence.get("event_ids") if isinstance(evidence, dict) else None
    entries = (_attack_entry(a.get("technique_id"), confidence) for a in finding.get("attack") or [] if isinstance(a, dict))
    return {
        "rule": rule,
        "category": category,
        "label": f"ssh:{rule}",
        "finding_id": finding_id,
        "severity": severity,
        "confidence": confidence,
        "rationale": rationale,
        "attack": [e for e in entries if e is not None],
        "evidence_event_ids": [e for e in (event_ids or []) if isinstance(e, str) and _UUID.fullmatch(e)][:MAX_EVIDENCE_IDS],
    }


def _details(eventid: str, clean: dict[str, Any]) -> dict[str, Any]:
    return {key: clean[key] for key in _DETAIL_FIELDS.get(eventid, ()) if key in clean}


def _evidence(record: dict[str, Any], eventid: str, clean: dict[str, Any], detections: list[dict[str, Any]]) -> dict[str, Any]:
    raw = record.get("raw")
    raw = raw if isinstance(raw, dict) else {}
    ref = raw.get("ref") if isinstance(raw.get("ref"), dict) else {}
    sha256 = raw.get("sha256")
    file_name = ref.get("file")
    offset = ref.get("offset")
    evidence: dict[str, Any] = {
        "source": DESTINATION_SERVICE,
        "honeypot_type": SERVICE,
        "source_product": "cowrie",
        "native_event": eventid if eventid in EVENTS else "cowrie_other",
        "destination_ip": clean.get("dst_ip"),
        "destination_port": clean.get("dst_port"),
        "protocol": clean.get("protocol"),
        "details": _details(eventid, clean),
        "raw": {
            "format": "cowrie-json",
            "sha256": sha256 if isinstance(sha256, str) and _HASH.fullmatch(sha256) else None,
            "ref": {"file": file_name if isinstance(file_name, str) and _LOG_FILE.fullmatch(file_name) else None,
                    "offset": offset if isinstance(offset, int) and not isinstance(offset, bool) else None},
            "event": clean,
        },
        "mitre": [e for e in (_attack_entry(a.get("technique_id"), "medium") for a in record.get("attack") or []
                              if isinstance(a, dict)) if e is not None],
        "detections": detections,
    }
    if detections:
        top = max(detections, key=lambda d: _SEVERITY_ORDER[d["severity"]])
        evidence["severity"] = top["severity"].upper()
        evidence["attack_stage"] = RULES[top["rule"]][1]
    return evidence


def _fit(evidence: dict[str, Any], tags: list[str]) -> dict[str, Any]:
    if len(json.dumps(evidence)) <= MAX_EVIDENCE_BYTES:
        return evidence
    tags.append("ssh:evidence_trimmed")
    evidence["raw"]["event"] = {}
    if len(json.dumps(evidence)) > MAX_EVIDENCE_BYTES:
        evidence["details"] = {}
    if len(json.dumps(evidence)) > MAX_EVIDENCE_BYTES:
        raise Skip(OVERSIZED)
    return evidence


def translate(record: Any, sensor_id: str, findings: Any = (), session_username: str | None = None) -> dict[str, Any]:
    """Build one canonical event, or raise Skip."""
    if not isinstance(record, dict) or record.get("record_type") != "event":
        raise Skip(BAD_RECORD)
    event_id = record.get("event_id")
    if not isinstance(event_id, str) or not _UUID.fullmatch(event_id):
        raise Skip(BAD_EVENT_ID)
    if record.get("sensor_id") != sensor_id:
        raise Skip(BAD_SENSOR_ID)
    timestamp = record.get("timestamp")
    if not _valid_timestamp(timestamp):
        raise Skip(BAD_TIMESTAMP)
    session_id = record.get("session_id")
    if not isinstance(session_id, str) or not _SESSION.fullmatch(session_id):
        raise Skip(BAD_SESSION)
    raw = record.get("raw")
    if not isinstance(raw, dict) or not isinstance(raw.get("event"), dict):
        raise Skip(BAD_RECORD)

    clean = sanitize_event(raw["event"])
    eventid = clean.get("eventid")
    if eventid == "cowrie.client.var" and not (isinstance(clean.get("name"), str) and _KEPT_ENV_NAME.fullmatch(clean["name"])):
        clean = {**clean, "name": R, "value": R}  # an attacker can choose the variable name too
    event_type, action, outcome = EVENTS.get(eventid, OTHER_EVENT)
    is_download = eventid == "cowrie.session.file_download"
    if is_download and "url" not in clean and "shasum" not in clean:
        action = CAPTURED_INPUT_ACTION

    tags = [f"ssh:{action}"]
    username = safe_username(clean["username"]) if isinstance(clean.get("username"), str) else None
    if username is None and session_username is not None:
        username = safe_username(session_username)
        tags.append("ssh:username_from_session")

    command = None
    if eventid in _SHOWS_COMMAND and clean.get("input") != R:
        command = redact_line(clean.get("input"))[:MAX_COMMAND_CHARS]
        tags.append("ssh:emulated")
    if action == "typed_input_hidden":
        tags.append("ssh:emulated")

    file_name = None
    file_direction = None
    if action in ("file_download", "file_upload"):
        name = clean.get("filename") or clean.get("destfile")
        file_name = name if isinstance(name, str) and name else None
        file_direction = "upload" if action == "file_upload" else "download"

    port = record.get("source_port")
    detections = [d for d in map(_detection, list(findings)[:MAX_DETECTIONS]) if d is not None]
    event = {
        "event_id": event_id,
        "timestamp": timestamp,
        "sensor_id": sensor_id,
        "service": SERVICE,
        "source_ip": source_address(record.get("source_ip"), session_id),
        "source_port": port if isinstance(port, int) and not isinstance(port, bool) and 0 <= port <= 65535 else None,
        "destination_service": DESTINATION_SERVICE,
        "event_type": event_type,
        "action": action,
        "outcome": outcome,
        "username": username,
        "session_id": session_id,
        "campaign_id": None,
        "request_path": None,
        "http_method": None,
        "http_status": None,
        "command": command,
        "query_type": None,
        "database_name": None,
        "table_names": [],
        "rows_returned": None,
        "file_name": file_name,
        "file_direction": file_direction,
        "user_agent": None,
        "raw_evidence_redacted": _fit(_evidence(record, eventid, clean, detections), tags),
        "tags": tags,
    }
    if validate(event, sensor_id) is not None:
        raise Skip(FAILED_VALIDATION)
    return event


def _valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate(event: Any, sensor_id: str) -> str | None:
    """Return None if the event may be sent, otherwise the name of the first problem.

    Stricter than the collector, which accepts things like an empty event_id or a port of
    "22". tests/integration proves this rejects everything the collector rejects.
    """
    if not isinstance(event, dict) or tuple(sorted(event)) != tuple(sorted(FIELDS)):
        return "fields"
    for name in REQUIRED_TEXT:
        if not isinstance(event[name], str) or not event[name]:
            return name
    for name in OPTIONAL_TEXT:
        if event[name] is not None and not isinstance(event[name], str):
            return name
    for name in ALWAYS_NULL:
        if event[name] is not None:
            return name
    if not _UUID.fullmatch(event["event_id"]):
        return "event_id"
    if not _valid_timestamp(event["timestamp"]):
        return "timestamp"
    if event["sensor_id"] != sensor_id:
        return "sensor_id"
    if event["service"] != SERVICE:
        return "service"
    if event["event_type"] not in ALLOWED_EVENT_TYPES:
        return "event_type"
    if event["outcome"] not in ALLOWED_OUTCOMES:
        return "outcome"
    if event["destination_service"] != DESTINATION_SERVICE:
        return "destination_service"
    source = event["source_ip"]
    if not _NO_ADDRESS.fullmatch(source):
        try:
            ipaddress.ip_address(source)
        except ValueError:
            return "source_ip"
    port = event["source_port"]
    if port is not None and (type(port) is not int or not 0 <= port <= 65535):
        return "source_port"
    if event["session_id"] is None or not _SESSION.fullmatch(event["session_id"]):
        return "session_id"
    if event["command"] is not None and len(event["command"]) > MAX_COMMAND_CHARS:
        return "command"
    for name in ("username", "file_name", "file_direction"):
        if event[name] is not None and len(event[name]) > MAX_TEXT_CHARS:
            return name
    if type(event["table_names"]) is not list or event["table_names"]:
        return "table_names"
    tags = event["tags"]
    if type(tags) is not list or not all(type(t) is str and t.startswith("ssh:") for t in tags):
        return "tags"
    evidence = event["raw_evidence_redacted"]
    if type(evidence) is not dict or not all(type(k) is str for k in evidence):
        return "raw_evidence_redacted"
    try:
        if len(json.dumps(evidence)) > MAX_EVIDENCE_BYTES:
            return "raw_evidence_redacted"
    except (TypeError, ValueError):
        return "raw_evidence_redacted"
    return None
