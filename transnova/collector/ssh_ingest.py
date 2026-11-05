"""Who may speak for the SSH honeypot.

Web and Database senders have no credentials yet, so anything they send is accepted as today. A
caller could otherwise forge SSH activity, and even a critical SSH alert from a `service: web`
event, so every field that claims SSH identity is protected, not only `service`.

Markers are read from raw JSON, before schema validation, so a malformed request cannot skip them.
They are compared after Unicode normalization, removing punctuation and ignoring case. That catches
`SSH-01`, `ssh_01` and hidden zero-width characters, but not look-alike letters from other alphabets.

`source_ip` is deliberately not a marker. The Database sensor copies it from an audit line an
attacker can forge, and a refusal would block that sender's queue forever. detections._correlate
handles that label instead.

Strict checks repeat the sensor's own rules on purpose: the collector does not rely on the sensor
being correct. A failed batch is refused whole. Responses hold fixed text, never input values.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import unicodedata
from datetime import datetime
from typing import Any

from fastapi import HTTPException

from . import read_auth
from .auth import bearer, load_token, same
from .guards import note_refusal
from .schema import CanonicalEvent

SENSOR_ID = "ssh-01"
SERVICE = "ssh"
DESTINATION_SERVICE = "ssh-honeypot"
MAX_EVIDENCE_BYTES = 8192
MAX_EVIDENCE_DEPTH = 16
MAX_COMMAND_CHARS = 2048
MAX_TEXT_CHARS = 256
MAX_TAGS = 16
MAX_DETECTIONS = 10
MAX_ATTACK_ITEMS = 10
MAX_EVIDENCE_IDS = 50

RULES = ("SSH-BRUTE-001", "SSH-AUTH-002", "SSH-EXEC-001", "SSH-DISC-001", "SSH-CRED-001", "SSH-TOOL-001", "SSH-SEQ-001",
         "SSH-EVADE-001")
_CATEGORIES = ("behavior_detected", "decoy_interaction", "probe_detected")
_SEVERITIES = ("low", "medium", "high", "critical")
_CONFIDENCES = ("low", "medium", "high")
_DETECTION_KEYS = {"rule", "category", "label", "finding_id", "severity", "confidence", "rationale", "attack",
                   "evidence_event_ids"}
_ATTACK_KEYS = {"technique", "name", "tactic", "status", "confidence", "rationale"}
_NULL_FIELDS = ("campaign_id", "request_path", "http_method", "http_status", "query_type", "database_name",
                "rows_returned", "user_agent")
_TEXT_FIELDS = ("username", "file_name", "file_direction")
_FIELDS = set(CanonicalEvent.model_fields)
_FORBIDDEN_KEYS = {"password", "message", "format", "ttylog"}
_ALLOWED_PATH = ("raw", "format")  # the record format label, which holds no attacker text
_RAW_FORMAT = "cowrie-json"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z")
_SESSION = re.compile(r"[0-9a-f]{1,32}")

NOT_AUTHORIZED = "not authorized"
FORBIDDEN = "not allowed for this sender"
UNAVAILABLE = "ssh ingestion unavailable"
REJECTED = "ssh batch rejected"


def _plain(value: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKC", value).casefold() if c.isalnum())


def _starts_ssh(value: Any) -> bool:
    return isinstance(value, str) and _plain(value).startswith("ssh")


def _ssh_sensor(value: Any) -> bool:
    return isinstance(value, str) and _plain(value).startswith(("ssh", "cowrie"))


def _ssh_rule(value: Any) -> bool:
    """detections.py stores str(rule), so a list or object holding an SSH rule counts as one."""
    text = _plain(str(value))
    return text.startswith("ssh") or (not isinstance(value, str) and "ssh" in text)


def _claims_ssh(item: Any) -> bool:
    if not isinstance(item, dict):
        return False
    destination = item.get("destination_service")
    if _starts_ssh(item.get("service")) or _ssh_sensor(item.get("sensor_id")):
        return True
    if isinstance(destination, str) and "sshhoneypot" in _plain(destination):
        return True
    tags = item.get("tags")
    if isinstance(tags, list) and any(_starts_ssh(tag) for tag in tags):
        return True
    evidence = item.get("raw_evidence_redacted")
    detections = evidence.get("detections") if isinstance(evidence, dict) else None
    return isinstance(detections, list) and any(
        isinstance(d, dict) and (("rule" in d and _ssh_rule(d["rule"])) or _starts_ssh(d.get("label")))
        for d in detections)


def _claims_ssh_status(item: Any) -> bool:
    return isinstance(item, dict) and (_starts_ssh(item.get("service")) or _ssh_sensor(item.get("sensor_id")))


def _claims_ssh_adaptation(item: Any) -> bool:
    return _claims_ssh_status(item) or (isinstance(item, dict) and _starts_ssh(item.get("rule_id")))


def _refuse(status: int, detail: str, reason: str) -> HTTPException:
    note_refusal(reason)
    return HTTPException(status_code=status, detail=detail)


def _sender_is_ssh(headers: list[tuple[bytes, bytes]], peer: str | None, claimed: bool) -> bool:
    """True for the real SSH sensor. A request with no claim and no header never reads the token
    file, so a broken SSH secret cannot touch Web or Database traffic."""
    presented = any(name == b"authorization" for name, _ in headers)
    if not claimed and not presented:
        return False
    token = load_token(os.environ.get("SSH_INGEST_TOKEN_FILE"))
    read_token = read_auth.token()
    if token is None or read_token is None or same(token, read_token):
        # No SSH data while reads are open, and a read token must never be able to write.
        if claimed:
            raise _refuse(503, UNAVAILABLE, "ssh token or read token unavailable")
        return False
    valid = same(bearer(headers), token)
    locked_to = os.environ.get("SSH_SENSOR_PEER")
    if valid and locked_to and peer != locked_to:
        valid = False
    if claimed and not valid:
        raise _refuse(401, NOT_AUTHORIZED, "ssh claim without a valid token")
    return valid


def admit_events(items: list[Any], headers: list[tuple[bytes, bytes]], peer: str | None) -> bool:
    """Decide before schema validation, so an unauthenticated caller learns nothing about fields."""
    claims = [_claims_ssh(item) for item in items]
    is_ssh = _sender_is_ssh(headers, peer, any(claims))
    if is_ssh and not all(claims):
        raise _refuse(403, FORBIDDEN, "ssh token used for another service")
    return is_ssh


def admit_heartbeat(body: Any, headers: list[tuple[bytes, bytes]], peer: str | None) -> bool:
    claimed = _claims_ssh_status(body)
    is_ssh = _sender_is_ssh(headers, peer, claimed)
    if is_ssh and not claimed:
        raise _refuse(403, FORBIDDEN, "ssh token used for another service")
    return is_ssh


def admit_adaptations(items: list[Any], headers: list[tuple[bytes, bytes]], peer: str | None) -> None:
    """SSH has no adaptive deception, so these are refused even with a valid token."""
    if any(_claims_ssh_adaptation(item) for item in items):
        raise _refuse(403, FORBIDDEN, "ssh adaptation claim")
    if _sender_is_ssh(headers, peer, False):
        raise _refuse(403, FORBIDDEN, "ssh token used for adaptations")


def _text(value: Any, limit: int = MAX_TEXT_CHARS) -> bool:
    return value is None or (type(value) is str and len(value) <= limit)


def _uuid(value: Any) -> bool:
    return type(value) is str and _UUID.fullmatch(value) is not None


def _clean_keys(value: Any) -> bool:
    """No sensitive key at any depth. Iterative, because evidence nesting is attacker-reachable."""
    stack: list[tuple[Any, tuple[str, ...]]] = [(value, ())]
    while stack:
        node, path = stack.pop()
        if len(path) > MAX_EVIDENCE_DEPTH:  # storage cannot serialize very deep values on every Python
            return False
        if isinstance(node, dict):
            for key, child in node.items():
                here = (*path, key)
                if type(key) is not str:
                    return False
                if _plain(key) in _FORBIDDEN_KEYS and here != _ALLOWED_PATH:
                    return False
                stack.append((child, here))
        elif isinstance(node, list):
            stack.extend((child, (*path, "[]")) for child in node)
    return True


def _small_json(value: Any) -> bool:
    try:
        return len(json.dumps(value)) <= MAX_EVIDENCE_BYTES
    except (TypeError, ValueError, RecursionError):
        return False


def _valid_detection(item: Any) -> bool:
    if type(item) is not dict or not set(item) <= _DETECTION_KEYS or not _DETECTION_KEYS - {"attack", "evidence_event_ids"} <= set(item):
        return False
    rule = item["rule"]
    if rule not in RULES or item["label"] != f"ssh:{rule}" or item["category"] not in _CATEGORIES:
        return False
    if item["severity"] not in _SEVERITIES or item["confidence"] not in _CONFIDENCES or not _uuid(item["finding_id"]):
        return False
    if type(item["rationale"]) is not str or len(item["rationale"]) > MAX_TEXT_CHARS:
        return False
    attack, ids = item.get("attack", []), item.get("evidence_event_ids", [])
    if type(attack) is not list or len(attack) > MAX_ATTACK_ITEMS or type(ids) is not list or len(ids) > MAX_EVIDENCE_IDS:
        return False
    return all(_uuid(i) for i in ids) and all(
        type(a) is dict and set(a) <= _ATTACK_KEYS and all(type(v) is str and len(v) <= MAX_TEXT_CHARS for v in a.values())
        for a in attack)


def _valid_evidence(evidence: Any) -> bool:
    if type(evidence) is not dict or not _small_json(evidence) or not _clean_keys(evidence):
        return False
    if evidence.get("honeypot_type") != SERVICE or evidence.get("source") != DESTINATION_SERVICE:
        return False
    raw = evidence.get("raw")
    if type(raw) is not dict or raw.get("format") != _RAW_FORMAT:
        return False
    detections = evidence.get("detections", [])
    return type(detections) is list and len(detections) <= MAX_DETECTIONS and all(map(_valid_detection, detections))


def _valid_source(source: Any, session: str) -> bool:
    if type(source) is not str:
        return False
    if source == f"unknown-ssh-{session}":
        return True
    try:
        ipaddress.ip_address(source)
    except ValueError:
        return False
    return True


def _valid_timestamp(value: Any) -> bool:
    if type(value) is not str or not _TIMESTAMP.fullmatch(value):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _valid_event(item: Any) -> bool:
    if type(item) is not dict or set(item) != _FIELDS:
        return False
    session, port, tags = item["session_id"], item["source_port"], item["tags"]
    return (
        item["sensor_id"] == SENSOR_ID and item["service"] == SERVICE and item["destination_service"] == DESTINATION_SERVICE
        and _uuid(item["event_id"]) and _valid_timestamp(item["timestamp"])
        and type(session) is str and _SESSION.fullmatch(session) is not None
        and _valid_source(item["source_ip"], session)
        and (port is None or (type(port) is int and 0 <= port <= 65535))
        and all(item[name] is None for name in _NULL_FIELDS)
        and item["table_names"] == [] and type(item["table_names"]) is list
        and _text(item["command"], MAX_COMMAND_CHARS) and all(_text(item[name]) for name in _TEXT_FIELDS)
        and type(tags) is list and len(tags) <= MAX_TAGS
        and all(type(tag) is str and tag.startswith("ssh:") and len(tag) <= MAX_TEXT_CHARS for tag in tags)
        and _valid_evidence(item["raw_evidence_redacted"])
    )


def check_events(items: list[Any]) -> None:
    if not all(map(_valid_event, items)):
        raise _refuse(422, REJECTED, "ssh batch failed strict checks")


def check_heartbeat(body: Any) -> None:
    valid = (type(body) is dict and body.get("sensor_id") == SENSOR_ID and body.get("service") == SERVICE
             and _small_json(body) and _clean_keys(body))
    if not valid:
        raise _refuse(422, REJECTED, "ssh heartbeat failed strict checks")
