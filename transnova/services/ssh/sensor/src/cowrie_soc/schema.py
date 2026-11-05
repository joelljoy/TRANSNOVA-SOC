"""Output record contract: normalized events and detection findings.

This is the *proposed* PS04 common-event shape for the SSH sensor, based on the
project handoff (event_id, timestamp, source_service, sensor_id, source_ip,
source_port, session_id, event_type, category, raw_event_ref, details,
scenario_id) plus SSH fields (username, command, ...). The team's final schema
is not decided yet; anything that must change should change in
`cowrie_soc.encoders`, not in the collector core. See docs/integration-contract.md
and docs/schema/*.schema.json.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

EVENT_SCHEMA_VERSION = "ps04.event.v0.1"
FINDING_SCHEMA_VERSION = "ps04.finding.v0.1"

RECORD_EVENT = "event"
RECORD_FINDING = "finding"

SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("low", "medium", "high")

# Namespace for deterministic UUIDv5 identifiers (stable across re-reads).
ID_NAMESPACE = uuid.UUID("6f0c2a52-31a8-4c1e-9d0e-6b8f3f0e2a11")


def deterministic_id(*parts: str) -> str:
    return str(uuid.uuid5(ID_NAMESPACE, "\x1f".join(parts)))


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity)


EVENT_REQUIRED: dict[str, type | tuple[type, ...]] = {
    "record_type": str,
    "schema_version": str,
    "event_id": str,
    "timestamp": str,
    "ingested_at": str,
    "source_service": str,
    "source_product": str,
    "sensor_id": str,
    "session_id": str,
    "event_type": str,
    "category": str,
    "details": dict,
    "attack": list,
    "raw": dict,
}

FINDING_REQUIRED: dict[str, type | tuple[type, ...]] = {
    "record_type": str,
    "schema_version": str,
    "finding_id": str,
    "rule_id": str,
    "rule_name": str,
    "title": str,
    "severity": str,
    "confidence": str,
    "created_at": str,
    "first_seen": str,
    "last_seen": str,
    "source_service": str,
    "sensor_id": str,
    "session_ids": list,
    "attack": list,
    "evidence": dict,
    "explanation": str,
}


def _is_iso_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def validate_record(record: Any) -> list[str]:
    """Return a list of contract violations (empty when the record is valid)."""
    if not isinstance(record, dict):
        return ["record is not a JSON object"]
    rtype = record.get("record_type")
    if rtype == RECORD_EVENT:
        required, version = EVENT_REQUIRED, EVENT_SCHEMA_VERSION
    elif rtype == RECORD_FINDING:
        required, version = FINDING_REQUIRED, FINDING_SCHEMA_VERSION
    else:
        return [f"unknown record_type {rtype!r}"]

    errors: list[str] = []
    for field, ftype in required.items():
        if field not in record:
            errors.append(f"missing field {field!r}")
        elif not isinstance(record[field], ftype):
            errors.append(f"field {field!r} has type {type(record[field]).__name__}")
    if record.get("schema_version") not in (None, version):
        errors.append(f"schema_version {record.get('schema_version')!r} != {version!r}")
    for ts_field in ("timestamp", "ingested_at", "created_at", "first_seen", "last_seen"):
        if ts_field in record and not _is_iso_timestamp(record[ts_field]):
            errors.append(f"field {ts_field!r} is not an ISO-8601 timestamp")
    if rtype == RECORD_FINDING:
        if record.get("severity") not in SEVERITIES:
            errors.append(f"severity {record.get('severity')!r} not in {SEVERITIES}")
        if record.get("confidence") not in CONFIDENCES:
            errors.append(f"confidence {record.get('confidence')!r} not in {CONFIDENCES}")
        evidence = record.get("evidence")
        if isinstance(evidence, dict) and not evidence.get("event_ids"):
            errors.append("finding evidence has no event_ids")
    for tech in record.get("attack") or []:
        if not (isinstance(tech, dict) and {"technique_id", "name", "tactic"} <= tech.keys()):
            errors.append(f"malformed attack entry {tech!r}")
    return errors


def record_id(record: dict[str, Any]) -> str:
    return record["event_id"] if record["record_type"] == RECORD_EVENT else record["finding_id"]
