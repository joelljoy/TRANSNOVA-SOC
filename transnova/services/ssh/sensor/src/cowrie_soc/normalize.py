"""Map validated Cowrie events onto the common event record.

Field mapping is based on events observed from Cowrie 3.1.4 in this lab
(tests/fixtures/real_capture_2026-10-31.json) plus Cowrie's documented
file-transfer/forwarding events. Unknown Cowrie event ids are kept as
`cowrie_other` rather than discarded. The original JSON object is preserved
verbatim under `raw.event` together with its SHA-256 and file location.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from cowrie_soc import attack, commands
from cowrie_soc.parser import ParsedEvent
from cowrie_soc.schema import EVENT_SCHEMA_VERSION, RECORD_EVENT, deterministic_id

# cowrie eventid -> (event_type, category, outcome)
EVENT_MAP: dict[str, tuple[str, str, str | None]] = {
    "cowrie.session.connect": ("ssh_connection", "connection", None),
    "cowrie.session.closed": ("session_closed", "connection", None),
    "cowrie.client.version": ("client_version", "client_fingerprint", None),
    "cowrie.client.kex": ("client_kex", "client_fingerprint", None),
    "cowrie.client.fingerprint": ("publickey_offered", "authentication", None),
    "cowrie.client.size": ("terminal_size", "session", None),
    "cowrie.client.var": ("client_env_var", "session", None),
    "cowrie.session.params": ("session_params", "session", None),
    "cowrie.login.failed": ("authentication_failure", "authentication", "failure"),
    "cowrie.login.success": ("authentication_success", "authentication", "success"),
    "cowrie.command.input": ("shell_command", "command", None),
    "cowrie.command.failed": ("shell_command_not_found", "command", "failure"),
    "cowrie.session.file_download": ("file_download", "file_transfer", "success"),
    "cowrie.session.file_download.failed": ("file_download", "file_transfer", "failure"),
    "cowrie.session.file_upload": ("file_upload", "file_transfer", "success"),
    "cowrie.direct-tcpip.request": ("port_forward_request", "network", None),
    "cowrie.direct-tcpip.data": ("port_forward_data", "network", None),
    "cowrie.log.closed": ("tty_log_closed", "session", None),
}

# Cowrie fields promoted to top-level record fields (everything else -> details).
_TOP_LEVEL = {
    "eventid", "timestamp", "session", "src_ip", "src_port", "dst_ip", "dst_port",
    "sensor", "uuid", "protocol", "message", "username", "password", "input",
}
# Very large, low-value fields: kept in raw.event, not copied into details.
_DETAIL_SKIP = {"kexAlgs", "keyAlgs", "encCS", "macCS", "compCS", "langCS", "hasshAlgorithms"}


@dataclass(frozen=True)
class NormalizeConfig:
    sensor_id: str
    include_passwords: bool = True
    max_field_chars: int = 4096
    scenario_id: str | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _clip(value: Any, limit: int, truncated: list[str], name: str) -> Any:
    if isinstance(value, str) and len(value) > limit:
        truncated.append(name)
        return value[:limit]
    return value


def normalize(parsed: ParsedEvent, cfg: NormalizeConfig, ingested_at: str | None = None) -> dict[str, Any]:
    ev = parsed.event
    eventid: str = ev["eventid"]
    event_type, category, outcome = EVENT_MAP.get(eventid, ("cowrie_other", "other", None))
    truncated: list[str] = []
    limit = cfg.max_field_chars

    details: dict[str, Any] = {}
    for key, value in ev.items():
        if key in _TOP_LEVEL or key in _DETAIL_SKIP:
            continue
        details[key] = _clip(value, limit, truncated, f"details.{key}")
    if eventid == "cowrie.client.version":
        details["client_version"] = details.pop("version", None)

    command = ev.get("input") if category == "command" else None
    attack_tags: list[dict[str, str]] = []
    if eventid == "cowrie.command.input" and isinstance(command, str):
        analysis = commands.analyze(command)
        attack_tags = attack.as_dicts(analysis.technique_ids)
        details["command_analysis"] = {
            "programs": [c.program for c in analysis.commands][:50],
            "indicators": [
                {"technique_id": i.technique_id, "reason": i.reason} for i in analysis.indicators
            ][:50],
            "parse_fallback": analysis.parse_fallback,
        }

    record: dict[str, Any] = {
        "record_type": RECORD_EVENT,
        "schema_version": EVENT_SCHEMA_VERSION,
        "event_id": deterministic_id("cowrie-event", parsed.raw_sha256),
        "timestamp": ev["timestamp"],
        "ingested_at": ingested_at or utc_now_iso(),
        "source_service": "ssh",
        "source_product": "cowrie",
        "sensor_id": cfg.sensor_id,
        "source_ip": ev.get("src_ip"),
        "source_port": ev.get("src_port"),
        "dest_ip": ev.get("dst_ip"),
        "dest_port": ev.get("dst_port"),
        "protocol": ev.get("protocol", "ssh"),
        "session_id": ev["session"],
        "event_type": event_type,
        "category": category,
        "outcome": outcome,
        "username": _clip(ev.get("username"), limit, truncated, "username"),
        "password": _clip(ev.get("password"), limit, truncated, "password") if cfg.include_passwords else None,
        "command": _clip(command, limit, truncated, "command"),
        "message": _clip(ev.get("message"), limit, truncated, "message"),
        "attack": attack_tags,
        "details": details,
        "scenario_id": cfg.scenario_id,
        "raw": {
            "format": "cowrie-json",
            "cowrie_eventid": eventid,
            "cowrie_sensor": ev.get("sensor"),
            "sha256": parsed.raw_sha256,
            "ref": {"file": parsed.source, "offset": parsed.offset},
            "event": ev,
        },
    }
    if not cfg.include_passwords and "password" in ev:
        record["raw"]["event"] = {**ev, "password": "[redacted]"}
        if isinstance(record.get("message"), str) and ev["password"]:
            record["message"] = record["message"].replace(str(ev["password"]), "[redacted]")
        record["raw"]["event"]["message"] = record["message"]
        record["raw"]["redacted"] = ["password"]
    if truncated:
        record["truncated_fields"] = truncated
    return record
