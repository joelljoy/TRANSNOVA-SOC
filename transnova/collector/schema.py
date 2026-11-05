"""Canonical models (HANDOFF_FINAL.md §6).

CanonicalEvent is field-for-field the envelope the web decoy already emits. Adaptation records
are a separate model on purpose: they describe what WE changed, so they must never be mistaken
for attacker activity.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

Service = Literal["ssh", "web", "database"]
EventType = Literal["connection", "authentication", "command", "http_request", "sql_query", "file_transfer"]
Outcome = Literal["observed", "succeeded", "failed", "blocked", "simulated"]


class CanonicalEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    timestamp: datetime
    sensor_id: str
    service: Service
    source_ip: str
    source_port: int | None = None
    destination_service: str
    event_type: EventType
    action: str
    outcome: Outcome
    username: str | None = None
    session_id: str | None = None
    campaign_id: str | None = None
    request_path: str | None = None
    http_method: str | None = None
    http_status: int | None = None
    command: str | None = None
    query_type: str | None = None
    database_name: str | None = None
    table_names: list[str] = Field(default_factory=list)
    rows_returned: int | None = None
    file_name: str | None = None
    file_direction: str | None = None
    user_agent: str | None = None
    raw_evidence_redacted: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def _must_be_utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None or v.utcoffset() != timezone.utc.utcoffset(None):
            raise ValueError("timestamp must be timezone-aware UTC")
        return v

    @field_serializer("timestamp")
    def _rfc3339(self, v: datetime) -> str:
        return v.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ConsoleEvent(CanonicalEvent):
    """The SOC console's own authentication audit trail, in the same envelope as decoy events.

    Kept out of Service on purpose: /api/events validates CanonicalEvent, so no sender on the
    ingest network can claim to be the console. Only collector/console_api.py builds these, for
    a caller holding the console token.
    """

    service: Literal["soc"]
    sensor_id: Literal["soc-auth"]
    destination_service: Literal["soc-console"]
    event_type: Literal["authentication"]


class AdaptationRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    adaptation_id: str
    timestamp: str
    sensor_id: str
    service: Service
    rule_id: str
    stage: int
    trigger_event_id: str
    trigger_session_id: str | None = None
    trigger_reason: str
    adaptation_type: str
    asset_revealed: str
    source_ip: str
    tracker_key: str
    target_account: str
    privilege_before: bool | None = None
    privilege_after: bool | None = None
    statement: str | None = None
    status: Literal["applied", "already_present", "failed"]
    error: str | None = None


class Heartbeat(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sensor_id: str
    service: Service
    status: Literal["ok", "degraded"]
    details: dict[str, Any] = Field(default_factory=dict)
