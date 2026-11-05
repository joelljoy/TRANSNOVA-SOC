"""READ-ONLY copy of the canonical event envelope (HANDOFF_FINAL.md §6).

The integrator owns the schema. Do not add or rename fields here; when
`collector/schema.py` is published, Phase 5 replaces this module with it.
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
