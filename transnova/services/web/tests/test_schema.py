"""Phase 3: every emitted event matches the canonical envelope (HANDOFF §6)."""

import uuid
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from web_decoy.telemetry.schema import CanonicalEvent
from .conftest import GOOD_PASS, GOOD_USER, read_events

HANDOFF_FIELDS = {
    "event_id", "timestamp", "sensor_id", "service", "source_ip", "source_port",
    "destination_service", "event_type", "action", "outcome", "username", "session_id",
    "campaign_id", "request_path", "http_method", "http_status", "command", "query_type",
    "database_name", "table_names", "rows_returned", "file_name", "file_direction",
    "user_agent", "raw_evidence_redacted", "tags",
}


def _minimal(**over):
    base = dict(event_id=str(uuid.uuid4()), timestamp=datetime.now(timezone.utc), sensor_id="web-01",
                service="web", source_ip="203.0.113.10", destination_service="web-decoy",
                event_type="http_request", action="page_view", outcome="observed")
    base.update(over)
    return base


def test_model_fields_match_handoff_exactly():
    assert set(CanonicalEvent.model_fields) == HANDOFF_FIELDS


@pytest.mark.parametrize("bad", [
    {"event_type": "exploit"}, {"outcome": "pwned"}, {"service": "ftp"},
    {"unexpected_field": 1}, {"timestamp": datetime(2026, 1, 1)},  # naive time
])
def test_model_rejects_invalid(bad):
    with pytest.raises(ValidationError):
        CanonicalEvent(**_minimal(**bad))


def test_timestamp_serialized_rfc3339_utc():
    out = CanonicalEvent(**_minimal()).model_dump(mode="json")
    assert out["timestamp"].endswith("Z") and "+" not in out["timestamp"]


def _traffic(client):
    client.get("/")
    client.get("/admin")
    client.get("/.env")
    client.get("/search", params={"q": "abc"})
    client.post("/login", data={"username": GOOD_USER, "password": "nope"})
    client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    client.get("/portal")
    client.get("/api/v1/users/1002")
    client.post("/upload", files={"document": ("a.pdf", b"%PDF-1.4 x", "application/pdf")})
    client.post("/logout")


def test_every_emitted_event_validates(client, settings):
    _traffic(client)
    events = read_events(settings)
    assert len(events) == 10
    for e in events:
        CanonicalEvent.model_validate(e)
        assert set(e) == HANDOFF_FIELDS
        assert uuid.UUID(e["event_id"]).version == 4
        assert e["sensor_id"] == "web-01" and e["service"] == "web"
        assert e["timestamp"].endswith("Z")
        # Database-only fields are never fabricated by the web sensor.
        assert e["command"] is None and e["query_type"] is None and e["database_name"] is None
        assert e["table_names"] == [] and e["rows_returned"] is None


def test_event_ids_unique(client, settings):
    _traffic(client)
    ids = [e["event_id"] for e in read_events(settings)]
    assert len(ids) == len(set(ids))
