"""Wire formats for the HTTP sink - the replaceable part of the SOC integration.

The collector produces records in this component's documented format
(docs/integration-contract.md). When the team agrees on the shared SOC
schema/endpoint, add an Encoder here (or adjust field_map) instead of
changing the collector core.

Built-in encoders:
  envelope - {"source": ..., "sensor_id": ..., "sent_at": ..., "records": [...]}
  array    - a bare JSON array of records
"""

from __future__ import annotations

from typing import Any, Protocol

from cowrie_soc.normalize import utc_now_iso


class Encoder(Protocol):
    def encode_batch(self, records: list[dict[str, Any]]) -> Any: ...


def _rename(record: dict[str, Any], field_map: dict[str, str]) -> dict[str, Any]:
    if not field_map:
        return record
    return {field_map.get(k, k): v for k, v in record.items()}


class EnvelopeEncoder:
    def __init__(self, sensor_id: str, field_map: dict[str, str] | None = None) -> None:
        self.sensor_id = sensor_id
        self.field_map = dict(field_map or {})

    def encode_batch(self, records: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "source": "cowrie-ssh",
            "sensor_id": self.sensor_id,
            "sent_at": utc_now_iso(),
            "count": len(records),
            "records": [_rename(r, self.field_map) for r in records],
        }


class ArrayEncoder:
    def __init__(self, field_map: dict[str, str] | None = None) -> None:
        self.field_map = dict(field_map or {})

    def encode_batch(self, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [_rename(r, self.field_map) for r in records]


def make_encoder(name: str, sensor_id: str, field_map: dict[str, str] | None = None) -> Encoder:
    if name == "envelope":
        return EnvelopeEncoder(sensor_id, field_map)
    if name == "array":
        return ArrayEncoder(field_map)
    raise ValueError(f"unknown payload_format {name!r} (expected 'envelope' or 'array')")
