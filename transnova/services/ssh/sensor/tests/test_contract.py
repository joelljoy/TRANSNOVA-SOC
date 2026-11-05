"""Guard against drift between the code and the documented integration contract."""

from __future__ import annotations

import json
from pathlib import Path

from cowrie_soc.attack import TECHNIQUES
from cowrie_soc.detection import RULE_CLASSES
from cowrie_soc.normalize import EVENT_MAP
from cowrie_soc.schema import EVENT_REQUIRED, FINDING_REQUIRED, validate_record

DOCS = Path(__file__).parents[2] / "docs"


def test_event_schema_matches_code() -> None:
    schema = json.loads((DOCS / "schema" / "event.schema.json").read_text(encoding="utf-8"))
    documented = set(schema["properties"]["event_type"]["enum"])
    assert documented == {t for t, _, _ in EVENT_MAP.values()} | {"cowrie_other"}
    assert set(schema["required"]) == set(EVENT_REQUIRED)
    categories = set(schema["properties"]["category"]["enum"])
    assert {c for _, c, _ in EVENT_MAP.values()} | {"other"} <= categories


def test_finding_schema_matches_code() -> None:
    schema = json.loads((DOCS / "schema" / "finding.schema.json").read_text(encoding="utf-8"))
    assert set(schema["required"]) == set(FINDING_REQUIRED)


def test_sample_records_are_valid() -> None:
    lines = (DOCS / "examples" / "sample-records.jsonl").read_text(encoding="utf-8").splitlines()
    assert lines
    for line in lines:
        assert validate_record(json.loads(line)) == []


def test_envelope_example_matches_encoder_and_contract() -> None:
    env = json.loads((DOCS / "examples" / "envelope-example.json").read_text(encoding="utf-8"))
    assert env["source"] == "cowrie-ssh" and env["count"] == len(env["records"])
    for rec in env["records"]:
        assert validate_record(rec) == []
        assert rec["source_service"] == "ssh"


def test_every_rule_and_technique_is_documented() -> None:
    text = (DOCS / "detections.md").read_text(encoding="utf-8")
    for cls in RULE_CLASSES:
        assert cls.rule_id in text and cls.config_key in text
    for tid in TECHNIQUES:
        assert tid in text
