"""Clean SSH records into the shared SOC event format.

Fake markers are random and must never be shown. PYTEST_DONT_REWRITE turns off pytest's
assertion detail for this file, so a failure cannot print a marker.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

import pytest

from cowrie_soc import canonical
from cowrie_soc.canonical import FIELDS, Skip, safe_id, source_address, translate, validate
from cowrie_soc.config import Config
from cowrie_soc.normalize import NormalizeConfig, normalize
from cowrie_soc.pipeline import Processor
from cowrie_soc.parser import RawLine
from cowrie_soc.redact import R

from .conftest import cowrie_line, parse_text

SENSOR = "ssh-01"
EVENT_ID = "11111111-2222-5333-8444-555555555555"
FINDING_ID = "aaaaaaaa-bbbb-5ccc-8ddd-eeeeeeeeeeee"


def marker() -> str:
    return "X" + secrets.token_hex(16)


def record(eventid: str, **fields: Any) -> dict[str, Any]:
    rec = normalize(parse_text(cowrie_line(eventid, session="abc123", **fields)),
                    NormalizeConfig(SENSOR, include_passwords=False))
    return rec


def finding(rule: str = "SSH-CRED-001", **change: Any) -> dict[str, Any]:
    return {"record_type": "finding", "rule_id": rule, "finding_id": FINDING_ID, "severity": "high", "confidence": "high",
            "attack": [{"technique_id": "T1552.001", "name": "x", "tactic": "credential-access"}],
            "evidence": {"event_ids": [EVENT_ID, "not-a-uuid"]}, **change}


@pytest.mark.parametrize(("eventid", "fields", "expected"), [
    ("cowrie.session.connect", {}, ("connection", "ssh_connect", "observed")),
    ("cowrie.session.closed", {"duration_ms": 5}, ("connection", "ssh_disconnect", "observed")),
    ("cowrie.client.version", {"version": "SSH-2.0-x"}, ("connection", "ssh_client_version", "observed")),
    ("cowrie.client.kex", {"hassh": "a" * 32}, ("connection", "ssh_client_kex", "observed")),
    ("cowrie.client.size", {"width": 80, "height": 24}, ("connection", "ssh_terminal_size", "observed")),
    ("cowrie.client.var", {"name": "LANG", "value": "C"}, ("connection", "ssh_client_env", "observed")),
    ("cowrie.session.params", {"arch": "linux-x64"}, ("connection", "ssh_session_params", "observed")),
    ("cowrie.client.fingerprint", {"username": "root"}, ("authentication", "ssh_publickey_offered", "observed")),
    ("cowrie.login.failed", {"username": "root"}, ("authentication", "ssh_login", "failed")),
    ("cowrie.login.success", {"username": "root"}, ("authentication", "ssh_login", "succeeded")),
    ("cowrie.command.input", {"input": "id"}, ("command", "shell_command", "observed")),
    ("cowrie.command.failed", {"input": "nosuch"}, ("command", "shell_command_not_found", "failed")),
    ("cowrie.command.success", {"input": "x"}, ("command", "typed_input_hidden", "observed")),
    ("cowrie.session.input", {"input": "x", "realm": "cat"}, ("command", "typed_input_hidden", "observed")),
    ("cowrie.command.chpasswd", {"username": "root"}, ("command", "password_change_attempt", "observed")),
    ("cowrie.session.file_download", {"url": "http://192.0.2.1/a", "shasum": "a" * 64}, ("file_transfer", "file_download", "observed")),
    ("cowrie.session.file_download", {"format": "Saved stdin contents"}, ("file_transfer", "input_captured", "observed")),
    ("cowrie.session.file_download.failed", {"url": "http://192.0.2.1/a"}, ("file_transfer", "file_download", "failed")),
    ("cowrie.session.file_upload", {"filename": "a.bin", "shasum": "a" * 64}, ("file_transfer", "file_upload", "observed")),
    ("cowrie.future.event", {}, ("connection", "cowrie_other", "observed")),
])
def test_mapping(eventid: str, fields: dict[str, Any], expected: tuple[str, str, str]) -> None:
    event = translate(record(eventid, **fields), SENSOR)
    assert (event["event_type"], event["action"], event["outcome"]) == expected
    assert tuple(event) == FIELDS


def test_no_file_event_claims_success() -> None:
    for eventid in ("cowrie.session.file_download", "cowrie.session.file_upload"):
        assert translate(record(eventid, url="http://192.0.2.1/a", shasum="a" * 64, filename="a"), SENSOR)["outcome"] == "observed"


def test_fixed_identity() -> None:
    event = translate(record("cowrie.session.connect", src_ip="172.31.77.50"), SENSOR)
    assert (event["service"], event["destination_service"], event["sensor_id"]) == ("ssh", "ssh-honeypot", SENSOR)
    assert event["source_ip"] == "172.31.77.50" and event["campaign_id"] is None


def test_no_alias_is_applied_to_the_attacker_address() -> None:
    assert source_address("172.31.77.50", "abc") == "172.31.77.50"


@pytest.mark.parametrize("value", [None, "", "not-an-ip", 5, "999.1.1.1", ["10.0.0.1"], "unknown"])
def test_missing_address_gets_a_session_label_never_a_shared_word(value: Any) -> None:
    assert source_address(value, "abc123") == "unknown-ssh-abc123"


def test_two_sessions_with_no_address_do_not_share_a_label() -> None:
    assert source_address(None, "abc") != source_address(None, "def")


def test_username_from_session_is_tagged() -> None:
    event = translate(record("cowrie.command.input", input="id"), SENSOR, session_username="backup")
    assert event["username"] == "backup" and "ssh:username_from_session" in event["tags"]


@pytest.mark.parametrize(("change", "reason"), [
    ({"event_id": "bad"}, canonical.BAD_EVENT_ID),
    ({"event_id": None}, canonical.BAD_EVENT_ID),
    ({"sensor_id": "other"}, canonical.BAD_SENSOR_ID),
    ({"timestamp": "yesterday"}, canonical.BAD_TIMESTAMP),
    ({"timestamp": "2026-10-31T00:00:00+05:30"}, canonical.BAD_TIMESTAMP),
    ({"timestamp": "2026-13-31T00:00:00Z"}, canonical.BAD_TIMESTAMP),
    ({"session_id": "NOT HEX"}, canonical.BAD_SESSION),
    ({"raw": None}, canonical.BAD_RECORD),
    ({"record_type": "finding"}, canonical.BAD_RECORD),
])
def test_bad_records_are_skipped_with_a_fixed_reason(change: dict[str, Any], reason: str) -> None:
    with pytest.raises(Skip) as exc:
        translate({**record("cowrie.session.connect"), **change}, SENSOR)
    assert exc.value.reason == reason


@pytest.mark.parametrize("value", [None, 5, "text", []])
def test_non_records_are_skipped(value: Any) -> None:
    with pytest.raises(Skip):
        translate(value, SENSOR)


def test_safe_id_never_echoes_a_bad_identifier() -> None:
    secret = marker()
    assert safe_id({"event_id": EVENT_ID}) == EVENT_ID
    assert safe_id({"event_id": secret}, "a" * 64) == "sha256:" + "a" * 64
    assert safe_id({"event_id": secret}, secret) == "unidentified"


def stage2_record(secret: str) -> dict[str, Any]:
    """Shaped like a Stage 2 record, written before the allowed-field rule existed."""
    rec = record("cowrie.command.input", input="id")
    rec["command"] = f"mysql -p{secret}"
    rec["message"] = f"CMD: mysql -p{secret}"
    rec["password"] = secret
    rec["details"] = {"command_analysis": {"programs": [secret]}, "other": secret, "ttylog": secret}
    rec["raw"]["event"] = {**rec["raw"]["event"], "input": f"mysql -p{secret}", "message": secret, "password": secret,
                           "kexAlgs": [secret], "anything": secret}
    return rec


def test_older_records_are_cleaned_again() -> None:
    secret = marker()
    event = translate(stage2_record(secret), SENSOR)
    assert secret not in json.dumps(event)


@pytest.mark.parametrize(("eventid", "fields"), [
    ("cowrie.command.success", {"input": "M", "realm": "passwd"}),
    ("cowrie.session.input", {"input": "M", "realm": "tee"}),
    ("cowrie.client.var", {"name": "M", "value": "M"}),
    ("cowrie.client.var", {"name": "DB_SECRET", "value": "M"}),
    ("cowrie.login.failed", {"username": "M", "password": "M"}),
    ("cowrie.command.input", {"input": "mysql -pM"}),
    ("cowrie.session.file_upload", {"filename": "M.tar", "shasum": "b" * 64}),
    ("cowrie.session.file_download", {"url": "http://a:M@192.0.2.1/x", "shasum": "b" * 64}),
    ("cowrie.future.event", {"input": "M", "data": "M", "anything": "M"}),
])
def test_marker_in_any_field_never_reaches_the_event(eventid: str, fields: dict[str, Any]) -> None:
    secret = marker()
    filled = {k: v.replace("M", secret) if isinstance(v, str) else v for k, v in fields.items()}
    event = translate(record(eventid, **filled), SENSOR)
    assert secret not in json.dumps(event)


def test_finding_text_is_never_read() -> None:
    secret = marker()
    dirty = finding(title=secret, explanation=secret, rule_name=secret, recommended_action=secret,
                    evidence={"event_ids": [EVENT_ID, secret], "observed": {"command": secret, "username": secret}})
    event = translate(record("cowrie.command.input", input="id"), SENSOR, [dirty])
    assert secret not in json.dumps(event)
    detection = event["raw_evidence_redacted"]["detections"][0]
    assert detection["label"] == "ssh:SSH-CRED-001"
    assert detection["rationale"] == canonical.RULES["SSH-CRED-001"][2]
    assert detection["evidence_event_ids"] == [EVENT_ID]


@pytest.mark.parametrize("change", [{"rule_id": "OTHER"}, {"severity": "mega"}, {"confidence": "x"}, {"finding_id": "bad"}])
def test_unrecognised_findings_are_dropped(change: dict[str, Any]) -> None:
    event = translate(record("cowrie.command.input", input="id"), SENSOR, [finding(**change)])
    assert event["raw_evidence_redacted"]["detections"] == []


def test_unknown_techniques_are_dropped_and_known_ones_come_from_the_catalogue() -> None:
    secret = marker()
    dirty = finding(attack=[{"technique_id": secret}, {"technique_id": "T1078", "name": secret, "tactic": secret}])
    entries = translate(record("cowrie.command.input", input="id"), SENSOR, [dirty])["raw_evidence_redacted"]["detections"][0]["attack"]
    assert [a["technique"] for a in entries] == ["T1078"]
    assert secret not in json.dumps(entries) and entries[0]["tactic"] == "Initial Access"


def test_download_technique_is_only_an_attempt() -> None:
    entry = canonical._attack_entry("T1105", "high")
    assert entry["status"] == "attempted" and entry["confidence"] == "low"


def test_collector_key_is_technique_not_technique_id() -> None:
    assert "technique_id" not in json.dumps(translate(record("cowrie.command.input", input="id"), SENSOR, [finding()]))


def test_severity_uses_the_highest_detection() -> None:
    event = translate(record("cowrie.command.input", input="id"), SENSOR,
                      [finding(severity="low"), finding("SSH-SEQ-001", severity="critical")])
    assert event["raw_evidence_redacted"]["severity"] == "CRITICAL"
    assert event["raw_evidence_redacted"]["attack_stage"] == "execution"


def test_no_score_or_severity_is_invented() -> None:
    evidence = translate(record("cowrie.session.connect"), SENSOR)["raw_evidence_redacted"]
    assert "risk_score" not in evidence and "severity" not in evidence


def test_large_evidence_is_trimmed_within_the_cap() -> None:
    rec = record("cowrie.command.input", input="cat /etc/passwd " * 500)
    event = translate(rec, SENSOR)
    assert len(json.dumps(event["raw_evidence_redacted"])) <= canonical.MAX_EVIDENCE_BYTES
    assert len(event["command"]) <= canonical.MAX_COMMAND_CHARS
    assert event["raw_evidence_redacted"]["raw"]["sha256"]


def good() -> dict[str, Any]:
    return translate(record("cowrie.session.connect"), SENSOR)


@pytest.mark.parametrize(("field", "value"), [
    ("event_id", ""), ("event_id", 5), ("timestamp", 1793000000), ("timestamp", "2026-10-31T00:00:00"),
    ("sensor_id", "other"), ("service", "SSH"), ("service", "web"), ("source_ip", ""), ("source_ip", "unknown"),
    ("source_port", "22"), ("source_port", True), ("source_port", -1), ("source_port", 70000), ("source_port", 22.0),
    ("destination_service", "other"), ("event_type", "Command"), ("action", ""), ("outcome", "ok"), ("username", 5),
    ("campaign_id", "x"), ("request_path", "/"), ("http_status", 200), ("rows_returned", 1), ("table_names", None),
    ("table_names", ["x"]), ("tags", None), ("tags", ("ssh:x",)), ("tags", ["other"]), ("tags", [1]),
    ("raw_evidence_redacted", None), ("raw_evidence_redacted", []), ("raw_evidence_redacted", {1: "a"}),
    ("raw_evidence_redacted", {"a": object()}), ("raw_evidence_redacted", {"a": "x" * 9000}),
])
def test_validator_rejects(field: str, value: Any) -> None:
    assert validate({**good(), field: value}, SENSOR) == field


def test_validator_rejects_extra_and_missing_fields() -> None:
    event = good()
    assert validate({**event, "extra": 1}, SENSOR) == "fields"
    del event["tags"]
    assert validate(event, SENSOR) == "fields"


def test_validator_accepts_a_good_event() -> None:
    assert validate(good(), SENSOR) is None


def test_processor_with_delivery_off_translates_nothing() -> None:
    out = Processor(Config()).process([RawLine(cowrie_line("cowrie.session.connect", session="abc").encode(), "cowrie.json", 0)])
    assert out.canonical == [] and out.skipped == []


def enabled() -> Config:
    config = Config()
    config.http.enabled = True
    return config


def test_processor_queues_only_validated_events() -> None:
    out = Processor(enabled()).process([RawLine(cowrie_line("cowrie.session.connect", session="abc").encode(), "cowrie.json", 0)])
    assert len(out.canonical) == 1 and out.skipped == []


def test_processor_skips_a_bad_session_with_a_safe_id_only() -> None:
    secret = marker()
    line = cowrie_line("cowrie.session.connect", session=secret + "!")
    out = Processor(enabled()).process([RawLine(line.encode(), "cowrie.json", 0)])
    assert out.canonical == [] and [reason for _, reason in out.skipped] == [canonical.BAD_SESSION]
    assert secret not in json.dumps(out.skipped)


def test_translator_fault_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    secret = marker()

    def broken(*_args: Any) -> None:
        raise ValueError(secret)

    monkeypatch.setattr("cowrie_soc.pipeline.translate", broken)
    out = Processor(enabled()).process([RawLine(cowrie_line("cowrie.session.connect", session="abc").encode(), "cowrie.json", 0)])
    assert out.canonical == [] and [reason for _, reason in out.skipped] == [canonical.TRANSLATOR_ERROR]
    assert secret not in json.dumps(out.skipped)


def test_the_shipped_config_stays_off() -> None:
    from cowrie_soc.config import load_config

    cfg = load_config(Path(__file__).parents[1] / "config" / "collector.toml", env={})
    assert cfg.http.enabled is False and cfg.http.batch_size == 50 and cfg.http.payload_format == "array"
    assert R == "__REDACTED__"
