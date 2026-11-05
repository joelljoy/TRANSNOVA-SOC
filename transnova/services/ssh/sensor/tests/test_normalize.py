from __future__ import annotations

import hashlib
import json
from collections import Counter

from cowrie_soc.normalize import EVENT_MAP, NormalizeConfig, normalize
from cowrie_soc.parser import ParsedEvent, RawLine, parse_line
from cowrie_soc.schema import validate_record

from .conftest import cowrie_line, parse_text

CFG = NormalizeConfig(sensor_id="cowrie-test")


def _normalize_all(lines: list[bytes]) -> list[dict]:
    out, offset = [], 0
    for line in lines:
        parsed = parse_line(RawLine(line, "cowrie.json", offset))
        assert isinstance(parsed, ParsedEvent)
        out.append(normalize(parsed, CFG))
        offset += len(line) + 1
    return out


def test_real_capture_normalizes_to_valid_records(real_lines: list[bytes]) -> None:
    records = _normalize_all(real_lines)
    assert all(validate_record(r) == [] for r in records)
    types = Counter(r["event_type"] for r in records)
    # Every event type observed from the live Cowrie 3.1.4 container maps to a known type.
    assert "cowrie_other" not in types
    assert types["authentication_failure"] == 8
    assert types["shell_command"] == 24  # 23 via paramiko shell + 1 OpenSSH exec line
    assert types["ssh_connection"] == types["session_closed"]


def test_raw_event_is_preserved_verbatim(real_lines: list[bytes]) -> None:
    rec = _normalize_all(real_lines[:5])[4]
    assert rec["raw"]["event"] == json.loads(real_lines[4])
    assert rec["raw"]["sha256"] == hashlib.sha256(real_lines[4]).hexdigest()
    assert rec["raw"]["ref"]["file"] == "cowrie.json"
    assert rec["raw"]["ref"]["offset"] == sum(len(line) + 1 for line in real_lines[:4])


def test_event_ids_are_deterministic_and_unique(real_lines: list[bytes]) -> None:
    first = [r["event_id"] for r in _normalize_all(real_lines)]
    second = [r["event_id"] for r in _normalize_all(real_lines)]
    assert first == second
    assert len(set(first)) == len(first)


def test_login_failure_fields() -> None:
    rec = normalize(parse_text(cowrie_line("cowrie.login.failed", username="root", password="toor",
                                           message="login attempt [root/toor] failed")), CFG)
    assert (rec["event_type"], rec["category"], rec["outcome"]) == ("authentication_failure", "authentication", "failure")
    assert rec["username"] == "root" and rec["password"] == "toor"
    assert rec["source_ip"] == "10.66.0.5" and rec["source_service"] == "ssh"


def test_password_redaction() -> None:
    cfg = NormalizeConfig(sensor_id="s", include_passwords=False)
    rec = normalize(parse_text(cowrie_line("cowrie.login.failed", username="root", password="hunter2",
                                           message="login attempt [root/hunter2] failed")), cfg)
    assert rec["password"] is None
    assert "hunter2" not in json.dumps(rec)
    assert rec["raw"]["redacted"] == ["password"]


def test_command_gets_attack_tags_and_analysis() -> None:
    rec = normalize(parse_text(cowrie_line("cowrie.command.input", input="uname -a; cat /etc/passwd")), CFG)
    assert rec["event_type"] == "shell_command"
    assert rec["command"] == "uname -a; cat /etc/passwd"
    assert {t["technique_id"] for t in rec["attack"]} == {"T1082", "T1087.001"}
    assert rec["details"]["command_analysis"]["programs"] == ["uname", "cat"]


def test_unknown_eventid_is_kept_not_dropped() -> None:
    rec = normalize(parse_text(cowrie_line("cowrie.future.event", foo="bar")), CFG)
    assert rec["event_type"] == "cowrie_other" and rec["details"]["foo"] == "bar"


def test_documented_download_event_maps() -> None:
    # Not observed live (Cowrie's out_addr blocks downloads before this event); fields per Cowrie docs.
    rec = normalize(parse_text(cowrie_line("cowrie.session.file_download.failed", url="http://192.0.2.9/a")), CFG)
    assert (rec["event_type"], rec["outcome"]) == ("file_download", "failure")
    assert set(EVENT_MAP) >= {"cowrie.session.file_download", "cowrie.direct-tcpip.request"}


def test_long_fields_are_truncated_and_flagged() -> None:
    cfg = NormalizeConfig(sensor_id="s", max_field_chars=10)
    rec = normalize(parse_text(cowrie_line("cowrie.command.input", input="A" * 50)), cfg)
    assert rec["command"] == "A" * 10
    assert "command" in rec["truncated_fields"]
    assert rec["raw"]["event"]["input"] == "A" * 50
