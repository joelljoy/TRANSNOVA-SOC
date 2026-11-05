from __future__ import annotations

import json

import pytest

from cowrie_soc.parser import ParsedEvent, ParseError, RawLine, parse_line

from .conftest import cowrie_line


def raw(data: bytes | str, **kw: bool) -> RawLine:
    return RawLine(data.encode() if isinstance(data, str) else data, "cowrie.json", 42, **kw)


def test_valid_real_line_parses(real_lines: list[bytes]) -> None:
    parsed = parse_line(raw(real_lines[0]))
    assert isinstance(parsed, ParsedEvent)
    assert parsed.event["eventid"] == "cowrie.session.connect"
    assert parsed.offset == 42 and parsed.source == "cowrie.json"
    assert len(parsed.raw_sha256) == 64


def test_every_real_capture_line_is_valid(real_lines: list[bytes]) -> None:
    results = [parse_line(raw(line)) for line in real_lines]
    assert all(isinstance(r, ParsedEvent) for r in results)


def test_blank_line_is_skipped() -> None:
    assert parse_line(raw("   ")) is None


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        ("{not json", "invalid JSON"),
        ("[1, 2, 3]", "expected object"),
        (json.dumps({"timestamp": "2026-10-31T00:00:00Z", "session": "s"}), "non-Cowrie 'eventid'"),
        (json.dumps({"eventid": "other.thing", "timestamp": "2026-10-31T00:00:00Z", "session": "s"}), "non-Cowrie"),
        (json.dumps({"eventid": "cowrie.x", "session": "s"}), "missing 'timestamp'"),
        (json.dumps({"eventid": "cowrie.x", "timestamp": "yesterday", "session": "s"}), "unparseable 'timestamp'"),
        (json.dumps({"eventid": "cowrie.x", "timestamp": "2026-10-31T00:00:00", "session": "s"}), "unparseable"),
        (json.dumps({"eventid": "cowrie.x", "timestamp": "2026-10-31T00:00:00Z"}), "missing 'session'"),
        (cowrie_line("cowrie.session.connect", src_ip="999.1.1.1"), "not an IP address"),
        (cowrie_line("cowrie.session.connect", src_ip="'; DROP TABLE x;--"), "not an IP address"),
    ],
)
def test_malformed_lines_are_rejected_with_reason(data: str, reason: str) -> None:
    result = parse_line(raw(data))
    assert isinstance(result, ParseError)
    assert reason in result.reason
    assert result.offset == 42 and result.excerpt == ""


def test_bad_port_rejected() -> None:
    line = json.loads(cowrie_line("cowrie.session.connect"))
    line["src_port"] = "22; rm -rf /"
    assert isinstance(parse_line(raw(json.dumps(line))), ParseError)


def test_invalid_utf8_rejected() -> None:
    result = parse_line(raw(b'{"eventid": "cowrie.x\xff"}'))
    assert isinstance(result, ParseError) and "UTF-8" in result.reason


def test_oversized_and_unterminated_flags() -> None:
    over = parse_line(raw("x" * 10, oversized=True))
    assert isinstance(over, ParseError) and "max_line_bytes" in over.reason
    tail = parse_line(raw('{"eventid": "cowrie.ses', unterminated=True))
    assert isinstance(tail, ParseError) and "unterminated" in tail.reason


@pytest.mark.parametrize(("field", "value"), [("password", ["a"]), ("username", {"x": 1}), ("input", 12345)])
def test_wrong_typed_string_fields_are_rejected(field: str, value: object) -> None:
    # Regression: a list-typed password crashed the brute-force rule mid-batch.
    line = json.loads(cowrie_line("cowrie.login.failed", username="root", password="x"))
    line[field] = value
    result = parse_line(raw(json.dumps(line)))
    assert isinstance(result, ParseError) and "expected string" in result.reason
