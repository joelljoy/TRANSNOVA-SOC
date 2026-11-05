"""Parse and validate raw Cowrie JSON log lines.

Each line is treated as untrusted input. A line either becomes a ParsedEvent
(valid JSON object with the fields every Cowrie event carries) or a
ParseError, which the pipeline quarantines with its location. Nothing is
dropped silently. A rejected line may hold anything, so quarantine keeps only
its location, hash and a fixed reason, never its content.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

# Fields Cowrie always writes as strings; anything else means a corrupted/tampered line.
_STRING_FIELDS = ("username", "password", "input", "message", "url", "dst_ip", "protocol", "sensor")


@dataclass(frozen=True)
class RawLine:
    """One line from a log file, with its location for evidence/checkpointing."""

    data: bytes
    source: str
    offset: int
    oversized: bool = False
    unterminated: bool = False


@dataclass(frozen=True)
class ParsedEvent:
    event: dict[str, Any]
    raw_text: str
    raw_sha256: str
    source: str
    offset: int


@dataclass(frozen=True)
class ParseError:
    reason: str
    source: str
    offset: int
    excerpt: str
    raw_sha256: str


def parse_timestamp(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return dt


def parse_line(raw: RawLine) -> ParsedEvent | ParseError | None:
    """Return None for blank lines, otherwise a ParsedEvent or ParseError."""
    digest = hashlib.sha256(raw.data).hexdigest()

    def fail(reason: str) -> ParseError:
        return ParseError(reason, raw.source, raw.offset, "", digest)

    if raw.oversized:
        return fail("line exceeds max_line_bytes")
    if not raw.data.strip():
        return None
    try:
        text = raw.data.decode("utf-8")
    except UnicodeDecodeError as exc:
        return fail(f"invalid UTF-8 at byte {exc.start}")
    try:
        event = json.loads(text)
    except json.JSONDecodeError as exc:
        suffix = " (unterminated final line)" if raw.unterminated else ""
        return fail(f"invalid JSON: {exc.msg} at char {exc.pos}{suffix}")
    if not isinstance(event, dict):
        return fail(f"JSON value is {type(event).__name__}, expected object")

    eventid = event.get("eventid")
    if not isinstance(eventid, str) or not eventid.startswith("cowrie."):
        return fail("missing or non-Cowrie 'eventid'")
    ts = event.get("timestamp")
    if not isinstance(ts, str):
        return fail("missing 'timestamp'")
    try:
        parse_timestamp(ts)
    except ValueError:
        return fail("unparseable 'timestamp'")
    session = event.get("session")
    if not isinstance(session, str) or not session:
        return fail("missing 'session'")
    src_ip = event.get("src_ip")
    if src_ip is not None:
        if not isinstance(src_ip, str):
            return fail("'src_ip' is not a string")
        try:
            ipaddress.ip_address(src_ip)
        except ValueError:
            return fail("'src_ip' is not an IP address")
    for str_field in _STRING_FIELDS:
        value = event.get(str_field)
        if value is not None and not isinstance(value, str):
            return fail(f"'{str_field}' is {type(value).__name__}, expected string")
    for port_field in ("src_port", "dst_port"):
        port = event.get(port_field)
        if port is not None and (not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535):
            return fail(f"'{port_field}' is not a valid port")

    return ParsedEvent(event, text, digest, raw.source, raw.offset)
