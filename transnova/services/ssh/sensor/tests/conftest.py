from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from cowrie_soc.config import Config, load_config
from cowrie_soc.parser import ParsedEvent, RawLine, parse_line

FIXTURES = Path(__file__).parent / "fixtures"
REAL_CAPTURE = FIXTURES / "real_capture_2026-10-31.json"
CONFIG_FILE = Path(__file__).parents[1] / "config" / "collector.toml"

T0 = datetime(2026, 10, 31, 12, 0, 0, tzinfo=timezone.utc)


def cowrie_line(eventid: str, session: str = "aaaa00000001", at: float = 0.0, src_ip: str = "10.66.0.5",
                **fields: Any) -> str:
    """Build a Cowrie-shaped JSON line using the field layout observed from Cowrie 3.1.4."""
    ts = (T0 + timedelta(seconds=at)).isoformat(timespec="microseconds").replace("+00:00", "Z")
    event = {
        "session": session, "protocol": "ssh", "src_ip": src_ip, "src_port": 40000,
        "dst_ip": "172.18.0.2", "dst_port": 2222, **fields, "eventid": eventid,
        "sensor": "cowrie-ssh-01", "uuid": "5458743a-d0ea-11f1-9b92-2aedfafa4905", "timestamp": ts,
        "message": fields.pop("message", ""),
    }
    return json.dumps(event)


def parse_text(line: str, offset: int = 0) -> ParsedEvent:
    parsed = parse_line(RawLine(line.encode(), "cowrie.json", offset))
    assert isinstance(parsed, ParsedEvent), parsed
    return parsed


@pytest.fixture
def config() -> Config:
    return load_config(CONFIG_FILE, env={})


@pytest.fixture
def real_lines() -> list[bytes]:
    return REAL_CAPTURE.read_bytes().splitlines()
