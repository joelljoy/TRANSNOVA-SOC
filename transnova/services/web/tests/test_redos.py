"""Phase 4: detection stays fast on pathological input (PLAN §5.1)."""

import time

import pytest

from web_decoy.detection.behavior import BehaviorEngine
from web_decoy.detection.signatures import detect_signatures
from web_decoy.telemetry.middleware import RequestContext

NASTY = [
    "'" + " " * 50000 + "or",
    "' or " + "a" * 50000,
    "union " * 10000,
    "<" * 50000,
    "<script" + " " * 50000,
    "on" * 30000 + "=",
    "../" * 20000,
    "%25" * 30000,
    "http://" + "a" * 50000,
    "．" * 30000,
    "a" * 100000,
]


def _ctx(value, path="/search"):
    return RequestContext("GET", path, [("q", value)] * 50, [("f", value)] * 50, [], {}, "203.0.113.9",
                          200, False, {}, None)


@pytest.mark.parametrize("value", NASTY, ids=range(len(NASTY)))
def test_signature_time_budget(value):
    start = time.perf_counter()
    detect_signatures(_ctx(value, path="/" + value[:4000]))
    assert time.perf_counter() - start < 1.0  # 100 fields of pathological input


def test_behavior_memory_is_bounded():
    from web_decoy.detection import behavior
    eng = BehaviorEngine()
    for i in range(behavior.MAX_SOURCES + 500):
        eng.detect(RequestContext("GET", "/x", [], [], [], {}, f"10.{i // 65536}.{i // 256 % 256}.{i % 256}",
                                  404, False, {}, None))
    assert len(eng) == behavior.MAX_SOURCES


def test_per_source_history_is_bounded():
    from web_decoy.detection import behavior
    eng = BehaviorEngine(clock=lambda: 5.0)  # frozen clock: nothing ages out
    for i in range(behavior.MAX_EVENTS_PER_SOURCE * 3):
        eng.detect(RequestContext("GET", f"/p{i}", [], [], [], {}, "10.0.0.1", 404, False, {}, None))
    assert len(eng._sources["10.0.0.1"].paths) <= behavior.MAX_EVENTS_PER_SOURCE
