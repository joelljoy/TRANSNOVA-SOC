from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from cowrie_soc.config import Config
from cowrie_soc.pipeline import Pipeline
from cowrie_soc.sinks import Deliverer, JsonlSink, SinkError
from cowrie_soc.store import Store

from .conftest import REAL_CAPTURE


class FlakySink:
    """Test sink: fails (retryable or not) while `fail` is set, records what it received."""

    def __init__(self, name: str = "flaky", batch_size: int = 50) -> None:
        self.name = name
        self.batch_size = batch_size
        self.fail: str | None = None
        self.received: list[dict[str, Any]] = []

    def send(self, records: list[dict[str, Any]]) -> None:
        if self.fail == "retry":
            raise SinkError("backend down", retryable=True)
        if self.fail == "reject":
            raise SinkError("HTTP 400 schema mismatch", retryable=False)
        self.received.extend(records)


@pytest.fixture
def lab(tmp_path: Path, config: Config) -> Config:
    (tmp_path / "logs").mkdir()
    config.source.log_dir = str(tmp_path / "logs")
    config.collector.state_db = str(tmp_path / "state" / "collector.db")
    config.jsonl.path = str(tmp_path / "state" / "normalized.jsonl")
    config.source.batch_max_lines = 25
    return config


def append(cfg: Config, lines: list[bytes]) -> None:
    with (Path(cfg.source.log_dir) / "cowrie.json").open("ab") as fh:
        for line in lines:
            fh.write(line + b"\n")


def run_until_idle(p: Pipeline, max_steps: int = 100) -> None:
    """Step until two consecutive steps read nothing and nothing is pending."""
    quiet = 0
    for _ in range(max_steps):
        quiet = quiet + 1 if p.step() == 0 and p.store.pending_count() == 0 else 0
        if quiet == 2:
            return
    raise AssertionError("pipeline did not become idle")


def jsonl_records(cfg: Config) -> list[dict[str, Any]]:
    return [json.loads(x) for x in Path(cfg.jsonl.path).read_text(encoding="utf-8").splitlines()]


def test_end_to_end_real_capture_exactly_once(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, real_lines[:40])
    p = Pipeline(lab)
    run_until_idle(p)
    append(lab, real_lines[40:])
    run_until_idle(p)
    recs = jsonl_records(lab)
    events = [r for r in recs if r["record_type"] == "event"]
    findings = [r for r in recs if r["record_type"] == "finding"]
    assert len(events) == len(real_lines) == 104
    assert len({r["event_id"] for r in events}) == 104
    assert len(findings) == 14
    assert p.store.status()["sinks"][0]["pending"] == 0


def test_restart_resumes_without_loss_or_duplicates(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, real_lines[:30])
    p1 = Pipeline(lab)
    run_until_idle(p1)
    p1.store.close()
    append(lab, real_lines[30:60])
    p2 = Pipeline(lab)  # simulated collector restart
    run_until_idle(p2)
    events = [r for r in jsonl_records(lab) if r["record_type"] == "event"]
    assert [r["raw"]["sha256"] for r in events] == [
        __import__("hashlib").sha256(line).hexdigest() for line in real_lines[:60]
    ]


def test_crash_between_commit_and_delivery_redelivers_same_ids(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, real_lines[:10])
    store = Store(lab.collector.state_db)
    sink = FlakySink()
    sink.fail = "retry"
    p1 = Pipeline(lab, store=store, sinks=[sink])
    p1.step()  # committed to outbox, delivery failed
    assert store.pending_count("flaky") == 10
    store.close()
    store2 = Store(lab.collector.state_db)
    sink2 = FlakySink()
    p2 = Pipeline(lab, store=store2, sinks=[sink2])
    run_until_idle(p2)
    assert len(sink2.received) == 10  # nothing lost, nothing re-read from the log


def test_retryable_failure_keeps_records_and_recovers(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, real_lines[:20])
    sink = FlakySink()
    sink.fail = "retry"
    p = Pipeline(lab, sinks=[sink])
    p.deliverers[0].base_backoff = 0
    for _ in range(5):
        p.step()
    assert sink.received == []
    assert p.store.pending_count("flaky") >= 20
    assert "backend down" in p.store.status()["sinks"][0]["last_error"]
    sink.fail = None
    run_until_idle(p)
    assert len([r for r in sink.received if r["record_type"] == "event"]) == 20


def test_permanent_rejection_goes_to_dead_letter(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, real_lines[:5])
    sink = FlakySink()
    sink.fail = "reject"
    p = Pipeline(lab, sinks=[sink])
    run_until_idle(p)
    assert p.store.status()["dead_letters"] == 5


def test_backpressure_pauses_ingestion_without_loss(lab: Config, real_lines: list[bytes]) -> None:
    lab.collector.max_pending_records = 30
    append(lab, real_lines)
    sink = FlakySink()
    sink.fail = "retry"
    p = Pipeline(lab, sinks=[sink])
    p.deliverers[0].base_backoff = 0
    for _ in range(10):
        p.step()
    assert p.backpressure
    assert p.store.pending_count() < 60  # ingestion stopped near the bound
    sink.fail = None
    run_until_idle(p)
    assert len([r for r in sink.received if r["record_type"] == "event"]) == 104


def test_malformed_lines_are_quarantined_and_ingestion_continues(lab: Config, real_lines: list[bytes]) -> None:
    append(lab, [real_lines[0], b"{garbage", b'["not", "an", "object"]', real_lines[1]])
    p = Pipeline(lab)
    run_until_idle(p)
    status = p.store.status()
    assert status["quarantined"] == 2
    assert len([r for r in jsonl_records(lab) if r["record_type"] == "event"]) == 2
    reasons = [q["reason"] for q in p.store.quarantine_rows()]
    assert any("invalid JSON" in r for r in reasons) and any("expected object" in r for r in reasons)


def test_rotation_through_pipeline(lab: Config, real_lines: list[bytes]) -> None:
    log = Path(lab.source.log_dir) / "cowrie.json"
    append(lab, real_lines[:10])
    p = Pipeline(lab)
    run_until_idle(p)
    append(lab, real_lines[10:15])
    log.rename(log.with_name("cowrie.json.2026-10-31"))
    append(lab, real_lines[15:20])
    run_until_idle(p)
    assert len([r for r in jsonl_records(lab) if r["record_type"] == "event"]) == 20


def test_outbox_pruning_keeps_recent_rows(lab: Config, real_lines: list[bytes]) -> None:
    lab.collector.retain_delivered_records = 10
    append(lab, real_lines)
    p = Pipeline(lab)
    run_until_idle(p)
    assert p.store.status()["outbox_rows"] <= 10 + lab.source.batch_max_lines


def test_deliverer_backoff_grows(tmp_path: Path) -> None:
    store = Store(tmp_path / "s.db")
    store.commit("x", None, [{"record_type": "event", "event_id": "e1"}])
    sink = FlakySink()
    sink.fail = "retry"
    now = [0.0]
    d = Deliverer(sink, store, base_backoff=1, max_backoff=8, clock=lambda: now[0])
    delays = []
    for _ in range(5):
        d.deliver()
        delays.append(d.next_attempt - now[0])
        now[0] = d.next_attempt
    assert delays == [1, 2, 4, 8, 8]


def test_jsonl_sink_rotates(tmp_path: Path) -> None:
    sink = JsonlSink(tmp_path / "out.jsonl", max_bytes=100)
    sink.send([{"record_type": "event", "event_id": "a" * 80}])
    sink.send([{"record_type": "event", "event_id": "b"}])
    assert (tmp_path / "out.jsonl.1").exists()


def test_real_capture_fixture_present() -> None:
    assert REAL_CAPTURE.stat().st_size > 0


def test_removed_sink_does_not_block_pending_or_pruning(lab: Config, real_lines: list[bytes]) -> None:
    # Regression: a sink used in an earlier run (e.g. http) but no longer configured kept its
    # stale cursor, so pending never reached 0 (eventual backpressure stall) and pruning stopped.
    store = Store(lab.collector.state_db)
    store.register_sink("http")
    store.close()
    lab.collector.retain_delivered_records = 5
    append(lab, real_lines[:40])
    p = Pipeline(lab)  # jsonl only
    run_until_idle(p)
    assert p.store.pending_count() == 0
    assert p.store.status()["outbox_rows"] <= 5 + lab.source.batch_max_lines


def test_processing_error_is_quarantined_not_retried(lab: Config, monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: an exception inside normalize/detect made step() raise and re-read the batch,
    # double-counting detection state and losing the finding the crash interrupted.
    from cowrie_soc import pipeline as pipeline_mod

    from .conftest import cowrie_line

    real_normalize = pipeline_mod.normalize

    def flaky_normalize(parsed, cfg):  # type: ignore[no-untyped-def]
        if parsed.event["session"] == "boom":
            raise RuntimeError("simulated processing bug")
        return real_normalize(parsed, cfg)

    monkeypatch.setattr(pipeline_mod, "normalize", flaky_normalize)
    lines = [cowrie_line("cowrie.login.failed", f"s{i}", at=i, username="root", password=f"p{i}") for i in range(5)]
    lines.insert(2, cowrie_line("cowrie.login.failed", "boom", at=1.5, username="root", password="x"))
    append(lab, [line.encode() for line in lines])
    p = Pipeline(lab)
    run_until_idle(p)
    recs = jsonl_records(lab)
    assert len([r for r in recs if r["record_type"] == "event"]) == 5
    brute = [r for r in recs if r.get("rule_id") == "SSH-BRUTE-001"]
    assert len(brute) == 1 and brute[0]["evidence"]["observed"]["failed_attempts"] == 5
    assert "processing error" in p.store.quarantine_rows()[0]["reason"]
