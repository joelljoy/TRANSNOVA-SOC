"""Sensor loop: tail → parse → filter internal → classify → emit → adapt → commit position.

    python -m db_sensor.main          # follow forever
    python -m db_sensor.main --once   # process what is in the log now, then exit
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx

from .adaptive import AdaptiveEngine, GrantBackend
from .audit import LineAssembler, parse_line
from .config import Settings, load_rules
from .emitter import DurableSender
from .events import EventBuilder, malformed_event
from .state import SensorState
from .tailer import AuditTailer

log = logging.getLogger("db_sensor")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps({"ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"), "level": record.levelname,
                           "logger": record.name, "msg": record.getMessage()})


class Sensor:
    def __init__(self, settings: Settings, transport: httpx.BaseTransport | None = None) -> None:
        self.s = settings
        self.rules = load_rules(settings.rules_path)
        data = Path(settings.data_dir)
        self.state = SensorState(settings.data_dir)
        self.tailer = AuditTailer(settings.audit_log_path, self.state.load_position())
        self.assembler = LineAssembler()
        self.builder = EventBuilder(settings, self.rules, self.state)
        self.events = DurableSender(f"{settings.collector_url}/api/events", data / "db-events.jsonl",
                                    data / "db-spool.jsonl", settings.batch_size, settings.post_timeout_s,
                                    settings.max_log_bytes, transport)
        self.adaptations = DurableSender(f"{settings.collector_url}/api/adaptations", data / "db-adaptations.jsonl",
                                         data / "db-adaptations-spool.jsonl", settings.batch_size,
                                         settings.post_timeout_s, settings.max_log_bytes, transport)
        self.backend = GrantBackend(settings)
        self.engine = AdaptiveEngine(settings, self.rules, self.state, self.backend, self.adaptations.add)
        self.stats = {"lines": 0, "events": 0, "internal_ignored": 0, "malformed": 0}
        self._last_heartbeat = 0.0
        self._heartbeat_client = httpx.Client(timeout=settings.post_timeout_s, trust_env=False, transport=transport)

    def handle_line(self, line: str) -> None:
        self.stats["lines"] += 1
        rec = parse_line(line)
        if rec is None:
            self.stats["malformed"] += 1
            self.events.add(malformed_event(line, self.s, f"{self.tailer.position.identity}:{self.tailer.position.offset}"))
            return
        if self.builder.is_internal(rec):
            self.stats["internal_ignored"] += 1
            return
        event, _classification, key = self.builder.build(rec)
        if event is None:
            return
        self.stats["events"] += 1
        self.events.add(event)
        for record in self.engine.evaluate(key, event):
            session = self.state.sessions.get(rec.connection_id)
            if session is not None and record["rule_id"] not in session.reveal_rules:
                session.reveal_rules.append(record["rule_id"])

    def poll_once(self) -> int:
        lines = self.tailer.poll()
        for line in lines:
            for record in self.assembler.feed(line):
                self.handle_line(record)
        self.events.flush()
        self.adaptations.flush()
        # Committed after delivery or spooling: a crash re-reads lines rather than losing them,
        # and stable event ids make the re-read harmless.
        self.state.commit(self.tailer.position)
        return len(lines)

    def heartbeat(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._last_heartbeat < self.s.heartbeat_interval_s:
            return
        self._last_heartbeat = now
        try:
            db_ok = self.backend.ping()
        except Exception as exc:  # any driver or network failure just means "database down"
            log.warning("database ping failed: %s", type(exc).__name__)
            db_ok = False
        body: dict[str, Any] = {
            "sensor_id": self.s.sensor_id, "service": "database", "status": "ok" if db_ok else "degraded",
            "details": {**self.stats, "database_reachable": db_ok, "spool_pending": self.events.spool_depth(),
                        "revealed_assets": sorted(self.state.revealed_assets()),
                        "sessions": [asdict(p) for p in list(self.state.sessions.values())[-50:]]},
        }
        try:
            self._heartbeat_client.post(f"{self.s.collector_url}/api/sensors/heartbeat", json=body)
        except httpx.HTTPError as exc:
            log.warning("heartbeat failed: %s", type(exc).__name__)

    def run(self) -> None:
        log.info("sensor started; audit log %s", self.s.audit_log_path)
        while True:
            self.poll_once()
            self.heartbeat()
            time.sleep(self.s.poll_interval_s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    logging.basicConfig(level=logging.INFO, handlers=[handler])
    logging.getLogger("httpx").setLevel(logging.WARNING)
    sensor = Sensor(Settings.from_env())
    if args.once:
        while sensor.poll_once():
            pass
        sensor.heartbeat(force=True)
        print(json.dumps(sensor.stats))
        return 0
    sensor.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
