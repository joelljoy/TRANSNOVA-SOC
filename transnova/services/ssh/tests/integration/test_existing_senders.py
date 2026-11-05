"""Web and Database keep working exactly as before, using their real sender code on a real server.

The before-and-after test runs the same requests through the last collector before these changes
(extracted from Git into a temporary folder) and the current one, and compares every answer.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import zipfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from collector_support import REPO, TIMESTAMP, real_collector, web_event, write_tokens

sys.path[:0] = [str(REPO), str(REPO / "services/web"), str(REPO / "services/database/sensor")]

from db_sensor.classify import classify  # noqa: E402
from db_sensor.config import load_rules  # noqa: E402
from db_sensor.emitter import DurableSender  # noqa: E402
from db_sensor.state import SessionProfile  # noqa: E402
from web_decoy.app import create_app  # noqa: E402
from web_decoy.config import Settings  # noqa: E402
from web_decoy.telemetry.emitter import Emitter  # noqa: E402

BASELINE = "e3ad1bc"
OUTSIDE_IP = "203.0.113.10"
SAMPLE = REPO / "services/web/samples/web-attack-campaign.sample.jsonl"

REPLAY = r'''
import json, sys, uuid
from pathlib import Path
from fastapi.testclient import TestClient
import collector.app as soc
api = TestClient(soc.app, raise_server_exceptions=False)
sample =[json.loads(l) for l in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines() if l.strip()]
ts = "2026-10-31T12:00:00.000Z"
def db(i, **kw):
    return {"event_id": f"db-{i}", "timestamp": ts, "sensor_id": "db-01", "service": "database", "source_ip": "172.28.0.51",
            "destination_service": "database-honeypot", "event_type": "sql_query", "action": "sensitive_access", "outcome": "succeeded",
            "session_id": "s1", "command": "SELECT 1", "table_names": ["api_credentials"], "tags": ["db:x"],
            "raw_evidence_redacted": {"severity": "HIGH", "mitre": [{"technique": "T1552", "name": "n", "status": "observed"}],
                "detections": [{"rule": "D-SENS-01", "severity": "HIGH", "confidence": "high", "rationale": "r",
                                "attack": [{"technique": "T1552", "name": "n", "status": "observed"}]}]}, **kw}
adaptation = {"adaptation_id": "a1", "timestamp": ts, "sensor_id": "db-01", "service": "database", "rule_id": "B", "stage": 1,
              "trigger_event_id": "db-1", "trigger_reason": "r", "adaptation_type": "t", "asset_revealed": "api_credentials",
              "source_ip": "172.28.0.51", "tracker_key": "k", "target_account": "d@%", "status": "applied"}
beat = {"sensor_id": "db-01", "service": "database", "status": "ok", "details": {"sessions": [], "spool_pending": 0}}
J = {"content-type": "application/json"}
steps = []
def record(r): steps.append((r.status_code, r.text))
for i in range(0, len(sample), 50):
    record(api.post("/api/events", json=sample[i:i + 50]))
record(api.post("/api/events", json=sample[:3]))
record(api.post("/api/events", json=[db(1), db(2), db(3, source_ip="10.0.0.1", service="web", sensor_id="web-01", event_type="http_request")]))
record(api.post("/api/events", json=db(4)))
record(api.post("/api/events", json=[]))
record(api.post("/api/adaptations", json=[adaptation]))
record(api.post("/api/sensors/heartbeat", json=beat))
for bad in ([db(5, hacker=1)], [{"event_id": "x"}], [1], "x", [db(6) for _ in range(51)], [db(7, outcome="nope")],
            [db(8, timestamp="2026-10-31T12:00:00")]):
    record(api.post("/api/events", json=bad))
record(api.post("/api/events", content=b"not json", headers=J))
record(api.post("/api/events", content=b"", headers=J))
record(api.post("/api/sensors/heartbeat", json={"sensor_id": "x"}))
record(api.post("/api/sensors/heartbeat", json={**beat, "extra": 1}))
record(api.post("/api/adaptations", json=[{"adaptation_id": "x"}]))
record(api.post("/api/events", json=[db(9)], headers={"Authorization": "Bearer nonsense"}))
for path in ("/api/events?limit=1000", "/api/alerts", "/api/attackers", "/api/attackers/172.28.0.51", "/api/attackers/none",
             "/api/adaptations", "/api/database/summary", "/api/sensors", "/health", "/nothing"):
    record(api.get(path))
print(json.dumps(steps, sort_keys=True))
'''


def scrub(value: Any) -> Any:
    """Remove what changes on every run: random IDs and clock times."""
    if isinstance(value, dict):
        return {k: scrub(v) for k, v in value.items() if k not in ("alert_id", "last_seen", "age_seconds", "read_capped_at")}
    if isinstance(value, list):
        return [scrub(v) for v in value]
    return value


def replay(code_root: Path, folder: Path) -> Any:
    script = folder / "replay.py"
    script.write_text(REPLAY, encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(code_root), "COLLECTOR_DB_PATH": str(folder / "replay.db"), "PYTHONDONTWRITEBYTECODE": "1"}
    env.pop("SSH_INGEST_TOKEN_FILE", None)
    env.pop("SOC_READ_TOKEN_FILE", None)
    done = subprocess.run([sys.executable, "-W", "ignore", str(script), str(SAMPLE)], env=env, capture_output=True, text=True, timeout=120,
                          cwd=folder)
    assert done.returncode == 0, done.stderr[-2000:]
    steps = []
    for status, text in json.loads(done.stdout):
        try:
            steps.append((status, scrub(json.loads(text))))
        except ValueError:
            steps.append((status, text))
    return steps


def test_same_requests_get_the_same_answers_as_before(tmp_path: Path) -> None:
    # The baseline is a commit in the team repo (edWINpious/finaldj). Repos that imported the code
    # without that history (e.g. RugvedHinge1/PS4---DJS) cannot run this comparison: skip, don't fail.
    known = subprocess.run(["git", "-C", str(REPO), "cat-file", "-e", f"{BASELINE}^{{commit}}"], capture_output=True, timeout=30)
    if known.returncode != 0:
        pytest.skip(f"baseline commit {BASELINE} is not in this repository's history")
    exported = subprocess.run(["git", "-C", str(REPO), "archive", "--format=zip", BASELINE, "collector"], capture_output=True, timeout=60)
    assert exported.returncode == 0
    old = tmp_path / "old"
    zipfile.ZipFile(io.BytesIO(exported.stdout)).extractall(old)
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    before, after = replay(old, tmp_path / "a"), replay(REPO, tmp_path / "b")
    assert len(before) == len(after) > 25
    before = apply_alert_policy(before)
    # The three alert-derived reads come back in severity order; ties used last_seen, which scrub() removes.
    assert after[-9][1] == sorted(after[-9][1], key=lambda a: SEVERITY[a["severity"]])
    for index in ALERT_READS:
        _check_extra_evidence(before[index][1], after[index][1])
        before[index], after[index] = canonical(before[index]), canonical(after[index])
    for was, now in zip(before, after):
        assert was == now


# Deliberate alert-policy change (2026-11-01, collector/rules_catalog.py): single-occurrence signals
# are recorded on the event but no longer open alerts, and X-CORR-01 is a medium-severity,
# low-confidence hint. Everything else, every ingest answer included, must still match exactly.
NON_ALERTING = {"W-AUTH-01", "W-ENUM-01"}
# Threshold and correlation alerts now also link the earlier events that led to them, so their
# related_event_ids may grow; the old IDs must all still be there (checked in canonical()).
EXTRA_EVIDENCE = {"W-AUTH-02", "W-AUTH-03", "W-ENUM-02", "X-CORR-01"}
SEVERITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
ALERT_READS = (-9, -8, -7)  # /api/alerts, /api/attackers, /api/attackers/172.28.0.51


def _policy(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for a in alerts:
        if a["rule"] in NON_ALERTING:
            continue
        if a["rule"] == "X-CORR-01":
            a = {**a, "severity": "medium", "confidence": "low"}
        out.append(a)
    return out


def _highest(alerts: list[dict[str, Any]]) -> str | None:
    return min((a["severity"] for a in alerts), key=SEVERITY.__getitem__, default=None)


def apply_alert_policy(steps: list[Any]) -> list[Any]:
    steps = list(steps)
    status, alerts = steps[-9]
    alerts = _policy(alerts)
    steps[-9] = (status, alerts)
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for a in alerts:
        by_ip.setdefault(a["source_ip"], []).append(a)
    status, sources = steps[-8]
    steps[-8] = (status, [{**s, "alert_count": len(by_ip.get(s["source_ip"], [])),
                           "highest_severity": _highest(by_ip.get(s["source_ip"], []))} for s in sources])
    status, profile = steps[-7]
    kept = _policy(profile["alerts"])
    steps[-7] = (status, {**profile, "alerts": kept, "alert_count": len(kept), "highest_severity": _highest(kept)})
    return steps


def _alerts_in(body: Any) -> list[dict[str, Any]]:
    if isinstance(body, list):
        return [a for a in body if isinstance(a, dict) and "rule" in a]
    return [a for a in body.get("alerts", [])] if isinstance(body, dict) else []


def _check_extra_evidence(was: Any, now: Any) -> None:
    old = {a["rule"] + a["source_ip"]: set(a["related_event_ids"]) for a in _alerts_in(was) if a["rule"] in EXTRA_EVIDENCE}
    for a in _alerts_in(now):
        if a["rule"] in EXTRA_EVIDENCE and a["rule"] + a["source_ip"] in old:
            assert old[a["rule"] + a["source_ip"]] <= set(a["related_event_ids"])


def _strip(body: Any) -> Any:
    def one(a: Any) -> Any:
        return {k: v for k, v in a.items() if k != "related_event_ids"} if isinstance(a, dict) and a.get("rule") in EXTRA_EVIDENCE else a
    if isinstance(body, list):
        return [one(a) for a in body]
    if isinstance(body, dict) and isinstance(body.get("alerts"), list):
        return {**body, "alerts": [one(a) for a in body["alerts"]]}
    return body


def canonical(step: Any) -> Any:
    status, body = step
    body = _strip(body)
    key = lambda d: json.dumps(d, sort_keys=True)  # noqa: E731
    if isinstance(body, list):
        return status, sorted(body, key=key)
    if isinstance(body, dict) and isinstance(body.get("alerts"), list):
        return status, {**body, "alerts": sorted(body["alerts"], key=key)}
    return status, body


def wait_for(check: Any, seconds: float = 8.0) -> bool:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return True
        time.sleep(0.05)
    return False


def test_real_web_emitter_delivers_with_no_token(tmp_path: Path) -> None:
    """Hostile paths stay normal Web events, including the one that mentions .ssh."""
    with real_collector(tmp_path) as server:
        settings = Settings(collector_url=f"http://127.0.0.1:{server.port}/api/events", event_log_path=str(tmp_path / "events.jsonl"),
                            spool_path=str(tmp_path / "spool.jsonl"), flush_interval_s=0.05)
        emitter = Emitter(settings)
        with TestClient(create_app(settings, emitter=emitter), client=(OUTSIDE_IP, 1), follow_redirects=False) as decoy:
            for path in ("/.ssh/id_rsa", "/.env", "/ssh-01", "/?a=../../ssh-honeypot"):
                decoy.get(path, headers={"User-Agent": "ssh-01 cowrie"})
            assert wait_for(lambda: emitter.delivered_events >= 4)
        assert emitter.spooled_events == 0 and emitter.dropped_events == 0
        stored = json.loads(server.read(b"/api/events?limit=100")[1])
        assert len(stored) == 4 and {e["service"] for e in stored} == {"web"}
        assert any(e["request_path"] == "/.ssh/id_rsa" for e in stored)


def every_web_label_is_clear_of_ssh() -> None:
    from web_decoy.detection import mappings

    words = [str(v) for rule in vars(mappings).values() if isinstance(rule, dict)
             for entry in rule.values() if isinstance(entry, dict) for k, v in entry.items() if k in ("label", "rule")]
    words += [str(k) for rule in vars(mappings).values() if isinstance(rule, dict) for k in rule]
    assert words and not any(word.lower().replace("-", "").replace("_", "").startswith("ssh") for word in words)


def test_web_vocabulary_can_never_look_like_an_ssh_claim() -> None:
    every_web_label_is_clear_of_ssh()


def database_event(i: int, **change: Any) -> dict[str, Any]:
    return {"event_id": f"db-{i:06d}", "timestamp": TIMESTAMP, "sensor_id": "db-01", "service": "database", "source_ip": "172.28.0.51",
            "source_port": None, "destination_service": "database-honeypot", "event_type": "sql_query", "action": "restricted_access",
            "outcome": "blocked", "username": "decoy_user", "session_id": "db-01-1793000000-1", "tags": ["db:restricted_access"],
            "raw_evidence_redacted": {"source": "database-honeypot", "severity": "HIGH", "detections": []}, **change}


def sender(folder: Path, port: int, name: str) -> DurableSender:
    home = folder / name
    home.mkdir()
    return DurableSender(f"http://127.0.0.1:{port}/api/events", home / "events.jsonl", home / "spool.jsonl", 50, 10.0, 1 << 30)


def test_real_database_sender_delivers_with_no_token(tmp_path: Path) -> None:
    with real_collector(tmp_path) as server:
        delivery = sender(tmp_path, server.port, "normal")
        for i in range(120):
            delivery.add(database_event(i))
        delivery.flush()
        assert delivery.delivered == 120 and delivery.spool_depth() == 0


def test_largest_real_database_batch_passes(tmp_path: Path) -> None:
    """Real classifier, 64 KiB statements, 13,000 tables each, hostile characters kept in the text."""
    rules = load_rules(str(REPO / "services/database/sensor/config/rules.json"))
    names = ["".join(chr(97 + (i // 26 ** p) % 26) for p in range(4)) for i in range(13_100)]
    statement = "SELECT '[{,' FROM " + ",".join(names)
    tables = classify(statement, 1142, "transnova_logistics", rules).tables
    assert len(tables) == 13_100
    with real_collector(tmp_path) as server:
        delivery = sender(tmp_path, server.port, "largest")
        for i in range(50):
            delivery.add(database_event(i, command=statement[:2048], table_names=tables))
        delivery.flush()
        assert delivery.delivered == 50 and delivery.spool_depth() == 0


def test_a_batch_of_text_full_of_brackets_passes(tmp_path: Path) -> None:
    with real_collector(tmp_path) as server:
        delivery = sender(tmp_path, server.port, "brackets")
        for i in range(50):
            delivery.add(database_event(i, command="[{," * 682, table_names=["[{,"] * 20_000))
        delivery.flush()
        assert delivery.delivered == 50 and delivery.spool_depth() == 0


def test_a_refused_database_batch_blocks_all_later_events(tmp_path: Path) -> None:
    """A known limit of the Database sender, kept visible on purpose: it retries the head of its
    queue forever, so one refused batch stops all later telemetry until a person steps in. Nothing
    is lost, but this is why no collector limit may ever refuse a real batch."""
    with real_collector(tmp_path) as server:
        delivery = sender(tmp_path, server.port, "blocked")
        for i in range(50):
            delivery.add(database_event(i, raw_evidence_redacted={"padding": "x" * (400 << 10)}))
        delivery.flush()
        for i in range(3):
            delivery.add(database_event(1000 + i))
        for _ in range(3):
            delivery._retry_at = 0
            delivery.flush()
        assert delivery.delivered == 0 and delivery.spool_depth() == 53
        assert sum(1 for _ in open(delivery.log_path, encoding="ascii")) == 53


def test_database_heartbeats_and_adaptations_work_with_no_token(tmp_path: Path) -> None:
    profile = SessionProfile("s", "172.28.0.51", "decoy_user", 1, TIMESTAMP, TIMESTAMP, tables=["internal_network_assets"] * 31)
    heavy = {"sensor_id": "db-01", "service": "database", "status": "ok",
             "details": {"database_reachable": True, "sessions": [asdict(profile)] * 50}}
    record = {"adaptation_id": "a", "timestamp": TIMESTAMP, "sensor_id": "db-01", "service": "database", "rule_id": "B", "stage": 1,
              "trigger_event_id": "e", "trigger_reason": "r", "adaptation_type": "t", "asset_revealed": "a", "source_ip": "x",
              "tracker_key": "k", "target_account": "d", "status": "applied"}
    with real_collector(tmp_path) as server:
        base = f"http://127.0.0.1:{server.port}"
        assert httpx.post(f"{base}/api/sensors/heartbeat", json=heavy, trust_env=False).status_code == 200
        assert httpx.post(f"{base}/api/adaptations", json=[record], trust_env=False).status_code == 200


def test_broken_token_files_leave_web_and_database_working(tmp_path: Path) -> None:
    settings = write_tokens(tmp_path)[2]
    Path(settings["SSH_INGEST_TOKEN_FILE"]).unlink()
    Path(settings["SOC_READ_TOKEN_FILE"]).write_bytes(b"")
    with real_collector(tmp_path, env=settings) as server:
        delivery = sender(tmp_path, server.port, "broken")
        delivery.add(database_event(1))
        delivery.flush()
        assert delivery.delivered == 1
        assert server.talk(b"POST /api/events HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n"
                           % len(body := json.dumps([web_event("w")]).encode()) + body)[0] == ["200"]
