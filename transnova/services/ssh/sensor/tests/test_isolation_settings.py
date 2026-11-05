"""Guard the project rules this component must keep: no tried passwords, no SOC link yet."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

from cowrie_soc.config import NormalizeSection, load_config

SSH_ROOT = Path(__file__).parents[2]
SCRIPT = SSH_ROOT / "cowrie" / "harden_cowrie.py"
REDACTOR = SSH_ROOT / "cowrie" / "soc_redact.py"
COMPOSE = SSH_ROOT / "docker-compose.isolated.yml"
CHECKERS = """\
events.dispatch(
    "cowrie.login.success",
    "login attempt [%(username)s/%(password)s] succeeded",
                    username=escape_nonprintable(theusername),
                    password=escape_nonprintable(thepassword),
)
events.dispatch(
    "cowrie.login.failed",
    "login attempt [%(username)s/%(password)s] failed",
                username=escape_nonprintable(theusername),
                password=escape_nonprintable(thepassword),
)
"""
EVENTS = """\
from cowrie.core.output import convert

def dispatch(self, event):
        ev: dict[str, Any] = convert(event)
"""
LOGFILE = """\
def stdoutLogger() -> Callable[[dict], None]:
    return _observer(sys.stdout)
"""
SOURCES = {"core/checkers.py": CHECKERS, "core/events.py": EVENTS, "python/logfile.py": LOGFILE}


def hardener() -> ModuleType:
    spec = importlib.util.spec_from_file_location("harden_cowrie", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree(root: Path, sources: dict[str, str]) -> dict[str, str]:
    """Write a fake Cowrie source tree and return pins that match it."""
    for rel, text in sources.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(text.encode("utf-8"))
    return {rel: hashlib.sha256(text.encode("utf-8")).hexdigest() for rel, text in sources.items()}


def test_shipped_config_keeps_passwords_out_and_delivery_off() -> None:
    cfg = load_config(SSH_ROOT / "sensor" / "config" / "collector.toml", env={})
    assert cfg.collector.sensor_id == "ssh-01"
    assert cfg.normalize.include_passwords is False
    assert cfg.http.enabled is False


def test_password_capture_is_off_when_the_setting_is_missing() -> None:
    assert NormalizeSection().include_passwords is False


def test_cowrie_settings() -> None:
    text = (SSH_ROOT / "cowrie" / "cowrie.cfg").read_text(encoding="utf-8")
    assert "sensor_name = ssh-01\n" in text and "ttylog = false\n" in text


def test_every_patch_is_applied(tmp_path: Path) -> None:
    pins = tree(tmp_path / "src", SOURCES)
    hardener().harden(tmp_path / "src", tmp_path / "out", REDACTOR, pins)
    checkers = (tmp_path / "out/core/checkers.py").read_text(encoding="utf-8")
    assert "password" not in checkers and checkers.count("escape_nonprintable(theusername)") == 2
    events = (tmp_path / "out/core/events.py").read_text(encoding="utf-8")
    assert "sanitize_event(convert(event), keep_format=True)" in events
    logfile = (tmp_path / "out/python/logfile.py").read_text(encoding="utf-8")
    assert "_observer(sys.stdout)" not in logfile and "return _metadata_observer()" in logfile
    assert (tmp_path / "out/core/soc_redact.py").read_bytes() == REDACTOR.read_bytes()


@pytest.mark.parametrize("rel", sorted(SOURCES))
def test_any_change_to_upstream_source_fails_with_no_output(tmp_path: Path, rel: str) -> None:
    pins = tree(tmp_path / "src", SOURCES)
    (tmp_path / "src" / rel).write_bytes(SOURCES[rel].encode("utf-8") + b"# changed\n")
    with pytest.raises(SystemExit):
        hardener().harden(tmp_path / "src", tmp_path / "out", REDACTOR, pins)
    assert not (tmp_path / "out").exists()


@pytest.mark.parametrize(("rel", "broken"), [
    ("core/checkers.py", CHECKERS.replace("                password=escape_nonprintable(thepassword),\n", "")),
    ("core/checkers.py", CHECKERS + 'log("%(password)s")\n'),
    ("core/events.py", EVENTS.replace("convert(event)", "other(event)")),
    ("python/logfile.py", LOGFILE.replace("_observer(sys.stdout)", "_observer(out)")),
])
def test_unexpected_code_fails_with_no_output_even_if_the_hash_matches(tmp_path: Path, rel: str, broken: str) -> None:
    pins = tree(tmp_path / "src", {**SOURCES, rel: broken})
    with pytest.raises(SystemExit):
        hardener().harden(tmp_path / "src", tmp_path / "out", REDACTOR, pins)
    assert not (tmp_path / "out").exists()


def test_pins_cover_every_patched_file() -> None:
    module = hardener()
    assert set(module.PINS) == set(module.EDITS)


def test_isolated_compose_has_no_soc_link_or_published_port() -> None:
    text = COMPOSE.read_text(encoding="utf-8")
    services = text.split("\nservices:\n", 1)[1]
    for forbidden in ("COWRIE_SOC_HTTP", "SOC_INGEST", "http://", "ports:", "lab_net", "ingest_net", "soc_edge"):
        assert forbidden not in services
    assert "network_mode: none" in services
    assert "internal: true" in text
    assert "com.docker.network.bridge.inhibit_ipv4" in text


def test_isolated_compose_stores_no_attacker_input_outside_clean_logs() -> None:
    honeypot = COMPOSE.read_text(encoding="utf-8").split("  ssh-sensor:\n", 1)[0]
    assert "/cowrie/cowrie-git/var/lib/cowrie/downloads:size=16m" in honeypot
    assert "driver: none" in honeypot
