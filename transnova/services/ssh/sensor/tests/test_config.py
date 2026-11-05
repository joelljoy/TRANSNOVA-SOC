from __future__ import annotations

from pathlib import Path

import pytest

from cowrie_soc.config import ConfigError, load_config

from .conftest import CONFIG_FILE


def test_shipped_config_loads_with_safe_defaults() -> None:
    cfg = load_config(CONFIG_FILE, env={})
    assert cfg.http.enabled is False  # no backend is assumed
    assert cfg.jsonl.enabled is True
    assert "/var/backups/db/.my.cnf" in cfg.detection["ssh_credential_access"]["honeytoken_paths"]


def test_env_overrides_enable_http(tmp_path: Path) -> None:
    cfg = load_config(CONFIG_FILE, env={"COWRIE_SOC_HTTP_URL": "http://10.10.0.20:9000/x",
                                        "COWRIE_SOC_SENSOR_ID": "cowrie-lab-2"})
    assert cfg.http.enabled and cfg.http.url == "http://10.10.0.20:9000/x"
    assert cfg.collector.sensor_id == "cowrie-lab-2"


@pytest.mark.parametrize(
    "toml",
    [
        "[sorce]\nlog_dir='x'\n",
        "[source]\nlogdir='x'\n",
        "[source]\nstart_position='middle'\n",
        "[source]\npoll_interval_seconds='fast'\n",
        "[sinks.http]\nenabled=true\nurl='ftp://x'\n",
        "[sinks.jsonl]\nenabled=false\n",
        "[sinks.kafka]\nenabled=true\n",
    ],
)
def test_invalid_configs_rejected(tmp_path: Path, toml: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(toml)
    with pytest.raises(ConfigError):
        load_config(path, env={})
