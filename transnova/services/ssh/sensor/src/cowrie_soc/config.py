"""Collector configuration: TOML file + a few environment overrides.

Environment variables (override the file; used by docker-compose):
  COWRIE_SOC_SENSOR_ID   sensor id stamped on every record
  COWRIE_SOC_LOG_DIR     directory containing cowrie.json
  COWRIE_SOC_STATE_DB    SQLite state path
  COWRIE_SOC_HTTP_URL    if non-empty, enables the HTTP sink with this URL
  COWRIE_SOC_HTTP_TOKEN  bearer token for the HTTP sink (read at send time, never logged)
  COWRIE_SOC_HTTP_TOKEN_FILE  file holding the bearer token, preferred over the variable
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


MAX_COLLECTOR_BATCH = 50  # collector/app.py returns 413 above this


class ConfigError(ValueError):
    pass


@dataclass
class SourceConfig:
    log_dir: str = "/data/cowrie-logs"
    base_name: str = "cowrie.json"
    start_position: str = "beginning"
    poll_interval_seconds: float = 1.0
    max_line_bytes: int = 1 << 20
    batch_max_lines: int = 500


@dataclass
class CollectorConfig:
    sensor_id: str = "ssh-01"
    state_db: str = "/data/state/collector.db"
    max_pending_records: int = 100_000
    retain_delivered_records: int = 20_000
    max_soc_pending: int = 100_000
    scenario_id: str = ""


@dataclass
class NormalizeSection:
    include_passwords: bool = False
    max_field_chars: int = 4096


@dataclass
class JsonlSinkConfig:
    enabled: bool = True
    path: str = "/data/state/normalized.jsonl"
    max_bytes: int = 50 * 1024 * 1024


@dataclass
class HttpSinkConfig:
    enabled: bool = False
    url: str = ""
    token_env: str = "COWRIE_SOC_HTTP_TOKEN"
    token_file: str = ""
    timeout_seconds: float = 5.0
    batch_size: int = 50
    payload_format: str = "array"
    verify_tls: bool = True
    field_map: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    source: SourceConfig = field(default_factory=SourceConfig)
    collector: CollectorConfig = field(default_factory=CollectorConfig)
    normalize: NormalizeSection = field(default_factory=NormalizeSection)
    jsonl: JsonlSinkConfig = field(default_factory=JsonlSinkConfig)
    http: HttpSinkConfig = field(default_factory=HttpSinkConfig)
    detection: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_homes: dict[str, str] = field(default_factory=dict)


def _fill(target: Any, values: dict[str, Any], section: str) -> None:
    for key, value in values.items():
        if not hasattr(target, key):
            raise ConfigError(f"[{section}] unknown key {key!r}")
        current = getattr(target, key)
        if isinstance(current, bool) and not isinstance(value, bool):
            raise ConfigError(f"[{section}] {key} must be true/false")
        if isinstance(current, (int, float)) and not isinstance(current, bool):
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise ConfigError(f"[{section}] {key} must be a number")
        if isinstance(current, str) and not isinstance(value, str):
            raise ConfigError(f"[{section}] {key} must be a string")
        setattr(target, key, value)


def load_config(path: str | Path | None = None, env: dict[str, str] | None = None) -> Config:
    env = dict(os.environ if env is None else env)
    cfg = Config()
    data: dict[str, Any] = {}
    if path is not None:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)

    known = {"source", "collector", "normalize", "sinks", "detection", "user_homes"}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"unknown config sections: {sorted(unknown)}")
    _fill(cfg.source, data.get("source", {}), "source")
    _fill(cfg.collector, data.get("collector", {}), "collector")
    _fill(cfg.normalize, data.get("normalize", {}), "normalize")
    sinks = data.get("sinks", {})
    if set(sinks) - {"jsonl", "http"}:
        raise ConfigError(f"unknown sinks: {sorted(set(sinks) - {'jsonl', 'http'})}")
    _fill(cfg.jsonl, sinks.get("jsonl", {}), "sinks.jsonl")
    _fill(cfg.http, sinks.get("http", {}), "sinks.http")
    cfg.detection = {k: dict(v) for k, v in data.get("detection", {}).items()}
    cfg.user_homes = {str(k): str(v) for k, v in data.get("user_homes", {}).items()}

    if env.get("COWRIE_SOC_SENSOR_ID"):
        cfg.collector.sensor_id = env["COWRIE_SOC_SENSOR_ID"]
    if env.get("COWRIE_SOC_LOG_DIR"):
        cfg.source.log_dir = env["COWRIE_SOC_LOG_DIR"]
    if env.get("COWRIE_SOC_STATE_DB"):
        cfg.collector.state_db = env["COWRIE_SOC_STATE_DB"]
    if env.get("COWRIE_SOC_HTTP_URL"):
        cfg.http.url = env["COWRIE_SOC_HTTP_URL"]
        cfg.http.enabled = True
    if env.get("COWRIE_SOC_HTTP_TOKEN_FILE"):
        cfg.http.token_file = env["COWRIE_SOC_HTTP_TOKEN_FILE"]

    _validate(cfg)
    return cfg


def _validate(cfg: Config) -> None:
    if cfg.source.start_position not in ("beginning", "end"):
        raise ConfigError("[source] start_position must be 'beginning' or 'end'")
    if cfg.source.poll_interval_seconds <= 0 or cfg.source.batch_max_lines <= 0:
        raise ConfigError("[source] poll_interval_seconds and batch_max_lines must be positive")
    if cfg.source.max_line_bytes < 1024:
        raise ConfigError("[source] max_line_bytes must be >= 1024")
    if cfg.collector.max_pending_records <= 0:
        raise ConfigError("[collector] max_pending_records must be positive")
    if not cfg.collector.sensor_id:
        raise ConfigError("[collector] sensor_id must not be empty")
    if cfg.http.enabled:
        if not cfg.http.url.startswith(("http://", "https://")):
            raise ConfigError("[sinks.http] enabled but url is not an http(s) URL")
        if cfg.http.payload_format != "array" or cfg.http.field_map:
            raise ConfigError("[sinks.http] the collector takes a plain array: payload_format 'array', no field_map")
        if not 1 <= cfg.http.batch_size <= MAX_COLLECTOR_BATCH:
            raise ConfigError(f"[sinks.http] batch_size must be 1 to {MAX_COLLECTOR_BATCH}")
    if not cfg.jsonl.enabled and not cfg.http.enabled:
        raise ConfigError("no sink enabled: enable [sinks.jsonl] and/or [sinks.http]")
