"""Console settings from the environment. Secrets are file paths, never values, and none reach the browser.

Required: COLLECTOR_BASE_URL, SOC_READ_TOKEN_FILE, SOC_CONSOLE_TOKEN_FILE, SOC_USERS_FILE.
Optional: ANTHROPIC_API_KEY or ANTHROPIC_API_KEY_FILE (AI explanations stay off without it),
SOC_AI_MODEL, SOC_COOKIE_SECURE, SOC_SESSION_IDLE_MIN, SOC_SESSION_MAX_HOURS, SOC_FRONTEND_DIR.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class ConfigError(RuntimeError):
    pass


def _flag(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    return default if value is None else value.strip().lower() in ("1", "true", "yes", "on")


def _read_secret_file(path: str | None) -> str | None:
    if not path:
        return None
    try:
        return Path(path).read_text(encoding="utf-8").strip() or None
    except OSError:
        return None


@dataclass(frozen=True)
class Settings:
    collector_url: str
    read_token_file: str
    console_token_file: str
    users_file: str
    frontend_dir: Path
    cookie_secure: bool
    idle_minutes: int
    max_hours: int
    ai_model: str
    ai_key_file: str | None

    @property
    def anthropic_key(self) -> str | None:
        return os.environ.get("ANTHROPIC_API_KEY") or _read_secret_file(self.ai_key_file)

    def problems(self) -> list[str]:
        """What is missing, by name only. Values are never echoed."""
        out = []
        for label, path in (("SOC_READ_TOKEN_FILE", self.read_token_file),
                            ("SOC_CONSOLE_TOKEN_FILE", self.console_token_file), ("SOC_USERS_FILE", self.users_file)):
            if not path or not Path(path).is_file():
                out.append(f"{label} is not set or does not point to a readable file")
        return out


def load() -> Settings:
    url = os.environ.get("COLLECTOR_BASE_URL", "").rstrip("/")
    if not url:
        raise ConfigError("COLLECTOR_BASE_URL is required")
    settings = Settings(
        collector_url=url,
        read_token_file=os.environ.get("SOC_READ_TOKEN_FILE", ""),
        console_token_file=os.environ.get("SOC_CONSOLE_TOKEN_FILE", ""),
        users_file=os.environ.get("SOC_USERS_FILE", ""),
        frontend_dir=Path(os.environ.get("SOC_FRONTEND_DIR", Path(__file__).resolve().parents[1] / "frontend" / "dist")),
        cookie_secure=_flag("SOC_COOKIE_SECURE", False),
        idle_minutes=int(os.environ.get("SOC_SESSION_IDLE_MIN", "30")),
        max_hours=int(os.environ.get("SOC_SESSION_MAX_HOURS", "8")),
        ai_model=os.environ.get("SOC_AI_MODEL", "claude-opus-5-5"),
        ai_key_file=os.environ.get("ANTHROPIC_API_KEY_FILE"),
    )
    problems = settings.problems()
    if problems:
        raise ConfigError("; ".join(problems))
    return settings
