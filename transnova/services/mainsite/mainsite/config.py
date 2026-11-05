"""Environment-driven settings for the public site."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

DEFAULT_BLOCK = ("tor", "vpn", "hosting")


@dataclass(frozen=True)
class Settings:
    # Where the partner portal (the honeypot) lives. Shown only through the "leaks" an
    # attacker would find: footer link, /admin redirect, robots.txt, an HTML comment, site.js.
    portal_url: str = "http://partners.transnova-logistics.example"
    # Anonymizer categories refused with 403. Empty = block nothing.
    block_categories: tuple[str, ...] = DEFAULT_BLOCK
    anon_data_dir: str = ""
    access_log_path: str = "data/mainsite-blocked.jsonl"
    max_body_bytes: int = 16 * 1024
    # SOC blocklist feed (USP 1): the collector's POST /api/blocklist/feed and the web ingest token.
    blocklist_url: str = ""
    blocklist_token: str = field(default="", repr=False)
    blocklist_poll_s: float = 5.0

    @classmethod
    def from_env(cls) -> "Settings":
        env = os.environ
        d = cls()
        raw = env.get("ANON_BLOCK")
        block = d.block_categories if raw is None else tuple(
            c.strip().lower() for c in raw.split(",") if c.strip().lower() in DEFAULT_BLOCK)
        return cls(
            portal_url=env.get("PORTAL_URL", d.portal_url).rstrip("/"),
            block_categories=block,
            anon_data_dir=env.get("ANON_DATA_DIR", d.anon_data_dir),
            access_log_path=env.get("MAINSITE_LOG_PATH", d.access_log_path),
            blocklist_url=env.get("BLOCKLIST_URL", d.blocklist_url).strip(),
            blocklist_token=env.get("BLOCKLIST_TOKEN", env.get("COLLECTOR_TOKEN", "")).strip(),
            blocklist_poll_s=max(1.0, float(env.get("BLOCKLIST_POLL_S", d.blocklist_poll_s))),
        )
