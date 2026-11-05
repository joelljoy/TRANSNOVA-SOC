"""Environment-driven configuration for the database sensor. No secret has a default."""

from __future__ import annotations

import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "config" / "rules.json"


def _accounts(raw: str) -> frozenset[tuple[str, str]]:
    out = set()
    for item in raw.split(","):
        item = item.strip()
        if item:
            user, _, host = item.partition("@")
            out.add((user, host))
    return frozenset(out)


@dataclass(frozen=True)
class Settings:
    sensor_id: str = "db-01"
    audit_log_path: str = "/var/log/mysql/server_audit.log"
    data_dir: str = "/data"
    collector_url: str = "http://collector:8000"
    rules_path: str = str(DEFAULT_RULES)
    poll_interval_s: float = 0.5
    heartbeat_interval_s: float = 15.0
    post_timeout_s: float = 3.0
    batch_size: int = 50  # the collector contract: at most 50 events per POST
    max_query_chars: int = 2048
    max_log_bytes: int = 50 * 1024 * 1024

    db_host: str = "database-honeypot"
    db_port: int = 3306
    db_name: str = "transnova_logistics"
    controller_user: str = "deception_ctrl"
    controller_password: str = ""
    attacker_account: str = "decoy_user"
    attacker_host: str = "%"
    destination_ip: str | None = None
    # Accounts whose activity is our own. Matched on user AND client host together, so an
    # attacker who logs in under one of these names from anywhere else is still reported.
    internal_accounts: frozenset[tuple[str, str]] = frozenset()
    simulator_cidrs: tuple[str, ...] = ("172.28.0.50/32",)
    adaptive_enabled: bool = True

    @classmethod
    def from_env(cls) -> "Settings":
        e, d = os.environ, cls()
        return cls(
            sensor_id=e.get("SENSOR_ID", d.sensor_id),
            audit_log_path=e.get("AUDIT_LOG_PATH", d.audit_log_path),
            data_dir=e.get("SENSOR_DATA_DIR", d.data_dir),
            collector_url=e.get("COLLECTOR_BASE_URL", d.collector_url).rstrip("/"),
            rules_path=e.get("RULES_PATH", d.rules_path),
            poll_interval_s=float(e.get("POLL_INTERVAL_S", d.poll_interval_s)),
            db_host=e.get("DB_HOST", d.db_host),
            db_port=int(e.get("DB_PORT", d.db_port)),
            db_name=e.get("DB_NAME", d.db_name),
            controller_user=e.get("CONTROLLER_DB_USER", d.controller_user),
            controller_password=e.get("CONTROLLER_DB_PASSWORD", ""),
            attacker_account=e.get("ATTACKER_DB_USER", d.attacker_account),
            destination_ip=e.get("DB_DESTINATION_IP") or None,
            internal_accounts=_accounts(e.get(
                "INTERNAL_ACCOUNTS",
                "deception_ctrl@172.29.0.21,root@localhost,healthcheck@localhost,mariadb.sys@localhost,boot@")),
            simulator_cidrs=tuple(c.strip() for c in e.get("SIMULATOR_SOURCE_CIDRS", "172.28.0.50/32").split(",")
                                  if c.strip()),
            adaptive_enabled=e.get("ADAPTIVE_ENABLED", "1").lower() in ("1", "true", "yes", "on"),
        )


def load_rules(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        rules = json.load(fh)
    allowed = set(rules["adaptive_tables"])
    for rule in rules["adaptive_rules"]:
        unknown = set(rule["reveal"]) - allowed
        if unknown:
            raise ValueError(f"rule {rule['id']} reveals tables outside adaptive_tables: {sorted(unknown)}")
    return rules


def ip_in(host: str | None, cidrs: tuple[str, ...]) -> bool:
    try:
        addr = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
