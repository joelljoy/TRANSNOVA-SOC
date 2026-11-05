"""Download fresh Tor-exit, VPN and hosting lists into services/anonintel/data/.

Run this on a machine WITH internet before the demo (the main site and the web decoy read
the files; neither downloads anything itself). Both pick up new files within ~30 s.

    python scripts/refresh_anon_lists.py

Every line is validated as an IP or CIDR before it is written; a download that fails or
looks wrong (too small / too big) keeps the previous file. Standard library only.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("ANON_DATA_DIR") or ROOT / "services/anonintel/data")

SOURCES = {
    "tor_exits.txt": [
        "https://check.torproject.org/torbulkexitlist",  # official
        "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst",
    ],
    "vpn_ipv4.txt": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/vpn/ipv4.txt"],
    "datacenter_ipv4.txt": ["https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output/datacenter/ipv4.txt"],
}
MIN_ENTRIES = {"tor_exits.txt": 300, "vpn_ipv4.txt": 1000, "datacenter_ipv4.txt": 5000}
MAX_BYTES = 16 * 1024 * 1024


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "transnova-anon-refresh/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 (fixed https URLs above)
        data = resp.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response too large")
    return data.decode("utf-8", "replace")


def validate(text: str) -> list[str]:
    out = []
    for line in text.splitlines():
        token = line.split("#", 1)[0].strip()
        if not token:
            continue
        try:
            out.append(str(ipaddress.ip_network(token, strict=False)))
        except ValueError:
            continue
    return out


def main() -> int:
    DATA.mkdir(parents=True, exist_ok=True)
    meta_path = DATA / "META.json"
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        meta = {}
    meta.setdefault("sources", {})
    ok_all = True
    for name, urls in SOURCES.items():
        for url in urls:
            try:
                entries = validate(fetch(url))
            except Exception as exc:  # noqa: BLE001 - report and try the next mirror
                print(f"  {name}: {url} failed ({exc.__class__.__name__})")
                continue
            if len(entries) < MIN_ENTRIES[name]:
                print(f"  {name}: {url} returned only {len(entries)} entries; ignored")
                continue
            tmp = DATA / (name + ".tmp")
            tmp.write_text("\n".join(entries) + "\n", encoding="utf-8")
            os.replace(tmp, DATA / name)
            meta["sources"][name] = {"url": url, "entries": len(entries)}
            print(f"updated {name}: {len(entries)} entries from {url}")
            break
        else:
            ok_all = False
            print(f"KEPT old {name} (every source failed)")
    meta["fetched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
