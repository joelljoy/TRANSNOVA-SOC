"""Anonymizer lookup: is this IP a Tor exit, a known VPN range, or a hosting/datacenter range?

Standard library only. It never makes a network call: it reads list files from a data
folder that `scripts/refresh_anon_lists.py` downloads ahead of time (the web decoy runs
with no internet). Files are re-read automatically when they change on disk.

Data folder (``ANON_DATA_DIR``, default ``./data`` next to this file):

    tor_exits.txt        one IP per line (Tor Project bulk exit list)
    vpn_ipv4.txt         CIDRs of commercial VPN providers (X4BNet lists_vpn)
    datacenter_ipv4.txt  CIDRs of hosting / cloud providers (X4BNet lists_vpn)
    demo.txt             optional, hand-written: "<ip-or-cidr> <tor|vpn|hosting>" per line,
                         to rehearse on a LAN where nobody really uses Tor
    META.json            when and from where the lists were fetched

Honest limits (also in docs/TOR_VPN.md):
- Tor exits are public, so Tor detection is strong for exits on the list at fetch time.
- VPN and hosting detection is best effort: a new or residential VPN, a private proxy or
  a friend's machine will not be on any list.
- Private, loopback and link-local addresses are never matched except through demo.txt.
"""

from __future__ import annotations

import bisect
import ipaddress
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path

CATEGORIES = ("tor", "vpn", "hosting")
# Priority when an address is on several lists: Tor is the most specific claim.
_PRIORITY = {"tor": 0, "vpn": 1, "hosting": 2}
_FILES = {"tor_exits.txt": ("tor", "tor_exit_list"),
          "vpn_ipv4.txt": ("vpn", "x4b_vpn"),
          "datacenter_ipv4.txt": ("hosting", "x4b_datacenter")}
MAX_LINES = 500_000          # a corrupted or hostile list file cannot exhaust memory
MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Verdict:
    category: str            # "tor" | "vpn" | "hosting"
    source: str              # which list matched: tor_exit_list, x4b_vpn, x4b_datacenter, demo
    list_date: str | None    # when the lists were fetched (META.json), if known

    def as_dict(self) -> dict[str, str | None]:
        return {"category": self.category, "source": self.source, "list_date": self.list_date}


class _Ranges:
    """Sorted, merged integer ranges per IP version, searched with bisect."""

    def __init__(self) -> None:
        self.starts: dict[int, list[int]] = {4: [], 6: []}
        self.ends: dict[int, list[int]] = {4: [], 6: []}

    @classmethod
    def build(cls, nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> "_Ranges":
        r = cls()
        for version in (4, 6):
            spans = sorted((int(n.network_address), int(n.broadcast_address))
                           for n in nets if n.version == version)
            merged: list[list[int]] = []
            for s, e in spans:
                if merged and s <= merged[-1][1] + 1:
                    merged[-1][1] = max(merged[-1][1], e)
                else:
                    merged.append([s, e])
            r.starts[version] = [s for s, _ in merged]
            r.ends[version] = [e for _, e in merged]
        return r

    def __contains__(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        v, n = ip.version, int(ip)
        i = bisect.bisect_right(self.starts[v], n) - 1
        return i >= 0 and n <= self.ends[v][i]

    def __len__(self) -> int:
        return len(self.starts[4]) + len(self.starts[6])


def _parse_net(token: str):
    try:
        return ipaddress.ip_network(token.strip(), strict=False)
    except ValueError:
        return None


def _read_lines(path: Path) -> list[str]:
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        return []
    out = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= MAX_LINES:
                break
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(line)
    return out


class AnonIntel:
    def __init__(self, data_dir: str | os.PathLike | None = None, recheck_s: float = 30.0) -> None:
        default = Path(__file__).resolve().parent / "data"
        self.data_dir = Path(data_dir or os.environ.get("ANON_DATA_DIR") or default)
        self.recheck_s = recheck_s
        self._lock = threading.Lock()
        self._sig: tuple = ()
        self._checked = 0.0
        self._lists: list[tuple[str, str, _Ranges]] = []   # (category, source, ranges)
        self.list_date: str | None = None
        self.counts: dict[str, int] = {}
        self._maybe_reload(force=True)

    # -- loading ------------------------------------------------------------------
    def _signature(self) -> tuple:
        sig = []
        for name in (*_FILES, "demo.txt", "META.json"):
            p = self.data_dir / name
            try:
                st = p.stat()
                sig.append((name, st.st_mtime_ns, st.st_size))
            except OSError:
                sig.append((name, None, None))
        return tuple(sig)

    def _maybe_reload(self, force: bool = False) -> None:
        now = time.monotonic()
        if not force and now - self._checked < self.recheck_s:
            return
        with self._lock:
            self._checked = now
            sig = self._signature()
            if sig == self._sig and not force:
                return
            lists: list[tuple[str, str, _Ranges]] = []
            counts: dict[str, int] = {}
            for name, (category, source) in _FILES.items():
                nets = [n for n in map(_parse_net, _read_lines(self.data_dir / name)) if n is not None]
                lists.append((category, source, _Ranges.build(nets)))
                counts[source] = len(nets)
            demo: dict[str, list] = {c: [] for c in CATEGORIES}
            for line in _read_lines(self.data_dir / "demo.txt"):
                parts = line.split()
                if len(parts) == 2 and parts[1].lower() in CATEGORIES:
                    net = _parse_net(parts[0])
                    if net is not None:
                        demo[parts[1].lower()].append(net)
            for category in CATEGORIES:
                if demo[category]:
                    lists.insert(0, (category, "demo", _Ranges.build(demo[category])))
            counts["demo"] = sum(len(v) for v in demo.values())
            lists.sort(key=lambda t: (t[1] != "demo", _PRIORITY[t[0]]))
            date = None
            try:
                meta = json.loads((self.data_dir / "META.json").read_text(encoding="utf-8"))
                date = str(meta.get("fetched_at"))[:40] if isinstance(meta, dict) else None
            except (OSError, ValueError):
                pass
            self._lists, self.counts, self.list_date, self._sig = lists, counts, date, sig

    # -- lookup -------------------------------------------------------------------
    def classify(self, ip: str | None) -> Verdict | None:
        """Return the verdict for one address, or None if it is on no list."""
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        self._maybe_reload()
        public = addr.is_global
        for category, source, ranges in self._lists:
            if source != "demo" and not public:
                continue
            if addr in ranges:
                return Verdict(category, source, self.list_date)
        return None

    def status(self) -> dict:
        return {"data_dir": str(self.data_dir), "list_date": self.list_date, "counts": dict(self.counts)}
