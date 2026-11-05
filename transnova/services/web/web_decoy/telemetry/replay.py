"""Resend spooled events to the collector.

    python -m web_decoy.telemetry.replay

Sends the spool in batches. Stops at the first failure and rewrites the spool with
only the unsent events, so nothing is lost and nothing is sent twice by this tool.
(The collector should still deduplicate on event_id: docs/INTEGRATOR_NOTES.md §1.)
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

from ..config import Settings
from .emitter import Emitter, dumps_line


async def replay(settings: Settings, transport: httpx.AsyncBaseTransport | None = None) -> tuple[int, int]:
    """Returns (sent, remaining)."""
    path = Path(settings.spool_path)
    if not path.exists():
        return 0, 0
    events = []
    with open(path, encoding="ascii") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip a torn line rather than block the whole spool
    if not settings.collector_url.strip():
        return 0, len(events)

    em = Emitter(settings, transport=transport)
    sent = 0
    async with em._client() as client:
        for i in range(0, len(events), settings.batch_size):
            batch = events[i : i + settings.batch_size]
            try:
                resp = await client.post(em.url, json=batch, headers=em.headers)
                ok = 200 <= resp.status_code < 300
            except httpx.HTTPError:
                ok = False
            if not ok:
                break
            sent += len(batch)

    remaining = events[sent:]
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="ascii", newline="\n") as fh:
        fh.writelines(dumps_line(e) for e in remaining)
    os.replace(tmp, path)  # atomic: a crash leaves either the old or the new spool
    return sent, len(remaining)


def main() -> int:
    sent, remaining = asyncio.run(replay(Settings.from_env()))
    print(f"replayed={sent} remaining={remaining}")
    return 0 if remaining == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
