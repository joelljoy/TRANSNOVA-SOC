"""Follow the audit log across appends, partial lines, restarts and rotation.

The saved position is (file identity, byte offset). server_audit rotates by renaming
server_audit.log to server_audit.log.1, so when the identity changes the old file is looked
for among the rotated names and drained from the saved offset before the new file starts.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

READ_CHUNK = 1024 * 1024
ROTATED_SUFFIXES = (".1", ".2", ".3")


@dataclass
class Position:
    identity: str = ""
    offset: int = 0


def file_identity(path: Path) -> str:
    st = os.stat(path)
    return f"{st.st_dev}:{st.st_ino}"


class AuditTailer:
    def __init__(self, path: str, position: Position | None = None) -> None:
        self.path = Path(path)
        self.position = position or Position()

    def _read_lines(self, path: Path, offset: int) -> tuple[list[str], int]:
        """Complete lines from offset. A trailing partial line stays unread until it ends."""
        with open(path, "rb") as fh:
            fh.seek(offset)
            data = fh.read(READ_CHUNK)
        end = data.rfind(b"\n")
        if end < 0:
            return [], offset
        body = data[: end + 1]
        lines = [b.decode("utf-8", errors="replace").rstrip("\r") for b in body.split(b"\n")[:-1]]
        return [ln for ln in lines if ln], offset + len(body)

    def _find_rotated(self, identity: str) -> Path | None:
        for suffix in ROTATED_SUFFIXES:
            candidate = self.path.with_name(self.path.name + suffix)
            try:
                if file_identity(candidate) == identity:
                    return candidate
            except FileNotFoundError:
                continue
        return None

    def poll(self) -> list[str]:
        try:
            identity = file_identity(self.path)
        except FileNotFoundError:
            return []  # the server has not created the log yet
        pos = self.position
        if pos.identity and pos.identity != identity:
            rotated = self._find_rotated(pos.identity)
            if rotated is not None:
                lines, new_offset = self._read_lines(rotated, pos.offset)
                if lines:
                    pos.offset = new_offset
                    return lines
            pos.identity, pos.offset = identity, 0
        elif not pos.identity:
            pos.identity = identity
        elif os.path.getsize(self.path) < pos.offset:
            pos.offset = 0  # truncated in place
        lines, pos.offset = self._read_lines(self.path, pos.offset)
        return lines
