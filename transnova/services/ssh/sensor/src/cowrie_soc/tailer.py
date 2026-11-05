"""Follow Cowrie's JSON log across restarts, rotation and truncation.

Cowrie (logtype = rotating) writes `cowrie.json` and at midnight renames it to
`cowrie.json.YYYY-MM-DD`, then starts a new `cowrie.json`. A file is identified
by a fingerprint of its first line rather than its name or inode, so after a
rename the follower still finds the file it was reading, drains whatever was
appended before rotation, and only then moves on to the new file.

Only complete (newline-terminated) lines are returned; a partially written
line stays unread until its newline arrives. The follower does not persist
anything itself: `poll()` returns lines plus the checkpoint *after* them, and
the caller stores that checkpoint atomically with the processed records.

Files are opened per poll and closed again, so rotation by rename also works
on Windows during local development.

The log volume is writable by Cowrie, so a compromised decoy controls what is in
this directory. Only regular files directly inside it are read. Each file is
opened once with O_NOFOLLOW relative to a held directory handle, its type is
checked on that open handle, and every later read uses the same handle. Nothing
is checked by path and then re-opened, so swapping the path afterwards has no effect.
"""

from __future__ import annotations

import errno
import hashlib
import logging
import os
import re
import stat
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from cowrie_soc.parser import RawLine
from cowrie_soc.store import Checkpoint

log = logging.getLogger(__name__)

FINGERPRINT_MAX_BYTES = 4096
READ_CHUNK = 1 << 20
_ROTATED_SUFFIX = re.compile(r"^\.[A-Za-z0-9_.\-]{1,32}$")

SECURE_OPEN = (
    hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NONBLOCK")
    and os.open in os.supports_dir_fd and os.listdir in os.supports_fd
)


class UnsafeLogFile(Exception):
    """The name exists but is not a regular file directly inside the log directory."""

    def __init__(self, kind: str) -> None:
        super().__init__(kind)
        self.kind = kind


def _file_kind(mode: int) -> str:
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
        return "device"
    if stat.S_ISLNK(mode):
        return "symlink"
    return "other"


def _open_fd(directory: Path, name: str) -> int | None:
    if SECURE_OPEN:
        try:
            dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except FileNotFoundError:
            return None
        try:
            return os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
        except FileNotFoundError:
            return None
        except OSError as exc:
            kinds = {errno.ELOOP: "symlink", errno.ENXIO: "special", errno.ENODEV: "special",
                     errno.EPERM: "denied", errno.EACCES: "denied"}
            if exc.errno in kinds:
                raise UnsafeLogFile(kinds[exc.errno]) from None
            raise
        finally:
            os.close(dir_fd)
    # Local development on Windows only; a Linux start refuses this path (see LogFollower).
    path = directory / name
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(mode):
        raise UnsafeLogFile(_file_kind(mode))
    return os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))


def open_log(directory: Path, name: str) -> BinaryIO | None:
    """Open a file directly inside `directory`. None if absent, UnsafeLogFile if not a plain file."""
    if name in ("", ".", "..") or "/" in name or "\\" in name or "\0" in name:
        raise UnsafeLogFile("bad_name")
    fd = _open_fd(directory, name)
    if fd is None:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise UnsafeLogFile(_file_kind(info.st_mode))
        if SECURE_OPEN and info.st_nlink != 1:
            raise UnsafeLogFile("hard_link")
        return os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise


def _first_line_hash(fh: BinaryIO) -> str | None:
    fh.seek(0)
    head = fh.read(FINGERPRINT_MAX_BYTES)
    nl = head.find(b"\n")
    if nl == -1:
        if len(head) < FINGERPRINT_MAX_BYTES:
            return None
        nl = len(head)
    return hashlib.sha256(head[:nl]).hexdigest()


def fingerprint(path: Path) -> str | None:
    """SHA-256 of the file's first line; None until a first full line exists."""
    try:
        fh = open_log(path.parent, path.name)
    except UnsafeLogFile:
        return None
    if fh is None:
        return None
    with fh:
        return _first_line_hash(fh)


@dataclass
class PollResult:
    lines: list[RawLine]
    checkpoint: Checkpoint | None
    notices: list[str] = field(default_factory=list)


class LogFollower:
    def __init__(
        self,
        directory: str | Path,
        base_name: str = "cowrie.json",
        start_at_end: bool = False,
        max_line_bytes: int = 1 << 20,
    ) -> None:
        if sys.platform == "linux" and not SECURE_OPEN:
            raise RuntimeError("secure file opening is not available on this system")
        self.directory = Path(directory)
        self.base_name = base_name
        self.start_at_end = start_at_end
        self.max_line_bytes = max_line_bytes
        self.rejected: Counter[str] = Counter()
        self._reported: set[str] = set()

    @property
    def base_path(self) -> Path:
        return self.directory / self.base_name

    def _open(self, name: str) -> BinaryIO | None:
        try:
            return open_log(self.directory, name)
        except UnsafeLogFile as exc:
            self.rejected[exc.kind] += 1
            return None
        except OSError as exc:
            self.rejected[f"error_{type(exc).__name__}"] += 1
            return None

    def _base_fingerprint(self) -> str | None:
        fh = self._open(self.base_name)
        if fh is None:
            return None
        with fh:
            return _first_line_hash(fh)

    def _rotated_names(self) -> list[str]:
        try:
            if SECURE_OPEN:
                dir_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    names = os.listdir(dir_fd)
                finally:
                    os.close(dir_fd)
            else:
                names = os.listdir(self.directory)
        except OSError:
            return []
        prefix = self.base_name
        return sorted(n for n in names if n.startswith(prefix) and _ROTATED_SUFFIX.fullmatch(n[len(prefix):]))

    def _locate(self, fp: str) -> tuple[str, BinaryIO] | None:
        """Find the file whose first line matches fp: the live file first, then rotated ones.

        The open handle is returned, so what was checked is exactly what gets read.
        """
        for name in (self.base_name, *self._rotated_names()):
            fh = self._open(name)
            if fh is None:
                continue
            if _first_line_hash(fh) == fp:
                return name, fh
            fh.close()
        return None

    def poll(self, checkpoint: Checkpoint | None, max_lines: int = 500) -> PollResult:
        result = self._poll(checkpoint, max_lines)
        for kind in sorted(set(self.rejected) - self._reported):
            self._reported.add(kind)
            result.notices.append(f"rejected unsafe entry in the log directory: {kind}")
        return result

    def _poll(self, checkpoint: Checkpoint | None, max_lines: int) -> PollResult:
        notices: list[str] = []
        if checkpoint is None:
            fh = self._open(self.base_name)
            if fh is None:
                return PollResult([], None)
            with fh:
                fp = _first_line_hash(fh)
                if fp is None:
                    return PollResult([], None)
                offset = self._end_offset(fh) if self.start_at_end else 0
            checkpoint = Checkpoint(fp, self.base_name, offset)
            notices.append(f"no checkpoint: starting {self.base_name} at offset {offset}")

        located = self._locate(checkpoint.fingerprint)
        if located is None:
            fp = self._base_fingerprint()
            if fp is None:
                return PollResult([], checkpoint, notices)
            notices.append(
                f"POSSIBLE DATA LOSS: file with fingerprint {checkpoint.fingerprint[:12]} "
                f"(last seen as {checkpoint.file} @ {checkpoint.offset}) no longer exists; "
                f"continuing from the start of {self.base_name}"
            )
            checkpoint = Checkpoint(fp, self.base_name, 0)
            located = self._locate(fp)
            if located is None:
                return PollResult([], checkpoint, notices)

        name, fh = located
        with fh:
            size = os.fstat(fh.fileno()).st_size
            if size < checkpoint.offset:
                notices.append(
                    f"POSSIBLE DATA LOSS: {name} shrank from {checkpoint.offset} to {size} bytes "
                    "(truncated); re-reading from offset 0"
                )
                checkpoint = Checkpoint(checkpoint.fingerprint, name, 0)

            is_rotated = name != self.base_name
            lines, new_offset = self._read_lines(fh, name, checkpoint.offset, max_lines, final=False)
            if lines:
                return PollResult(lines, Checkpoint(checkpoint.fingerprint, name, new_offset), notices)

            if is_rotated:
                # The rotated file will not grow again. Flush an unterminated tail, then move on.
                tail, tail_end = self._read_lines(fh, name, checkpoint.offset, 1, final=True)
                if tail:
                    return PollResult(tail, Checkpoint(checkpoint.fingerprint, name, tail_end), notices)
                fp = self._base_fingerprint()
                if fp is not None and fp != checkpoint.fingerprint:
                    notices.append(f"finished rotated file {name}; switching to new {self.base_name}")
                    return PollResult([], Checkpoint(fp, self.base_name, 0), notices)
            return PollResult([], Checkpoint(checkpoint.fingerprint, name, checkpoint.offset), notices)

    def _end_offset(self, fh: BinaryIO) -> int:
        """Offset just past the last complete line (used for start_position = end)."""
        size = os.fstat(fh.fileno()).st_size
        pos = size
        while pos > 0:
            step = min(READ_CHUNK, pos)
            fh.seek(pos - step)
            chunk = fh.read(step)
            nl = chunk.rfind(b"\n")
            if nl != -1:
                return pos - step + nl + 1
            pos -= step
        return 0

    def _read_lines(self, fh: BinaryIO, name: str, offset: int, max_lines: int, final: bool) -> tuple[list[RawLine], int]:
        lines: list[RawLine] = []
        fh.seek(offset)
        buf = b""
        buf_start = offset
        while len(lines) < max_lines:
            chunk = fh.read(READ_CHUNK)
            if not chunk:
                break
            buf += chunk
            while len(lines) < max_lines:
                nl = buf.find(b"\n")
                if nl == -1:
                    break
                line = buf[:nl]
                lines.append(RawLine(line, name, buf_start, oversized=len(line) > self.max_line_bytes))
                buf = buf[nl + 1 :]
                buf_start += nl + 1
            if len(buf) > self.max_line_bytes:
                # Keep reading to find the end of this oversized line, but do not hold it in memory.
                skipped_start, skipped = buf_start, len(buf)
                head = buf[:512]
                while True:
                    chunk = fh.read(READ_CHUNK)
                    if not chunk:
                        if final:
                            # A rotated file will not grow: report the oversized tail, don't skip it.
                            lines.append(RawLine(head, name, skipped_start, oversized=True, unterminated=True))
                            return lines, skipped_start + skipped
                        # Unterminated oversized line: leave it unread until it completes.
                        return lines, buf_start
                    nl = chunk.find(b"\n")
                    if nl != -1:
                        skipped += nl
                        lines.append(RawLine(head, name, skipped_start, oversized=True))
                        buf = chunk[nl + 1 :]
                        buf_start = skipped_start + skipped + 1
                        break
                    skipped += len(chunk)
        if final and buf and len(lines) < max_lines:
            lines.append(RawLine(buf, name, buf_start, unterminated=True))
            buf_start += len(buf)
        return lines, buf_start
