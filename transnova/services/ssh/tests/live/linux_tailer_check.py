"""Attack the sensor's log reader inside the real sensor image. Needs Linux. Standard library only.

Run with --device as root with CAP_MKNOD for the device case. Prints pass or fail per case
and never prints file contents. Everything is built under /tmp, so no real data is touched.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import signal
import socket
import sys
import tempfile
import threading
from pathlib import Path

from cowrie_soc import tailer
from cowrie_soc.config import Config
from cowrie_soc.pipeline import Pipeline
from cowrie_soc.sinks import JsonlSink
from cowrie_soc.store import Store
from cowrie_soc.tailer import LogFollower, UnsafeLogFile, open_log

GOOD = json.dumps({"eventid": "cowrie.session.connect", "timestamp": "2026-10-31T00:00:00Z", "session": "abc"}) + "\n"
results: list[tuple[str, bool]] = []


def check(name: str, ok: bool) -> None:
    results.append((name, bool(ok)))
    print(f"{'PASS' if ok else 'FAIL'} {name}")


def fresh() -> Path:
    return Path(tempfile.mkdtemp(prefix="logs-", dir="/tmp"))


def lines_seen(directory: Path, needle: str) -> tuple[int, int]:
    """Poll a few times; return (lines read, lines containing needle)."""
    follower = LogFollower(directory)
    cp, total, hits = None, 0, 0
    for _ in range(4):
        result = follower.poll(cp)
        total += len(result.lines)
        hits += sum(needle.encode() in line.data for line in result.lines)
        cp = result.checkpoint
    return total, hits


def rejected(directory: Path, name: str, *kinds: str) -> bool:
    try:
        fh = open_log(directory, name)
    except UnsafeLogFile as exc:
        return exc.kind in kinds
    if fh:
        fh.close()
    return False


def main() -> int:
    signal.alarm(120)  # a hang on a FIFO is a failure, not a stuck test
    secret = "X" + secrets.token_hex(16)
    outside = Path(tempfile.mkdtemp(prefix="outside-", dir="/tmp"))
    secret_file = outside / "secret.json"
    secret_file.write_text(json.dumps({"eventid": "cowrie.x", "password": secret}) + "\n", encoding="utf-8")

    check("secure opening is active", tailer.SECURE_OPEN)
    os.environ["FAKE_TOKEN"] = secret

    d = fresh()
    (d / "cowrie.json").symlink_to(secret_file)
    check("symlink to a file outside is rejected", rejected(d, "cowrie.json", "symlink"))
    check("symlink content is never read", lines_seen(d, secret) == (0, 0))

    d = fresh()
    (d / "cowrie.json").symlink_to("/proc/self/environ")
    check("symlink to process environment is rejected", lines_seen(d, secret) == (0, 0))

    d = fresh()
    (d / "cowrie.json").write_text(GOOD, encoding="utf-8")
    (d / "cowrie.json.2026-10-31").symlink_to(secret_file)
    check("symlinked rotated file is not read", lines_seen(d, secret)[1] == 0)

    d = fresh()
    (d / "cowrie.json").symlink_to(d / "cowrie.json")
    check("symlink loop is rejected", rejected(d, "cowrie.json", "symlink"))

    d = fresh()
    link = d / "real"
    link.symlink_to(outside, target_is_directory=True)
    check("a symlinked log directory is refused", lines_seen(link, secret) == (0, 0))

    d = fresh()
    os.mkfifo(d / "cowrie.json")
    check("FIFO is rejected without hanging", rejected(d, "cowrie.json", "fifo"))

    d = fresh()
    sock = socket.socket(socket.AF_UNIX)
    sock.bind(str(d / "cowrie.json"))
    check("socket is rejected", rejected(d, "cowrie.json", "socket", "special"))
    sock.close()

    d = fresh()
    (d / "cowrie.json").mkdir()
    check("directory is rejected", rejected(d, "cowrie.json", "directory"))

    d = fresh()
    os.link(secret_file, d / "cowrie.json")
    check("hard link is rejected", rejected(d, "cowrie.json", "hard_link"))
    check("hard link content is never read", lines_seen(d, secret) == (0, 0))

    d = fresh()
    (d / "cowrie.json").write_text(GOOD, encoding="utf-8")
    fh = open_log(d, "cowrie.json")
    (d / "cowrie.json").unlink()
    (d / "cowrie.json").symlink_to(secret_file)
    content = fh.read()
    fh.close()
    check("replacing the path after opening has no effect", secret.encode() not in content and content == GOOD.encode())

    d = fresh()
    log = d / "cowrie.json"
    log.write_text(GOOD, encoding="utf-8")
    stop = threading.Event()

    def swap() -> None:
        spare = d / "spare"
        while not stop.is_set():
            spare.unlink(missing_ok=True)
            spare.symlink_to(secret_file)
            os.replace(spare, log)
            spare.write_text(GOOD, encoding="utf-8")
            os.replace(spare, log)

    swapper = threading.Thread(target=swap, daemon=True)
    swapper.start()
    follower = LogFollower(d)
    cp, leaked, reads = None, 0, 0
    for _ in range(4000):
        result = follower.poll(cp)
        reads += len(result.lines)
        leaked += sum(secret.encode() in line.data for line in result.lines)
        cp = None
    stop.set()
    swapper.join(5)
    check(f"racing symlink swap during 4000 polls leaks nothing (rejections seen={sum(follower.rejected.values()) > 0})",
          leaked == 0 and reads > 0 and follower.rejected["symlink"] > 0)

    d = fresh()
    (d / "cowrie.json").write_text(GOOD, encoding="utf-8")
    follower = LogFollower(d)
    first = follower.poll(None)
    (d / "cowrie.json").unlink()
    (d / "cowrie.json").symlink_to(secret_file)
    second = follower.poll(first.checkpoint)
    check("after a replaced log the sensor keeps running and reads nothing", not second.lines)

    if "--device" in sys.argv:
        d = fresh()
        os.mknod(d / "cowrie.json", 0o020600, os.makedev(1, 3))
        check("character device is rejected", rejected(d, "cowrie.json", "device", "special", "denied"))
        check("character device is never read", lines_seen(d, secret) == (0, 0))
        d = fresh()
        os.mknod(d / "cowrie.json", 0o060600, os.makedev(7, 0))
        check("block device is rejected", rejected(d, "cowrie.json", "device", "special", "denied"))
        check("block device is never read", lines_seen(d, secret) == (0, 0))
    else:
        check_pipeline(secret)

    shutil.rmtree(outside, ignore_errors=True)
    failed = sum(not ok for _, ok in results)
    print(f"TOTAL passed={len(results) - failed} failed={failed}")
    return 1 if failed else 0


def check_pipeline(secret: str) -> None:
    """Dirty lines through the real pipeline: nothing may reach the stored data."""
    root = Path(tempfile.mkdtemp(prefix="pipe-", dir="/tmp"))
    logs, state = root / "logs", root / "state"
    logs.mkdir()
    state.mkdir()
    base = {"timestamp": "2026-10-31T00:00:00Z", "session": "abc"}
    dirty = [
        {**base, "eventid": "cowrie.login.failed", "username": "root", "password": secret,
         "message": f"login attempt [root/{secret}] failed"},
        {**base, "eventid": "cowrie.login.failed", "username": secret},
        {**base, "eventid": "cowrie.command.input", "input": f"mysql -p{secret}"},
        {**base, "eventid": "cowrie.command.success", "realm": "passwd", "input": secret},
        {**base, "eventid": "cowrie.client.var", "name": "DB_SECRET", "value": secret},
        {**base, "eventid": "cowrie.unknown", "input": secret, "data": secret},
    ]
    text = "".join(json.dumps(line) + "\n" for line in dirty)
    text += f'{{"eventid": "cowrie.x", "password": "{secret}"\n'  # broken JSON
    text += json.dumps({"eventid": "cowrie.x", "timestamp": secret, "session": "s"}) + "\n"
    text += json.dumps({**base, "eventid": "cowrie.x", "src_ip": secret}) + "\n"
    (logs / "cowrie.json").write_text(text, encoding="utf-8")

    config = Config()
    config.source.log_dir = str(logs)
    store = Store(state / "collector.db")
    pipeline = Pipeline(config, store=store, sinks=[JsonlSink(state / "normalized.jsonl")])
    for _ in range(3):
        pipeline.step()
    quarantined = store.db.execute("select count(*) from quarantine").fetchone()[0]
    excerpts = store.db.execute("select count(*) from quarantine where excerpt != ''").fetchone()[0]
    store.db.execute("PRAGMA wal_checkpoint(FULL)")
    store.close()

    found = sum(path.read_bytes().count(secret.encode()) for path in state.rglob("*") if path.is_file())
    check("control: the dirty source log really holds the marker", secret.encode() in (logs / "cowrie.json").read_bytes())
    check("dirty lines reached the pipeline", len((state / "normalized.jsonl").read_text().splitlines()) >= 6)
    check("rejected lines were quarantined", quarantined == 3)
    check("quarantine holds no excerpts", excerpts == 0)
    check("no marker in any stored sensor file", found == 0)
    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
