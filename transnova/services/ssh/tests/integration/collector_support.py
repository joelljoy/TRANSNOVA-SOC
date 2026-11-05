"""A real collector on a random loopback port, and a raw socket client.

Starts the same uvicorn command as collector/Dockerfile with a temporary database, so requests take
the real h11 path. Nothing here can reach a running service.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

REPO = Path(__file__).resolve().parents[4]
TIMESTAMP = "2026-10-31T12:00:00.000Z"
MIB = 1 << 20
POST_EVENTS = b"POST /api/events HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
STATUS = re.compile(rb"HTTP/1\.1 (\d{3})")


def write_tokens(folder: Path) -> tuple[str, str, dict[str, str]]:
    """Random tokens, created for one test and never shown. Returns (ssh, read, settings)."""
    ssh_token, read_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
    (folder / "ssh.token").write_text(ssh_token + "\n", encoding="ascii")
    (folder / "read.token").write_text(read_token + "\n", encoding="ascii")
    return ssh_token, read_token, {"SSH_INGEST_TOKEN_FILE": str(folder / "ssh.token"),
                                   "SOC_READ_TOKEN_FILE": str(folder / "read.token")}


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def web_event(event_id: str | None = None, **change: Any) -> dict[str, Any]:
    return {"event_id": event_id or str(uuid.uuid4()), "timestamp": TIMESTAMP, "sensor_id": "web-01", "service": "web",
            "source_ip": "10.0.0.1", "destination_service": "web-decoy", "event_type": "http_request", "action": "a",
            "outcome": "observed", **change}


def post_request(body: bytes, path: bytes = b"/api/events") -> bytes:
    return (b"POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % (path, len(body))
            + body)


def event_request(event_id: str) -> bytes:
    return post_request(json.dumps([web_event(event_id)]).encode())


def chunked(body: bytes, tail: bytes = b"0\r\n\r\n") -> bytes:
    return b"%x\r\n" % len(body) + body + b"\r\n" + tail


class Server:
    def __init__(self, port: int) -> None:
        self.port = port

    def talk(self, data: bytes, wait: float = 0.6) -> tuple[list[str], bool]:
        """Send, then read until closed or quiet. Returns every status seen and whether it closed."""
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=wait)
        out, closed = b"", False
        try:
            try:
                sock.sendall(data)
            except OSError:
                closed = True
            while not closed:
                try:
                    part = sock.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    closed = True
                    break
                if not part:
                    closed = True
                out += part
        finally:
            sock.close()
        return [code.decode() for code in STATUS.findall(out)], closed

    def read(self, target: bytes, headers: bytes = b"") -> tuple[str, bytes]:
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=30)
        sock.sendall(b"GET %s HTTP/1.1\r\nHost: x\r\nConnection: close\r\n%s\r\n" % (target, headers))
        out = b""
        while True:
            part = sock.recv(1 << 20)
            if not part:
                break
            out += part
        sock.close()
        head, _, body = out.partition(b"\r\n\r\n")
        return head[9:12].decode(), body

    def stored(self, event_id: str) -> bool:
        return event_id.encode() in self.read(b"/api/events?limit=1000")[1]


def free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@contextmanager
def real_collector(tmp_path: Path, *flags: str, env: dict[str, str] | None = None) -> Iterator[Server]:
    port = free_port()
    settings = {**os.environ, "COLLECTOR_DB_PATH": str(tmp_path / f"{uuid.uuid4().hex}.db"), "PYTHONPATH": str(REPO),
                "PYTHONDONTWRITEBYTECODE": "1", **(env or {})}
    process = subprocess.Popen([sys.executable, "-m", "uvicorn", "collector.app:app", "--host", "127.0.0.1", "--port", str(port),
                                "--http", "h11", "--no-server-header", "--no-access-log", "--log-level", "critical", *flags],
                               env=settings, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(400):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("the test collector did not start")
        yield Server(port)
    finally:
        process.terminate()
        process.wait()
