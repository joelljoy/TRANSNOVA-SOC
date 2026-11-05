"""Console accounts: a small file of scrypt hashes, mounted as a secret.

    python -m console.users add <username> --role analyst --file <users file>

Line format: username:role:scrypt$n$r$p$salt$hash (salt and hash base64). Passwords never leave
this module; the hash never leaves the file.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROLES = ("viewer", "analyst", "admin")
USERNAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")
N, R, P = 2**15, 8, 1
MIN_PASSWORD = 12


@dataclass(frozen=True)
class User:
    username: str
    role: str
    hashed: str


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=N, r=R, p=P, maxmem=128 << 20, dklen=32)
    return f"scrypt${N}${R}${P}${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


def verify(hashed: str, password: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = hashed.split("$")
        if scheme != "scrypt":
            return False
        got = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt), n=int(n), r=int(r), p=int(p),
                             maxmem=128 << 20, dklen=32)
        return hmac.compare_digest(got, base64.b64decode(digest))
    except (ValueError, TypeError):
        return False


# Spent on unknown usernames so a miss takes as long as a wrong password.
_DUMMY = hash_password("not-a-real-password-for-timing")


def load(path: str | None) -> dict[str, User]:
    """Accounts from the file, or none. A broken line is skipped, never half-trusted."""
    if not path:
        return {}
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError:
        return {}
    users = {}
    for line in lines:
        parts = line.strip().split(":")
        if len(parts) == 3 and USERNAME.fullmatch(parts[0]) and parts[1] in ROLES and parts[2].startswith("scrypt$"):
            users[parts[0]] = User(parts[0], parts[1], parts[2])
    return users


def authenticate(users: dict[str, User], username: str, password: str) -> User | None:
    user = users.get(username)
    if user is None:
        verify(_DUMMY, password)
        return None
    return user if verify(user.hashed, password) else None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m console.users")
    sub = parser.add_subparsers(dest="cmd", required=True)
    add = sub.add_parser("add", help="add or replace an account")
    add.add_argument("username")
    add.add_argument("--role", choices=ROLES, default="analyst")
    add.add_argument("--file", required=True)
    add.add_argument("--password-stdin", action="store_true", help="read the password from stdin (for scripts)")
    args = parser.parse_args(argv)
    if not USERNAME.fullmatch(args.username):
        print("username: letters, digits, _ . - only (max 64)", file=sys.stderr)
        return 2
    password = sys.stdin.readline().rstrip("\n") if args.password_stdin else getpass.getpass("Password: ")
    if len(password) < MIN_PASSWORD:
        print(f"password must be at least {MIN_PASSWORD} characters", file=sys.stderr)
        return 2
    if not args.password_stdin and getpass.getpass("Repeat: ") != password:
        print("passwords differ", file=sys.stderr)
        return 2
    path = Path(args.file)
    keep = [ln for ln in (path.read_text(encoding="utf-8").splitlines() if path.exists() else [])
            if ln.strip() and not ln.startswith(f"{args.username}:")]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join([*keep, f"{args.username}:{args.role}:{hash_password(password)}"]) + "\n", encoding="utf-8")
    print(f"saved {args.username} ({args.role}) to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
