"""Create ./secrets for the team compose: four distinct random tokens (read, console, ssh, web ingest)
and the first console account.

    python scripts/make_secrets.py                 # prompts for the account password
    python scripts/make_secrets.py --user analyst  # account name (default: analyst)

Existing files are never overwritten, so re-running is safe. ./secrets is git-ignored. Rotate a
token by deleting its file, re-running, and restarting the stack.
"""

from __future__ import annotations

import argparse
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "secrets"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--user", default="analyst")
    parser.add_argument("--role", default="analyst", choices=("viewer", "analyst", "admin"))
    args = parser.parse_args()
    DIR.mkdir(exist_ok=True)
    for name in ("read", "console", "ssh", "web"):
        path = DIR / f"{name}.token"
        if path.exists():
            print(f"kept      {path.relative_to(ROOT)}")
            continue
        path.write_text(secrets.token_urlsafe(32) + "\n", encoding="ascii")
        print(f"created   {path.relative_to(ROOT)}")
    tokens = [(DIR / f"{n}.token").read_text(encoding="ascii").strip() for n in ("read", "console", "ssh", "web")]
    if len(set(tokens)) != 4:
        print("the four tokens must all differ; delete one and re-run", file=sys.stderr)
        return 1
    users = DIR / "users.txt"
    if users.exists() and users.read_text(encoding="utf-8").strip():
        print(f"kept      {users.relative_to(ROOT)} (add accounts with python -m console.users add)")
        return 0
    print(f"Create the first console account '{args.user}' ({args.role}). Use at least 12 characters.")
    return subprocess.call([sys.executable, "-m", "console.users", "add", args.user, "--role", args.role,
                            "--file", str(users)], cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(main())
