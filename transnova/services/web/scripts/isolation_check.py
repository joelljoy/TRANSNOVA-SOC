"""Containment proof for the web decoy. Run INSIDE the container, from the repo root:

    docker compose -f docker-compose.web.yml exec -T web-decoy python - < services/web/scripts/isolation_check.py

Windows PowerShell:

    Get-Content services/web/scripts/isolation_check.py | docker compose -f docker-compose.web.yml exec -T web-decoy python -

Prints one PASS/FAIL line per check and exits non-zero if any check fails.
This file is NOT copied into the image; it is piped in only when you run it.
"""

import os
import socket
import sys

results = []


def check(name, ok, detail):
    results.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")


def tcp(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "connected"
    except OSError as exc:
        return False, type(exc).__name__ + (f" ({exc.strerror})" if getattr(exc, "strerror", None) else "")


# 1. No internet egress (IP literal, so DNS is not involved)
for host in ("1.1.1.1", "8.8.8.8"):
    ok, detail = tcp(host, 443)
    check(f"no egress to {host}:443", not ok, detail)

# 2. No external DNS resolution
try:
    socket.getaddrinfo("example.com", 443)
    check("no external DNS", False, "example.com resolved")
except OSError as exc:
    check("no external DNS", True, type(exc).__name__)

# 2b. No default route at all (no path to the internet OR to the Docker host)
with open("/proc/net/route") as fh:
    routes = [line.split() for line in fh.readlines()[1:]]
default = [r for r in routes if len(r) > 2 and r[1] == "00000000"]
check("no default route", not default, "none" if not default else f"via interface {default[0][0]}")

# 3. Lab peers: collector reachable if it is running (informational when absent)
ok, detail = tcp("collector", 8000, timeout=2)
print(f"INFO  collector:8000 reachable={ok} ({detail})")

# 4. Process hardening
check("not root", os.getuid() != 0, f"uid={os.getuid()}")
with open("/proc/self/status") as fh:
    status = dict(line.split(":", 1) for line in fh if ":" in line)
cap_eff = int(status["CapEff"].strip(), 16)
check("no effective capabilities", cap_eff == 0, f"CapEff={status['CapEff'].strip()}")
check("no-new-privileges", status.get("NoNewPrivs", "0").strip() == "1", f"NoNewPrivs={status.get('NoNewPrivs', '?').strip()}")
try:
    with open("/app/isolation-write-test", "w"):
        pass
    check("read-only app filesystem", False, "/app is writable")
except OSError as exc:
    check("read-only app filesystem", True, type(exc).__name__)

print("RESULT:", "ALL PASS" if all(results) else "FAILURES PRESENT")
sys.exit(0 if all(results) else 1)
