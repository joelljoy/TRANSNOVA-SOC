"""Drive the live marker test and search everywhere attacker input could be stored.

Markers are random, exist only in this process and the client, and are never printed:
all output below is counts. Run from services/ssh after the isolated stack is up.

    python tests/live/run_marker_test.py [stage 2 client image]
"""

from __future__ import annotations

import collections
import json
import os
import random
import secrets
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).parent
NETWORK = "soc-ssh-isolated_ssh_isolated_net"
HARDENED = ["--read-only", "--tmpfs", "/tmp", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true"]
COWRIE_PYTHON = "/cowrie/cowrie-env/bin/python3"
WORDS = "maple river stone cloud amber tiger pearl ocean".split()
SCAN = """
import json, os
needles = {k: v.encode() for k, v in json.loads(NEEDLES).items()}
skip = tuple(SKIP)
totals = {}
for root in ROOTS:
    count = dict.fromkeys(needles, 0)
    files = 0
    for base, dirs, names in os.walk(root):
        if base.startswith(skip):
            dirs[:] = []
            continue
        for name in names:
            try:
                data = open(os.path.join(base, name), "rb").read()
            except OSError:
                continue
            files += 1
            for key, value in needles.items():
                count[key] += data.count(value)
    totals[root] = {"files": files, "secrets": sum(v for k, v in count.items() if k != "control"),
                    "control": count.get("control", 0)}
print(json.dumps(totals))
"""
NEW_EVENTS = """
import collections, glob, json
counts = collections.Counter()
for path in sorted(glob.glob("/data/cowrie-logs/cowrie.json*")):
    for number, line in enumerate(open(path, encoding="utf-8")):
        if number >= SKIP_LINES and line.strip():
            counts[json.loads(line)["eventid"]] += 1
print(json.dumps(counts))
"""
FINDINGS = """
import collections, json
records = [json.loads(line) for line in open("/data/state/normalized.jsonl", encoding="utf-8") if line.strip()]
print(json.dumps({"total": len(records), "rules": collections.Counter(r["rule_id"] for r in records[SKIP:] if r["record_type"] == "finding"),
                  "brute": sorted({a["technique_id"] for r in records[SKIP:] if r.get("rule_id") == "SSH-BRUTE-001" for a in r["attack"]})}))
"""


def word() -> str:
    return random.choice(WORDS) + str(secrets.randbelow(900) + 100) + random.choice(WORDS)


def hex_marker() -> str:
    return "X" + secrets.token_hex(16)


def in_container(container: str, python: str, script: str) -> str:
    done = subprocess.run(["docker", "exec", "-i", container, python, "-"], input=script.encode(),
                          capture_output=True, timeout=120)
    if done.returncode:
        raise SystemExit(f"script in {container} failed with exit {done.returncode}")
    return done.stdout.decode()


def scan(container: str, python: str, roots: list[str], needles: dict[str, str], skip: list[str]) -> dict:
    header = f"NEEDLES = {json.dumps(json.dumps(needles))}\nROOTS = {roots!r}\nSKIP = {skip!r}\n"
    return json.loads(in_container(container, python, header + SCAN))


def tty_files() -> int:
    script = "import os\nprint(sum(not n.startswith('.') for n in os.listdir('/cowrie/cowrie-git/var/lib/cowrie/tty')))\n"
    return int(in_container("ssh-honeypot", COWRIE_PYTHON, script))


def line_count() -> int:
    return int(in_container("ssh-sensor", "python", "print(sum(1 for _ in open('/data/cowrie-logs/cowrie.json', 'rb')))\n"))


def record_count() -> dict:
    return json.loads(in_container("ssh-sensor", "python", FINDINGS.replace("SKIP", "0")))


def run_client(image: str, values: dict[str, str]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as folder:
        env_file = Path(folder) / "client.env"
        env_file.write_text("".join(f"{k}={v}\n" for k, v in values.items()), encoding="utf-8")
        done = subprocess.run(["docker", "run", "--rm", "--name", "stage2b-client", "--network", NETWORK, "--ip", "172.31.77.50",
                               *HARDENED, "--env-file", str(env_file), image], capture_output=True, timeout=600)
    return done.returncode, done.stdout.decode("utf-8", "replace")


def main() -> int:
    decoy = next(line.split(":", 2)[2].strip() for line in (HERE.parent.parent / "cowrie/userdb.txt").read_text(encoding="utf-8").splitlines()
                 if line.startswith("backup:"))
    forms = [f for f in (HERE / "secret_forms.txt").read_text(encoding="utf-8").splitlines() if f]
    markers = {k: word() for k in ("login", "user_word", "env", "passwd", "su", "ssh", "redirect", "stdin_cat", "stdin_tee",
                                   "pipe", "exec_stdin", "sftp", "sftp_name")}
    markers["user_random"] = hex_marker()
    form_values = [word() for _ in forms] + [hex_marker() for _ in forms]
    markers_all = {**markers, **{f"form{i}": v for i, v in enumerate(form_values)}, "decoy_password": decoy}
    control = "ctrl" + secrets.token_hex(4) + "file"
    client_values = {**markers, "control": control,
                     "forms": [f.replace("{M}", v) for f, v in zip(forms * 2, form_values)]}

    start_lines, start_tty = line_count(), tty_files()
    start_records = record_count()["total"]
    failures = 0

    if len(sys.argv) > 1:
        stage2_marker = word()
        markers_all["stage2_marker"] = stage2_marker
        code, out = run_client(sys.argv[1], {"MARKER": stage2_marker, "DECOY_PASSWORD": decoy})
        time.sleep(4)
        after = json.loads(in_container("ssh-sensor", "python", FINDINGS.replace("SKIP", str(start_records))))
        print("stage 2 scenario: client exit", code, "| rules", dict(after["rules"]), "| brute techniques", after["brute"])
        for line in out.splitlines():
            if not any(v in line for v in markers_all.values()):
                print("  ", line)
        start_records = after["total"]

    code, out = run_client("soc-ssh-testclient:stage2b", {"MARKERS": json.dumps(client_values), "DECOY_PASSWORD": decoy})
    time.sleep(4)
    print(f"client exit {code}")
    for line in out.splitlines():
        if any(v in line for v in markers_all.values()):
            print("  client line withheld: it contained a marker")
            failures += 1
        else:
            print("  ", line)
            failures += "FAILED" in line

    events = collections.Counter(json.loads(in_container("ssh-sensor", "python", NEW_EVENTS.replace("SKIP_LINES", str(start_lines)))))
    print("new events:", dict(sorted(events.items())))
    expected = {"cowrie.login.failed": 3, "cowrie.login.success": 1, "cowrie.client.var": 2, "cowrie.command.input": len(forms),
                "cowrie.session.file_upload": 2, "cowrie.session.file_download": 1, "cowrie.command.success": 1}
    missing = [k for k, n in expected.items() if events[k] < n]
    print("scenarios that did not happen:", missing)
    failures += len(missing)

    needles = {**markers_all, "control": control}
    print(f"secret values searched: {len(markers_all)}")
    downloads = "/cowrie/cowrie-git/var/lib/cowrie/downloads"
    results = {
        **scan("ssh-honeypot", COWRIE_PYTHON, ["/cowrie/cowrie-git/var", "/tmp"], needles, [downloads]),
        **scan("ssh-sensor", "python", ["/data/cowrie-logs", "/data/state", "/tmp"], needles, []),
    }
    for root, count in results.items():
        print(f"  {root}: files={count['files']} secrets={count['secrets']} control={count['control']}")
        failures += count["secrets"]
    control_seen = results["/cowrie/cowrie-git/var"]["control"] > 0 and results["/data/state"]["control"] > 0
    print("control value found by the search:", control_seen)
    failures += not control_seen

    new_tty = tty_files() - start_tty
    print("new keystroke recordings:", new_tty)
    failures += new_tty != 0

    for container in ("ssh-honeypot", "ssh-sensor"):
        done = subprocess.run(["docker", "logs", container], capture_output=True, timeout=60)
        text = done.stdout + done.stderr
        found = sum(text.count(v.encode()) for v in markers_all.values())
        print(f"docker logs {container}: exit={done.returncode} bytes={len(text)} secrets={found}")
        failures += found

    memory = scan("ssh-honeypot", COWRIE_PYTHON, [downloads], needles, [])[downloads]
    print(f"in-memory downloads before restart: files={memory['files']} secrets={memory['secrets']}")
    failures += memory["secrets"] == 0  # proves the upload and redirect content really went there
    subprocess.run(["docker", "restart", "ssh-honeypot"], capture_output=True, timeout=60, check=True)
    time.sleep(6)
    memory = scan("ssh-honeypot", COWRIE_PYTHON, [downloads], needles, [])[downloads]
    print(f"in-memory downloads after restart: files={memory['files']} secrets={memory['secrets']}")
    failures += memory["files"] != 0

    print("FINDINGS:", json.loads(in_container("ssh-sensor", "python", FINDINGS.replace("SKIP", str(start_records))))["rules"])
    print(f"RESULT failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
