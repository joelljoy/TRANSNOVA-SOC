"""Run the database honeypot WITHOUT Docker, on a portable MariaDB (for machines where Docker
Desktop cannot start). Same schema, seed, accounts and audit configuration as the container.

    python services/database/scripts/native_lab.py init  --mariadb-home C:\\path\\mariadb-11.4.9-winx64 --workdir C:\\path\\lab
    python services/database/scripts/native_lab.py start --mariadb-home ... --workdir ...
    python services/database/scripts/native_lab.py stop  --mariadb-home ... --workdir ...

Binds 127.0.0.1:3307 only, so it never collides with a local MySQL on 3306 and is not
reachable from the network. This is a test convenience: it has NO network isolation.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PORT = 3307
ROOT_PW = os.environ.get("NATIVE_ROOT_PASSWORD", "native-lab-root")
DECOY_PW = os.environ.get("DECOY_DB_PASSWORD", "Summer2026-ops")
CTRL_PW = os.environ.get("CONTROLLER_DB_PASSWORD", "native-lab-controller")


def paths(args):
    home, work = Path(args.mariadb_home), Path(args.workdir)
    return home, work, home / "bin"


def write_ini(home: Path, work: Path) -> Path:
    logs = (work / "logs").as_posix()
    conf = (HERE / "conf" / "honeypot.cnf").read_text(encoding="utf-8")
    conf = conf.replace("/var/log/mysql", logs)
    conf = conf.replace("/var/lib/mysql-no-file-io", (work / "no-file-io").as_posix())
    ini = work / "my.ini"
    ini.write_text(
        conf.replace("[mariadb]", f"""[mariadb]
port={PORT}
bind_address=127.0.0.1
datadir={(work / 'data').as_posix()}
basedir={home.as_posix()}
plugin_dir={(home / 'lib' / 'plugin').as_posix()}
"""), encoding="utf-8")
    return ini


def client(bin_dir: Path, sql: str, user="root", password=ROOT_PW) -> None:
    subprocess.run([str(bin_dir / "mariadb.exe"), f"--port={PORT}", "--host=127.0.0.1", f"-u{user}", f"-p{password}",
                    "--default-character-set=utf8mb4"], input=sql.encode(), check=True)


def wait_ready(bin_dir: Path) -> None:
    for _ in range(60):
        probe = subprocess.run([str(bin_dir / "mariadb-admin.exe"), f"--port={PORT}", "--host=127.0.0.1",
                                "-uroot", f"-p{ROOT_PW}", "ping"], capture_output=True)
        if probe.returncode == 0:
            return
        time.sleep(0.5)
    raise SystemExit("MariaDB did not become ready; see <workdir>/logs/error.log")


def start(args) -> None:
    home, work, bin_dir = paths(args)
    ini = write_ini(home, work)
    # TZ=UTC so audit timestamps match the container, where the server clock is UTC.
    subprocess.Popen([str(bin_dir / "mariadbd.exe"), f"--defaults-file={ini}"],
                     env={**os.environ, "TZ": "UTC"}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                     creationflags=getattr(subprocess, "DETACHED_PROCESS", 0))
    wait_ready(bin_dir)
    print(f"ready on 127.0.0.1:{PORT}")


def stop(args) -> None:
    _, _, bin_dir = paths(args)
    subprocess.run([str(bin_dir / "mariadb-admin.exe"), f"--port={PORT}", "--host=127.0.0.1", "-uroot",
                    f"-p{ROOT_PW}", "shutdown"], check=True)
    print("stopped")


def init(args) -> None:
    home, work, bin_dir = paths(args)
    if (work / "data").exists():
        raise SystemExit(f"{work}/data already exists; delete it yourself to re-initialise")
    (work / "logs").mkdir(parents=True)
    (work / "no-file-io").mkdir()
    subprocess.run([str(bin_dir / "mariadb-install-db.exe"), f"--datadir={work / 'data'}", f"--password={ROOT_PW}"],
                   check=True, stdout=subprocess.DEVNULL)
    start(args)
    # The Windows installer tool creates a `test` database and anonymous grants; the official
    # container image does not, so remove them to match it.
    client(bin_dir, "DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db LIKE 'test%'; "
                    "DELETE FROM mysql.global_priv WHERE User=''; FLUSH PRIVILEGES;")
    client(bin_dir, (HERE / "initdb" / "01_schema.sql").read_text(encoding="utf-8"))
    client(bin_dir, (HERE / "initdb" / "02_seed.sql").read_text(encoding="utf-8"))
    accounts = (HERE / "initdb" / "accounts.sql.tmpl").read_text(encoding="utf-8")
    for key, value in (("DECOY_HOST", "%"), ("DECOY_PASSWORD", DECOY_PW), ("CONTROLLER_HOST", "127.0.0.1"),
                       ("CONTROLLER_PASSWORD", CTRL_PW)):
        accounts = accounts.replace(f"@@{key}@@", value)
    client(bin_dir, accounts)
    print("initialised")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["init", "start", "stop"])
    ap.add_argument("--mariadb-home", required=True)
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args()
    if not shutil.which(str(Path(args.mariadb_home) / "bin" / "mariadbd.exe")):
        raise SystemExit("mariadbd.exe not found under --mariadb-home/bin")
    {"init": init, "start": start, "stop": stop}[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
