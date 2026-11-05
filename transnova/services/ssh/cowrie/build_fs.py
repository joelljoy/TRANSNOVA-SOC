"""Build Cowrie's emulated filesystem: bundled fs.pickle + synthetic decoy files.

Runs at image build time with Cowrie's own interpreter:

    python3 build_fs.py <decoy-fs-dir> <output-pickle>

Every regular file under <decoy-fs-dir> is added at the same virtual path
(e.g. decoy-fs/var/backups/db/.my.cnf -> /var/backups/db/.my.cnf) with its
contents embedded in the pickle. Missing parent directories are created.
Only the trusted pickle that ships inside the Cowrie package is loaded.
"""

from __future__ import annotations

import os
import pickle
import sys
import time
from importlib.resources import files
from pathlib import Path

# Field indices / types mirror cowrie.shell.fs (a 10-field list per node).
A_NAME, A_TYPE, A_UID, A_GID, A_SIZE, A_MODE, A_CTIME, A_CONTENTS, A_TARGET, A_REALFILE = range(10)
T_LINK, T_DIR, T_FILE = 0, 1, 2

# Owner of the decoy files: Debian's "backup" system account (uid/gid 34).
DECOY_UID = 34
DECOY_GID = 34
DIR_MODE = 0o40750
FILE_MODE = 0o100640
# Fixed timestamp so `ls -l` looks plausible and builds are reproducible.
DECOY_CTIME = time.mktime((2026, 10, 30, 2, 15, 0, 0, 0, 0))


def _child(node: list, name: str) -> list | None:
    return next((c for c in node[A_CONTENTS] if c[A_NAME] == name), None)


def _ensure_dir(root: list, parts: list[str]) -> list:
    node = root
    for part in parts:
        child = _child(node, part)
        if child is None:
            child = [part, T_DIR, DECOY_UID, DECOY_GID, 4096, DIR_MODE, DECOY_CTIME, [], None, None]
            node[A_CONTENTS].append(child)
        elif child[A_TYPE] != T_DIR:
            raise SystemExit(f"cannot create directory over non-directory: {part}")
        node = child
    return node


def add_tree(root: list, decoy_dir: Path) -> list[str]:
    added: list[str] = []
    for dirpath, dirnames, filenames in os.walk(decoy_dir):
        dirnames.sort()
        rel = Path(dirpath).relative_to(decoy_dir)
        parent = _ensure_dir(root, [p for p in rel.parts if p not in ("", ".")])
        for name in sorted(filenames):
            data = (Path(dirpath) / name).read_bytes()
            existing = _child(parent, name)
            if existing is not None:
                parent[A_CONTENTS].remove(existing)
            parent[A_CONTENTS].append(
                [name, T_FILE, DECOY_UID, DECOY_GID, len(data), FILE_MODE, DECOY_CTIME, data, None, None]
            )
            added.append("/" + "/".join([*rel.parts, name]).lstrip("/"))
    return added


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(__doc__, file=sys.stderr)
        return 2
    decoy_dir, output = Path(argv[1]), Path(argv[2])
    bundled = files("cowrie.data").joinpath("fs.pickle").read_bytes()
    root = pickle.loads(bundled)
    added = add_tree(root, decoy_dir)
    output.write_bytes(pickle.dumps(root))
    for path in added:
        print(f"decoy file: {path}")
    print(f"wrote {output} ({len(added)} decoy files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
