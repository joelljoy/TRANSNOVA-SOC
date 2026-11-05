"""Build step: patch the pinned Cowrie so attacker input is cleaned before anything is written.

Cowrie has no settings for this:
- core/checkers.py puts tried passwords in the login events every output writes.
- core/events.py is the one path every event takes, so cleaning goes there, before any sink.
- python/logfile.py prints diagnostics that quote attacker input to the console, so the
  console now gets level and module only.

Every source file must match its pinned SHA-256 and every edit must match exactly once.
All files are checked before any output is written, so a build either applies all of
this or fails with no partial patch.

Usage: harden_cowrie.py <cowrie source dir> <output dir> <soc_redact.py>
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

PINS = {
    "core/checkers.py": "39ef2d3384d6c9bc2b7abc780e85c5492b1f269af18cbbcbb5545edc1016d714",
    "core/events.py": "e4d3df6d8075cf0f9d4482e7d9aa6ef0402aef459df3a1675c4485b70532ecc5",
    "python/logfile.py": "b4b82b443b06a75c8c4352e53e750781b291a3b724e64acf4aafedf92fde8975",
}
METADATA_OBSERVER = '''def _metadata_observer() -> Callable[[dict], None]:
    """Console line with no event text: diagnostics quote attacker input."""

    def observer(event: dict) -> None:
        level = getattr(event.get("log_level"), "name", "info")
        sys.stdout.write(f"{level} {event.get('log_namespace', '-')}\\n")
        sys.stdout.flush()

    directlyProvides(observer, ILogObserver)
    return observer


def stdoutLogger() -> Callable[[dict], None]:
'''
EDITS = {
    "core/checkers.py": [
        ('"login attempt [%(username)s/%(password)s] succeeded"', '"login attempt [%(username)s] succeeded"'),
        ('"login attempt [%(username)s/%(password)s] failed"', '"login attempt [%(username)s] failed"'),
        ("                    password=escape_nonprintable(thepassword),\n", ""),
        ("                password=escape_nonprintable(thepassword),\n", ""),
    ],
    "core/events.py": [
        ("from cowrie.core.output import convert\n",
         "from cowrie.core.output import convert\nfrom cowrie.core.soc_redact import sanitize_event\n"),
        ("        ev: dict[str, Any] = convert(event)\n",
         "        ev: dict[str, Any] = sanitize_event(convert(event), keep_format=True)\n"),
    ],
    "python/logfile.py": [
        ("def stdoutLogger() -> Callable[[dict], None]:\n", METADATA_OBSERVER),
        ("    return _observer(sys.stdout)\n", "    return _metadata_observer()\n"),
    ],
}
MUST_NOT_REMAIN = {"core/checkers.py": ["%(password)s", "password=escape_nonprintable"]}


def patched(rel: str, source: bytes, pins: dict[str, str]) -> str:
    if hashlib.sha256(source).hexdigest() != pins[rel]:
        sys.exit(f"{rel}: source does not match the pinned hash; refusing to patch")
    text = source.decode("utf-8")
    for old, new in EDITS[rel]:
        if text.count(old) != 1:
            sys.exit(f"{rel}: expected one match for an edit, found {text.count(old)}")
        text = text.replace(old, new)
    for leftover in MUST_NOT_REMAIN.get(rel, []):
        if leftover in text:
            sys.exit(f"{rel}: patch left {leftover!r} behind")
    compile(text, rel, "exec")
    return text


def harden(source_dir: Path, output_dir: Path, redactor: Path, pins: dict[str, str] = PINS) -> None:
    results = {rel: patched(rel, (source_dir / rel).read_bytes(), pins) for rel in EDITS}
    compile(redactor.read_text(encoding="utf-8"), "soc_redact.py", "exec")
    for rel, text in results.items():
        target = output_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    (output_dir / "core").mkdir(parents=True, exist_ok=True)
    shutil.copyfile(redactor, output_dir / "core" / "soc_redact.py")


if __name__ == "__main__":
    harden(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
