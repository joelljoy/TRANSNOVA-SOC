import sys

import pytest


def _check_environment():
    """Fail fast with one clear message instead of hundreds of confusing errors
    when pytest is run by the wrong Python (e.g. the global install, not .venv)."""
    import starlette
    problems = []
    if sys.version_info[:2] < (3, 12):
        problems.append(f"Python {sys.version.split()[0]} (need 3.12+)")
    major, minor = (int(x) for x in starlette.__version__.split(".")[:2])
    if (major, minor) < (1, 0):
        problems.append(f"starlette {starlette.__version__} (need the pinned version from requirements.txt)")
    if problems:
        raise pytest.UsageError(
            "Wrong Python environment: " + "; ".join(problems) + f"\n  Running: {sys.executable}\n"
            "  Fix: cd services/web, activate the venv (Windows: .\\.venv\\Scripts\\Activate.ps1), "
            "then run: python -m pytest -q"
        )


_check_environment()


@pytest.fixture(autouse=True)
def _no_ambient_tls(monkeypatch):
    """Tests must not depend on the shell/image environment (the image sets WEB_DECOY_TLS=1)."""
    monkeypatch.delenv("WEB_DECOY_TLS", raising=False)
from fastapi.testclient import TestClient

from web_decoy.app import create_app
from web_decoy.config import Settings

LAB_IP = "127.0.0.1"          # inside default HEALTH_ALLOWED_CIDRS
OUTSIDE_IP = "203.0.113.10"   # TEST-NET-3, outside every allowlist

GOOD_USER = "j.miller"
GOOD_PASS = "TransNova#Spring26"


@pytest.fixture
def settings(tmp_path):
    # JSONL/spool in a temp dir; no collector URL, so tests never touch the network.
    return Settings(
        collector_url="",
        rate_limit_per_s=0,  # off for general tests; tests/test_flood.py enables it
        event_log_path=str(tmp_path / "events.jsonl"),
        spool_path=str(tmp_path / "spool.jsonl"),
    )


@pytest.fixture
def app(settings):
    return create_app(settings)


def _client(app, ip):
    return TestClient(app, client=(ip, 40000), follow_redirects=False)


@pytest.fixture
def client(app):
    """An attacker-like client outside every allowlist."""
    return _client(app, OUTSIDE_IP)


@pytest.fixture
def lab_client(app):
    return _client(app, LAB_IP)


@pytest.fixture
def logged_in(client):
    r = client.post("/login", data={"username": GOOD_USER, "password": GOOD_PASS})
    assert r.status_code == 302
    return client


def read_events(settings):
    import json
    from pathlib import Path
    p = Path(settings.event_log_path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="ascii").splitlines() if line]


@pytest.fixture
def fs_guard(settings):
    """Context manager that records every file open except the decoy's own JSONL
    log/spool. Disallowed opens are recorded AND raise, so a handler that swallows
    the error still fails the test. Usage: `with fs_guard() as opened: ...`."""
    import builtins
    import contextlib
    import io
    import os
    import pathlib

    allowed = {os.path.abspath(settings.event_log_path), os.path.abspath(settings.spool_path)}

    def _target(name, a, kw):
        t = a[0] if a else kw.get("file", kw.get("path"))
        try:
            return os.path.abspath(os.fspath(t))
        except TypeError:
            return repr(t)

    @contextlib.contextmanager
    def guard():
        opened: list[tuple[str, str]] = []
        mp = pytest.MonkeyPatch()

        def wrap(name, real):
            def guarded(*a, **kw):
                target = _target(name, a, kw)
                if target in allowed:
                    return real(*a, **kw)
                opened.append((name, target))
                raise OSError("file access blocked by test")
            return guarded

        mp.setattr(builtins, "open", wrap("open", builtins.open))
        mp.setattr(io, "open", wrap("io.open", io.open))
        mp.setattr(os, "open", wrap("os.open", os.open))
        for meth in ("open", "read_text", "read_bytes", "write_text", "write_bytes"):
            mp.setattr(pathlib.Path, meth, wrap(f"Path.{meth}", getattr(pathlib.Path, meth)))
        try:
            yield opened
        finally:
            mp.undo()

    return guard
