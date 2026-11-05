"""Phase 4 exit: static and runtime safety guarantees (PLAN.md §6).

Static checks parse the source with `ast`, so they cannot be fooled by comments
or strings, and they fail the build if a dangerous call is ever introduced.
"""

import ast
from pathlib import Path

import pytest

PKG = Path(__file__).resolve().parent.parent / "web_decoy"
SOURCES = sorted(PKG.rglob("*.py"))
ROUTES = sorted((PKG / "routes").glob("*.py"))
DETECTION = sorted((PKG / "detection").glob("*.py"))

DANGEROUS_CALLS = {"eval", "exec", "compile", "__import__", "execfile", "input"}
DANGEROUS_MODULES = {"subprocess", "pty", "pickle", "marshal", "shelve", "ctypes", "multiprocessing"}
DANGEROUS_ATTRS = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"), ("os", "spawnv"),
                   ("os", "startfile")}
NETWORK_MODULES = {"httpx", "requests", "urllib.request", "urllib3", "aiohttp", "socket", "http.client",
                   "ftplib", "smtplib", "telnetlib"}
FILE_CALLS = {"open"}


def _tree(path):
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(tree):
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                yield a.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            yield node.module
            for a in node.names:
                yield f"{node.module}.{a.name}"


def test_sources_found():
    assert len(SOURCES) > 15 and ROUTES and DETECTION


@pytest.mark.parametrize("path", SOURCES, ids=lambda p: str(p.relative_to(PKG)))
def test_no_code_execution_primitives(path):
    tree = _tree(path)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Name):
                assert f.id not in DANGEROUS_CALLS, f"{path.name}: call to {f.id}()"
            if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
                assert (f.value.id, f.attr) not in DANGEROUS_ATTRS, f"{path.name}: {f.value.id}.{f.attr}()"
    for mod in _imports(tree):
        assert mod.split(".")[0] not in DANGEROUS_MODULES, f"{path.name}: imports {mod}"


@pytest.mark.parametrize("path", ROUTES + DETECTION, ids=lambda p: p.name)
def test_routes_and_detection_have_no_network_or_file_access(path):
    """Request input flows through routes and detection; neither may reach a socket or file."""
    tree = _tree(path)
    for mod in _imports(tree):
        assert mod not in NETWORK_MODULES and mod.split(".")[0] not in {"httpx", "requests", "socket",
                                                                         "aiohttp", "urllib3"}, \
            f"{path.name}: imports network module {mod}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in FILE_CALLS, f"{path.name}: calls open()"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {"read_text", "read_bytes", "write_text", "write_bytes",
                                          "urlopen"}, f"{path.name}: .{node.func.attr}()"


def test_only_emitter_and_replay_use_http_client():
    users = {p.name for p in SOURCES if any(m.split(".")[0] == "httpx" for m in _imports(_tree(p)))}
    assert users <= {"emitter.py", "replay.py"}, users


def test_templates_never_disable_escaping():
    for t in (PKG / "templates").glob("*.html"):
        text = t.read_text(encoding="utf-8")
        assert "|safe" not in text.replace(" ", ""), t.name
        assert "autoescape false" not in text.lower(), t.name
        assert "<script" not in text.lower(), t.name


def test_no_hardcoded_real_looking_secrets():
    import re
    pat = re.compile(r"AKIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|ghp_[A-Za-z0-9]{20,}")
    for p in SOURCES:
        assert not pat.search(p.read_text(encoding="utf-8")), p.name


def test_dockerfile_hardening():
    text = (PKG.parent / "Dockerfile").read_text()
    assert "USER 10001" in text and '"web_decoy.serve"' in text
    serve = (PKG / "serve.py").read_text()
    for setting in ("proxy_headers=False", "access_log=False", "server_header=False",
                    "http=HeaderDeadlineH11Protocol", "limit_concurrency=200"):
        assert setting in serve, setting


def _compose(name):
    path = PKG.parent.parent.parent / name
    return path.read_text() if path.exists() else None


def test_default_compose_is_isolated():
    """Phase 5: no published port, internal network, host unreachable (P12)."""
    compose = _compose("docker-compose.web.yml")
    if compose is None:
        pytest.skip("compose file not mounted")
    assert "ports:" not in compose
    assert "internal: true" in compose
    assert 'com.docker.network.bridge.inhibit_ipv4: "true"' in compose
    assert "read_only: true" in compose and "cap_drop: [ALL]" in compose
    assert "restart: unless-stopped" in compose  # security fix F4
    assert "no-new-privileges:true" in compose


def test_browse_override_binds_localhost_only():
    browse = _compose("docker-compose.web.browse.yml")
    if browse is None:
        pytest.skip("compose file not mounted")
    assert '"127.0.0.1:8080:8080"' in browse and "0.0.0.0" not in browse


def test_csp_blocks_scripts(client):
    csp = client.get("/").headers["content-security-policy"]
    assert "script-src 'none'" in csp and "object-src 'none'" in csp
