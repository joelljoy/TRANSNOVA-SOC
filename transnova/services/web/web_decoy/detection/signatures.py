"""Stateless signature rules. Input is normalized and capped first; every
pattern is linear (no nested quantifiers) to stay ReDoS-safe."""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from .mappings import NO_SUCCESS, make
from .normalize import normalize

MAX_FIELDS = 120

SQLI = [
    re.compile(r"'\s{0,5}(?:or|and)\s{1,5}['\"]?[\w]{1,20}['\"]?\s{0,5}(?:=|like|<|>)"),   # ' or 1=1 / ' or 'a'='a
    re.compile(r"\bunion\s{1,5}(?:all\s{1,5})?select\b"),
    re.compile(r"['\"`)]\s{0,5}(?:--|#|/\*)"),                                               # quote then comment
    re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s{0,5}\(|\bwaitfor\s{1,5}delay\b"),
    re.compile(r"\binformation_schema\b|\bsqlite_master\b|\bsys\.(?:tables|objects|databases)\b"),
    re.compile(r";\s{0,5}(?:drop|delete|insert|update|truncate|shutdown|exec|select)\b"),
    re.compile(r"\b(?:or|and)\s{1,5}\d{1,10}\s{0,5}=\s{0,5}\d{1,10}\b"),                    # or 1=1 without quote
    re.compile(r"\b(?:extractvalue|updatexml|load_file)\s{0,5}\("),
]

XSS = [
    re.compile(r"<\s{0,5}/?\s{0,5}script\b"),
    re.compile(r"\bon(?:error|load|mouseover|mouseenter|focus|blur|click|toggle|begin|animationstart|"
               r"pageshow|input|change|submit)\s{0,5}="),
    re.compile(r"javascript\s{0,5}:|vbscript\s{0,5}:|data\s{0,5}:\s{0,5}text/html"),
    re.compile(r"<\s{0,5}(?:iframe|object|embed|svg|math|base|meta)\b"),
    re.compile(r"\bdocument\.cookie\b|\bsrcdoc\s{0,5}="),
]

TRAVERSAL = [
    re.compile(r"\.\.[/\\]|[/\\]\.\.(?:$|[/\\])"),
    re.compile(r"/etc/(?:passwd|shadow|hosts|group)\b|/proc/self/"),
    re.compile(r"\b(?:win|boot|system)\.ini\b|[a-z]:[/\\]windows[/\\]|\\windows\\"),
]

SSRF_SCHEMES = ("file", "gopher", "dict", "ftp", "ldap", "tftp", "jar", "netdoc", "php", "expect")
SSRF_HOSTS = ("localhost", "metadata.google.internal", "metadata", "instance-data")
URLISH = re.compile(r"^[a-z][a-z0-9+.-]{1,15}://")

SENSITIVE_EXACT = {
    "/admin", "/admin/", "/backup", "/backup/", "/config", "/api", "/api/", "/.env", "/config.php",
    "/wp-login.php", "/wp-admin", "/wp-admin/", "/phpmyadmin", "/phpmyadmin/", "/server-status",
    "/.ds_store", "/web.config", "/actuator", "/actuator/env", "/console", "/.htaccess", "/.htpasswd",
}
SENSITIVE_PREFIX = ("/.git/", "/.svn/", "/.aws/", "/.ssh/", "/admin/", "/backup/", "/.env.")
BACKUP_FILE = re.compile(r"\.(?:sql|bak|old|orig|swp|zip|tar|tgz|gz|7z|rar|dump)$")

SCRIPT_EXT = re.compile(r"\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl)$")
SHELL_NAMES = {"shell", "cmd", "c99", "r57", "wso", "b374k", "webshell", "backdoor", "up", "x", "1",
               "alfa", "indoxploit", "mini", "sh", "bypass"}

EXEC_UPLOAD_TYPES = {"application/x-php", "application/x-elf", "application/x-msdownload",
                     "text/x-script", "text/x-server-page"}
EXEC_UPLOAD_EXT = re.compile(r"\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|sh|bash|py|pl|rb|exe|dll|so|elf|bat|ps1|cgi)$")


def _fields(ctx) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = [("path", ctx.path)]
    out += [(f"query.{k}", v) for k, v in ctx.query]
    out += [(f"form.{k}", v) for k, v in ctx.form]
    out += [(f"json.{k}", str(v)) for k, v in ctx.json_pairs if isinstance(v, (str, int, float))]
    return out[:MAX_FIELDS]


def _internal_host(host: str) -> bool:
    host = host.strip("[]").rstrip(".")
    if not host:
        return False
    if host in SSRF_HOSTS or host.endswith(".localhost") or host.endswith(".internal"):
        return True
    candidates = [host]                      # decimal form (2130706433) is handled below
    if host.startswith("0x"):                # hex form: 0x7f000001
        try:
            candidates.append(str(int(host, 16)))
        except ValueError:
            pass
    for c in candidates:
        try:
            ip = ipaddress.ip_address(int(c)) if c.isdigit() else ipaddress.ip_address(c)
        except ValueError:
            continue
        if ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_unspecified or ip.is_reserved:
            return True
    return False


def _ssrf(value: str) -> str | None:
    """Return a description if value is a URL aimed at an internal target or unsafe scheme."""
    if not URLISH.match(value):
        return None
    scheme = value.split("://", 1)[0]
    if scheme in SSRF_SCHEMES:
        return f"URL with non-web scheme '{scheme}'"
    try:
        host = urlsplit(value).hostname or ""
    except ValueError:
        return "malformed URL"
    if scheme in ("http", "https") and _internal_host(host):
        return "URL pointing at a loopback/private/link-local/metadata address"
    return None


def detect_signatures(ctx) -> list[dict[str, Any]]:
    found: dict[str, dict[str, Any]] = {}
    hits: dict[str, int] = {}

    def hit(rule: str, field: str, why: str, **kw):
        hits[rule] = hits.get(rule, 0) + 1
        if rule not in found:
            found[rule] = make(rule, field, why, **kw)

    for field, raw in _fields(ctx):
        text, had_nul = normalize(raw)
        if any(p.search(text) for p in SQLI):
            hit("W-SQLI-01", field, f"SQL injection-like syntax in {field}; " + NO_SUCCESS)
        if any(p.search(text) for p in XSS):
            hit("W-XSS-01", field, f"script/markup injection-like syntax in {field}; recorded, never rendered")
        if had_nul or any(p.search(text) for p in TRAVERSAL):
            why = "NUL byte" if had_nul else "directory traversal sequence or system file name"
            hit("W-PATH-01", field, f"{why} in {field}; no file was opened")
        if field != "path":
            desc = _ssrf(text)
            if desc:
                hit("W-SSRF-01", field, f"{desc} in {field}; the URL was never fetched")

    path, _ = normalize(ctx.path)
    base = path.rsplit("/", 1)[-1]
    stem = base.rsplit(".", 1)[0]
    if SCRIPT_EXT.search(path) and (stem in SHELL_NAMES or "/upload" in path):
        hit("W-SHELL-01", "path", "request for a known webshell-style script path; "
                                  "path probe only, no webshell exists or was deployed")
    elif path in SENSITIVE_EXACT or path.startswith(SENSITIVE_PREFIX) or BACKUP_FILE.search(path):
        hit("W-ENUM-01", "path", "request for an admin/backup/config/VCS path commonly targeted by scanners")

    upload = (ctx.route or {}).get("upload")
    if upload:
        name = (upload.get("file_name") or "").lower()
        sniffed = upload.get("sniffed_type") or ""
        declared = (upload.get("declared_type") or "").lower()
        reasons = []
        if sniffed in EXEC_UPLOAD_TYPES:
            reasons.append(f"content looks like {sniffed}")
        if EXEC_UPLOAD_EXT.search(name):
            reasons.append("executable/script file extension")
        if declared.startswith("image/") and not sniffed.startswith("image/"):
            reasons.append("declared as an image but content is not")
        script_markers = upload.get("script_markers") or []
        if script_markers:
            reasons.append("embedded server-side script markers (" + ", ".join(script_markers) + ")")
        if reasons:
            hit("W-UPL-01", "upload", "; ".join(reasons) + "; content was discarded, never stored or executed")

    for rule, n in hits.items():
        if n > 1:
            found[rule]["rationale"] += f" (matched in {n} fields)"
    return list(found.values())
