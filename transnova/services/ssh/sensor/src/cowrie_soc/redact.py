"""Decide what may be stored about attacker activity.

Project rule: attacker input is not recorded unless it is known to be needed.
Every event type has a list of allowed fields; anything else is dropped, and an
event type not listed here keeps only its metadata. Any failure while cleaning
also falls back to metadata only, so raw text can never pass through by accident.

This is prevention first and pattern matching second. It cannot find every secret:
an ordinary word passed to an allowed program (`cat maple7`) looks like a filename
and is kept. See docs/safety-and-isolation.md for the limits.

The same file is baked into Cowrie as cowrie/core/soc_redact.py and used by the
sensor as a second check. tests/test_redact.py keeps the two copies identical.
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
from collections import Counter
from collections.abc import Callable
from typing import Any

R = "__REDACTED__"

MAX_LINE_CHARS = 4096
MAX_WORD_CHARS = 512
MAX_SHELL_DEPTH = 3
MAX_META_CHARS = 128
RANDOM_MIN_CHARS = 20
RANDOM_MIN_ENTROPY = 3.0  # low on purpose: 32 hex digits often measure under 3.6

# In memory only, new at each start: the pseudonyms cannot be reversed by guessing names.
_PSEUDONYM_KEY = os.urandom(32)

SAFE_USERNAMES = frozenset("""
root admin administrator user test guest ubuntu debian centos fedora pi oracle postgres mysql
mariadb ftp ftpuser git www www-data nginx apache tomcat jenkins deploy ansible vagrant docker
backup support operator service default ec2-user azureuser
""".split())
_PSEUDONYM = re.compile(r"^(?:user|file)_[0-9a-f]{8}(?:\.[a-z0-9]{1,8})?$")

_WRAPPERS = {"sudo", "nohup", "busybox", "env", "time", "nice", "exec", "command", "stdbuf", "doas", "timeout"}
_SHELLS = {"sh", "bash", "dash", "ash", "zsh", "ksh"}
# Programs whose arguments the detection rules read. Anything else keeps its name and flags only.
_SAFE_PROGRAMS = frozenset("""
cat tac head tail less more strings base64 xxd od nl vi vim view nano grep egrep fgrep awk sed sort
uniq cut cp scp tar zip gzip gunzip unzip openssl file wc uname hostnamectl lscpu lsb_release
dmidecode uptime free df lspci lsmod lsblk arch nproc lsusb whoami id who w users logname ls find
locate tree dir du ifconfig route arp nmcli iwconfig ipconfig ip netstat ss ps top htop pstree
pgrep wget curl tftp ftpget fetch lwp-download aria2c chmod chown cd pwd mkdir rm rmdir mv touch
ln shred truncate history unset export getent lastlog last compgen unshadow hostname lsof iptables
date which whereis exit logout clear kill pkill ssh passwd crontab service systemctl mount umount
dd apt apt-get yum
""".split())
# Options whose VALUE is secret, attached or as the next word.
_SECRET_OPTIONS: dict[str, tuple[str, ...]] = {
    "curl": ("-u", "--user", "-U", "--proxy-user", "-E", "--cert", "-H", "--header", "--oauth2-bearer",
             "-d", "--data", "--data-raw", "--data-binary", "--data-urlencode", "-F", "--form", "-b", "--cookie"),
    "wget": ("--password", "--http-password", "--ftp-password", "--proxy-password", "--header", "--post-data",
             "--user", "--http-user", "--ftp-user"),
    "zip": ("-P", "--password"),
    "unzip": ("-P",),
    "openssl": ("-pass", "-passin", "-passout", "-k"),
    "ftpget": ("-p", "--password"),
    "ssh": ("-i",),
    "scp": ("-i",),
}

_KEY = r"[A-Za-z0-9_.\-]*(?:pass|pwd|secret|token|api[_-]?key|apikey|auth|cred|private[_-]?key)[A-Za-z0-9_.\-]*"
_KEY_VALUE = re.compile(rf"({_KEY})=[^,&\s]+", re.IGNORECASE)
_SECRET_OPTION = re.compile(rf"^--?{_KEY}$", re.IGNORECASE)
_URL_USERINFO = re.compile(r"([a-z][a-z0-9+.\-]*://)[^/\s@]+@", re.IGNORECASE)
_USER_PASS_HOST = re.compile(r"^[^/\s:@]+:[^/\s@]+@\S+$")
_SECRET_QUERY = re.compile(rf"([?&]{_KEY}=)[^&\s]*", re.IGNORECASE)
_SECRET_HEADER = re.compile(r"(authorization|x-api-key|cookie|x-auth-token)\s*:\s*.+", re.IGNORECASE)
_RANDOM_TOKEN = re.compile(r"[A-Za-z0-9+/=_\-]+")
_PLAIN_PROGRAM = re.compile(r"^[a-z][a-z0-9_+.\-]*$")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_KEPT_ASSIGNMENT = re.compile(r"^(?:HISTFILE|HISTFILESIZE|HISTSIZE|HISTCONTROL)=")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_KEPT_ENV_NAME = re.compile(r"^(?:LANG|LC_[A-Z]+|TERM)$")
_KEPT_ENV_VALUE = re.compile(r"^[A-Za-z0-9_.@:\-]{0,64}$")
_CLIENT_VERSION = re.compile(r"^SSH-[0-9.]{1,8}-[A-Za-z0-9._+ \-]{1,64}$")
_HEX = re.compile(r"^[0-9a-fA-F:]{1,128}$")
_WORD = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
_EXTENSION = re.compile(r"^\.[a-z0-9]{1,8}$")
_OPERATORS = ("&&", "||", ";;", "|&", ";", "|", "&")

_META_TEXT = ("eventid", "timestamp", "session", "src_ip", "dst_ip", "protocol", "sensor", "uuid")
_META_NUMBER = ("src_port", "dst_port", "time")


def _entropy(text: str) -> float:
    size = len(text)
    return -sum(n / size * math.log2(n / size) for n in Counter(text).values())


def _unquote(word: str) -> str:
    return word[1:-1] if len(word) >= 2 and word[0] == word[-1] and word[0] in "'\"" else word


def _random_token(text: str) -> bool:
    return (len(text) >= RANDOM_MIN_CHARS and _RANDOM_TOKEN.fullmatch(text) is not None
            and re.search(r"\d", text) is not None and re.search(r"[A-Za-z]", text) is not None
            and _entropy(text) >= RANDOM_MIN_ENTROPY)


def looks_random(word: str) -> bool:
    bare = _unquote(word)
    if bare.startswith(("/", "./", "../", "~/")):  # a path: judge each part, not the whole length
        return any(_random_token(part) for part in bare.split("/"))
    return _random_token(bare)


def _pseudonym(prefix: str, value: str) -> str:
    return f"{prefix}_{hmac.new(_PSEUDONYM_KEY, value.encode('utf-8', 'replace'), hashlib.sha256).hexdigest()[:8]}"


def safe_username(value: Any) -> str:
    """Common account names are kept; anything else may be a password typed in the wrong box."""
    if not isinstance(value, str):
        return R
    if value == "" or value in SAFE_USERNAMES or _PSEUDONYM.fullmatch(value):
        return value
    return _pseudonym("user", value)


def clean_word(word: str) -> str:
    """Rules for every word of every program."""
    if len(word) > MAX_WORD_CHARS:
        return R
    bare = _unquote(word)
    if _USER_PASS_HOST.match(bare):
        return f"{R}@{bare.rsplit('@', 1)[1]}"
    cleaned = _URL_USERINFO.sub(rf"\1{R}@", bare)
    cleaned = _SECRET_QUERY.sub(rf"\1{R}", cleaned)
    cleaned = _KEY_VALUE.sub(rf"\1={R}", cleaned)
    if _SECRET_HEADER.search(cleaned):
        cleaned = _SECRET_HEADER.sub(rf"\1: {R}", cleaned)
    if cleaned != bare:
        quote = word[0] if bare != word else ""  # an unquoted & would read as a shell operator
        return f"{quote}{cleaned}{quote}"
    return R if looks_random(word) else word


def _clean_unknown(word: str) -> str:
    """A program we know nothing about: keep flag names only."""
    if len(word) > MAX_WORD_CHARS:
        return R
    bare = _unquote(word)
    if bare.startswith("--"):
        return bare.split("=", 1)[0] + (f"={R}" if "=" in bare else "")
    if bare.startswith("-") and len(bare) >= 2:
        return bare[:2] + (R if len(bare) > 2 else "")
    return R


def _clean_program(word: str) -> str:
    """A word typed at the prompt may be a password pasted in the wrong place."""
    bare = _unquote(word)
    if "/" in bare or bare in _SAFE_PROGRAMS or bare in _WRAPPERS or bare in _SHELLS:
        return R if len(word) > MAX_WORD_CHARS else word
    if _PLAIN_PROGRAM.match(bare) and not (re.search(r"\d", bare) and len(bare) >= 7):
        return word
    return R


def _clean_assignment(word: str) -> str:
    return word if _KEPT_ASSIGNMENT.match(word) else f"{word.split('=', 1)[0]}={R}"


def _clean_safe_args(program: str, args: list[str]) -> list[str]:
    secret_options = _SECRET_OPTIONS.get(program, ())
    out: list[str] = []
    hide_next = False
    for word in args:
        if hide_next:
            hide_next = False
            out.append(R)
            continue
        bare = _unquote(word)
        if program == "export" and _ASSIGNMENT.match(bare):
            out.append(_clean_assignment(bare))
            continue
        option = next((o for o in secret_options if bare == o or (o.startswith("--") and bare.startswith(o + "="))
                       or (len(o) == 2 and bare.startswith(o) and len(bare) > 2)), None)
        if option is not None:
            if bare == option:
                out.append(word)
                hide_next = True
            else:
                out.append(f"{option}={R}" if option.startswith("--") else option + R)
        elif _SECRET_OPTION.match(bare):
            out.append(word)
            hide_next = True
        else:
            out.append(clean_word(word))
    return out


def _clean_shell_args(args: list[str], depth: int) -> list[str]:
    """`-c` holds a command line. The first other operand is a script; later words are its arguments."""
    out: list[str] = []
    inner_next = False
    script_seen = False
    for word in args:
        if inner_next:
            inner_next = False
            script_seen = True
            inner = redact_line(_unquote(word), depth + 1) if depth < MAX_SHELL_DEPTH else R
            out.append(R if "'" in inner else f"'{inner}'")
        elif script_seen:
            out.append(_clean_unknown(word))
        elif word == "-c":
            inner_next = True
            out.append(word)
        else:
            script_seen = not word.startswith("-")
            out.append(clean_word(word))
    return out


def _clean_command(words: list[str], depth: int) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(words):
        if _ASSIGNMENT.match(words[i]):
            out.append(_clean_assignment(words[i]))
            i += 1
            continue
        program = _unquote(words[i]).rsplit("/", 1)[-1]
        if program not in _WRAPPERS:
            break
        out.append(words[i])
        i += 1
        while i < len(words) and (words[i].startswith("-")
                                  or (program == "timeout" and re.fullmatch(r"\d+[smhd]?", words[i]))):
            if words[i] in ("-u", "-g", "-p", "-C", "-h", "-n") and i + 1 < len(words):
                out.append(words[i])
                i += 1
            out.append(words[i])
            i += 1
    if i >= len(words):
        return out
    program = _unquote(words[i]).rsplit("/", 1)[-1]
    out.append(_clean_program(words[i]))
    args = words[i + 1:]
    if program in _SHELLS:
        return out + _clean_shell_args(args, depth)
    if program in _SAFE_PROGRAMS:
        return out + _clean_safe_args(program, args)
    return out + [_clean_unknown(word) for word in args]


def _tokenize(line: str) -> list[tuple[str, str]]:
    """Split into (kind, text), kind being word, space or op. Bad quoting is tolerated."""
    tokens: list[tuple[str, str]] = []
    word: list[str] = []
    quote: str | None = None
    i = 0

    def flush() -> None:
        if word:
            tokens.append(("word", "".join(word)))
            word.clear()

    while i < len(line):
        char = line[i]
        if quote:
            word.append(char)
            quote = None if char == quote else quote
            i += 1
        elif char == "\\" and i + 1 < len(line):
            word.append(line[i:i + 2])
            i += 2
        elif char in "'\"":
            quote = char
            word.append(char)
            i += 1
        elif char.isspace():
            flush()
            start = i
            while i < len(line) and line[i].isspace():
                i += 1
            tokens.append(("space", line[start:i]))
        else:
            operator = next((o for o in _OPERATORS if line.startswith(o, i)), None)
            if operator:
                flush()
                tokens.append(("op", operator))
                i += len(operator)
            else:
                word.append(char)
                i += 1
    flush()
    return tokens


def redact_line(line: Any, depth: int = 0) -> str:
    """Clean one command line. Words are split by shell rules; spacing is kept."""
    if not isinstance(line, str):
        return R
    tokens = _tokenize(line[:MAX_LINE_CHARS])
    commands: list[list[int]] = [[]]
    for index, (kind, _) in enumerate(tokens):
        if kind == "op":
            commands.append([])
        elif kind == "word":
            commands[-1].append(index)
    for indexes in commands:
        cleaned = _clean_command([tokens[i][1] for i in indexes], depth)
        for position, index in enumerate(indexes):
            tokens[index] = ("word", cleaned[position] if position < len(cleaned) else R)
    return "".join(text for _, text in tokens)


def _hidden(_value: Any) -> str:
    return R


def _clean_url(value: Any) -> str:
    return clean_word(value) if isinstance(value, str) else R


def _clean_file_name(value: Any) -> str:
    """A file name can hold a secret: keep only a pseudonym and a plain extension."""
    if not isinstance(value, str):
        return R
    if _PSEUDONYM.fullmatch(value):
        return value
    base = value.rstrip("/").rsplit("/", 1)[-1]
    extension = base[base.rfind("."):].lower() if "." in base else ""
    return _pseudonym("file", base) + (extension if _EXTENSION.fullmatch(extension) else "")


def _clean_stored_file(value: Any) -> str:
    """Stored files are named by SHA-256; keep that name and drop the rest of the path."""
    if not isinstance(value, str):
        return R
    base = value.rsplit("/", 1)[-1]
    return base if re.fullmatch(r"[0-9a-f]{64}", base) else R


def _pattern(pattern: re.Pattern[str]) -> Callable[[Any], str]:
    def clean(value: Any) -> str:
        return value if isinstance(value, str) and pattern.fullmatch(value) else R
    return clean


def _number(value: Any) -> int | float | None:
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _flag(value: Any) -> bool | None:
    return value if isinstance(value, bool) else None


_word = _pattern(_WORD)
_hex = _pattern(_HEX)
_LOGIN = {"username": safe_username, "fingerprint": _hex, "type": _word}
_FILE = {"url": _clean_url, "outfile": _clean_stored_file, "shasum": _hex, "destfile": _clean_file_name,
         "filename": _clean_file_name, "duplicate": _flag}

# The allowed fields of each event type. Not listed = not stored.
_FIELDS: dict[str, dict[str, Callable[[Any], Any]]] = {
    "cowrie.session.connect": {},
    "cowrie.session.closed": {"duration_ms": _number},
    "cowrie.session.params": {"arch": _word},
    "cowrie.client.version": {"version": _pattern(_CLIENT_VERSION)},
    "cowrie.client.kex": {"hassh": _hex},
    "cowrie.client.size": {"width": _number, "height": _number},
    "cowrie.client.fingerprint": _LOGIN,
    "cowrie.login.success": _LOGIN,
    "cowrie.login.failed": _LOGIN,
    "cowrie.command.input": {"input": redact_line},
    "cowrie.command.failed": {"input": redact_line},
    "cowrie.command.success": {"input": _hidden},
    "cowrie.session.input": {"input": _hidden},
    "cowrie.command.chpasswd": {"username": safe_username},
    "cowrie.session.file_download": _FILE,
    "cowrie.session.file_download.failed": {"url": _clean_url},
    "cowrie.session.file_upload": _FILE,
}
_TYPED_INPUT_EVENTS = ("cowrie.command.input", "cowrie.command.failed")
_CAPTURED_INPUT = re.compile(r"^Saved (?:stdin|redir) contents")


def metadata_only(event: Any, keep_format: bool = False) -> dict[str, Any]:
    """The fail-closed result: identity and timing, no attacker text."""
    out: dict[str, Any] = {}
    if isinstance(event, dict):
        for key in _META_TEXT:
            value = event.get(key)
            if isinstance(value, str) and len(value) <= MAX_META_CHARS:
                out[key] = value
        for key in _META_NUMBER:
            if _number(event.get(key)) is not None:
                out[key] = event[key]
        if event.get("late") is True:
            out["late"] = True
    if keep_format:
        out["message"] = out.get("eventid", "event")
    return out


def _sanitize(event: dict[str, Any], keep_format: bool) -> dict[str, Any]:
    out = metadata_only(event)
    eventid = event.get("eventid")
    if eventid == "cowrie.client.var":
        name = event.get("name")
        known = isinstance(name, str) and _ENV_NAME.fullmatch(name) is not None
        out["name"] = name if known else R
        value = event.get("value")
        keep = known and _KEPT_ENV_NAME.fullmatch(name) and isinstance(value, str) and _KEPT_ENV_VALUE.fullmatch(value)
        out["value"] = value if keep else R
    elif eventid in _FIELDS:
        for key, clean in _FIELDS[eventid].items():
            if key in event:
                value = clean(event[key])
                if value is not None:
                    out[key] = value
        if eventid in _TYPED_INPUT_EVENTS and "realm" in event:
            out["input"] = R  # typed into a running program, not a command
    else:
        return metadata_only(event, keep_format)

    description = str(event.get("format") or event.get("message") or "")
    captured = eventid == "cowrie.session.file_download" and _CAPTURED_INPUT.match(description)
    if captured:  # short typed input: even its hash can be guessed
        out = {k: v for k, v in out.items() if k not in ("shasum", "outfile", "destfile", "url")}
    if keep_format:
        if captured:
            out["message"] = "Saved piped or redirected input; content and hash are not kept"
        elif isinstance(event.get("format"), str):
            out["format"] = event["format"]
        else:
            out["message"] = str(eventid)
    return out


def sanitize_event(event: Any, keep_format: bool = False) -> dict[str, Any]:
    """Return only what may be stored. `keep_format` is for Cowrie, which renders messages after this."""
    try:
        return _sanitize(event, keep_format)
    except Exception:  # noqa: BLE001 - a cleaning failure must never let raw text through
        return metadata_only(event, keep_format)
