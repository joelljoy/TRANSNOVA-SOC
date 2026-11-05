"""Static analysis of shell command lines typed into the Cowrie emulated shell.

Command text is untrusted attacker input. It is only tokenized and compared
against fixed tables here; it is never executed, interpolated into a shell,
used as a filesystem path, or passed to SQL.

Cowrie logs one `cowrie.command.input` per line the client sent, so a line can
hold several commands (`uname -a; cat /etc/shadow | head`). Each line is split
into simple commands, wrapper programs (sudo, busybox, nohup, ...) are peeled
off, and every simple command is checked against evidence-based indicators.
"""

from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass, field
from posixpath import basename

_SEPARATORS = {";", "&&", "||", "|", "&", "|&", ";;"}
_REDIRECTS = {">", ">>", "<", "<<", "<<<", ">&", "<&", "&>", "&>>", ">|"}
_IGNORED_PUNCT = {"(", ")", "{", "}"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_URL = re.compile(r"^(?:https?|ftp|tftp)://\S+", re.IGNORECASE)

# Programs that only wrap another command.
_WRAPPERS = {"sudo", "nohup", "busybox", "env", "time", "nice", "exec", "command", "stdbuf", "doas"}
# Wrappers whose options take a value (`sudo -u root`, `timeout 5`).
_WRAPPER_OPTS_WITH_VALUE = {"sudo": {"-u", "-g", "-C", "-h", "-p"}, "nice": {"-n"}}

# Programs that read (display/search/copy) file arguments.
_FILE_READERS = {
    "cat", "tac", "head", "tail", "less", "more", "strings", "base64", "xxd", "od", "nl",
    "vi", "vim", "view", "nano", "grep", "egrep", "fgrep", "awk", "sed", "sort", "uniq",
    "cut", "cp", "scp", "tar", "zip", "gzip", "openssl", "file", "wc",
}

_SYSINFO_PROGRAMS = {
    "uname", "hostnamectl", "lscpu", "lsb_release", "dmidecode", "uptime", "free", "df",
    "lspci", "lsmod", "lsblk", "arch", "nproc", "lsusb",
}
_SYSINFO_FILES = {
    "/etc/os-release", "/etc/issue", "/etc/lsb-release", "/etc/debian_version",
    "/etc/redhat-release", "/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/etc/machine-id",
}
_OWNER_PROGRAMS = {"whoami", "id", "who", "w", "users", "logname"}
_ACCOUNT_FILES = {"/etc/passwd", "/etc/group"}
_SHADOW_FILES = {"/etc/shadow", "/etc/gshadow", "/etc/master.passwd"}
_FILE_DISCOVERY_PROGRAMS = {"ls", "find", "locate", "tree", "dir", "du"}
_NETCONF_PROGRAMS = {"ifconfig", "route", "arp", "nmcli", "iwconfig", "ipconfig"}
_IP_NETCONF_SUBCOMMANDS = {"a", "addr", "address", "r", "route", "l", "link", "n", "neigh", "neighbour"}
_NETCONF_FILES = {"/etc/resolv.conf", "/etc/hosts", "/etc/network/interfaces", "/etc/hostname"}
_NETCONN_PROGRAMS = {"netstat", "ss"}
_PROCESS_PROGRAMS = {"ps", "top", "htop", "pstree", "pgrep"}
_DOWNLOADERS = {"wget", "curl", "tftp", "ftpget", "fetch", "lwp-download", "aria2c"}
_HISTORY_ASSIGNMENTS = ("HISTFILE=", "HISTSIZE=0", "HISTFILESIZE=0")
# Programs whose LAST operand is a destination (written, not read).
_COPY_PROGRAMS = {"cp", "scp"}
_INTERPRETERS = {"sh", "bash", "dash", "ash", "zsh", "ksh", "python", "python3", "perl"}
# Basenames that commonly hold secrets (generic, not honeypot specific).
CREDENTIAL_FILE_NAMES = {
    ".env", ".my.cnf", ".pgpass", ".netrc", ".git-credentials", "credentials",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "wp-config.php", ".htpasswd",
}


@dataclass(frozen=True)
class SimpleCommand:
    program: str
    args: tuple[str, ...]


@dataclass(frozen=True)
class Indicator:
    """One piece of evidence: this command matched this technique, because ..."""

    technique_id: str
    reason: str
    value: str


@dataclass
class CommandAnalysis:
    line: str
    commands: list[SimpleCommand] = field(default_factory=list)
    indicators: list[Indicator] = field(default_factory=list)
    # (path operand, effective `cd` target from earlier on the same line or None)
    file_reads: list[tuple[str, str | None]] = field(default_factory=list)
    download_urls: list[str] = field(default_factory=list)
    download_outputs: list[str] = field(default_factory=list)
    chmod_exec_targets: list[str] = field(default_factory=list)
    executed_paths: list[str] = field(default_factory=list)
    cd_targets: list[str] = field(default_factory=list)
    parse_fallback: bool = False

    @property
    def technique_ids(self) -> list[str]:
        out: list[str] = []
        for ind in self.indicators:
            if ind.technique_id not in out:
                out.append(ind.technique_id)
        return out


def split_commands(line: str) -> tuple[list[list[str]], bool]:
    """Split a command line into token lists, one per simple command.

    Returns (commands, used_fallback). Falls back to a naive split when the
    line is not valid shell syntax (e.g. unbalanced quotes).
    """
    commands: list[list[str]] = []
    fallback = False
    for physical in line.splitlines() or [""]:
        try:
            lexer = shlex.shlex(physical, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            tokens = list(lexer)
        except ValueError:
            fallback = True
            for part in re.split(r"\|\||&&|[;|&]", physical):
                if part.split():
                    commands.append(part.split())
            continue
        current: list[str] = []
        skip_next = False
        for tok in tokens:
            if skip_next:
                skip_next = False
                continue
            if tok in _SEPARATORS:
                if current:
                    commands.append(current)
                current = []
            elif tok in _REDIRECTS:
                skip_next = True
            elif tok in _IGNORED_PUNCT:
                continue
            else:
                current.append(tok)
        if current:
            commands.append(current)
    return commands, fallback


def _strip_wrappers(tokens: list[str]) -> list[str]:
    toks = list(tokens)
    while toks:
        while toks and _ASSIGNMENT.match(toks[0]):
            toks.pop(0)
        if not toks:
            break
        prog = basename(toks[0])
        if prog == "timeout":
            toks.pop(0)
            while toks and toks[0].startswith("-"):
                toks.pop(0)
            if toks:
                toks.pop(0)  # the duration
            continue
        if prog not in _WRAPPERS:
            break
        toks.pop(0)
        with_value = _WRAPPER_OPTS_WITH_VALUE.get(prog, set())
        while toks and toks[0].startswith("-"):
            opt = toks.pop(0)
            if opt in with_value and toks:
                toks.pop(0)
    return toks


def _non_options(args: tuple[str, ...]) -> list[str]:
    return [a for a in args if not a.startswith("-")]


def _matches_any(path: str, candidates: set[str]) -> bool:
    return path in candidates


def analyze(line: str) -> CommandAnalysis:
    result = CommandAnalysis(line=line)
    token_lists, result.parse_fallback = split_commands(line)
    for tokens in token_lists:
        for tok in tokens:  # leading VAR=value assignments, e.g. `HISTSIZE=0` or `HISTFILE=/dev/null cmd`
            if not _ASSIGNMENT.match(tok):
                break
            if tok.startswith(_HISTORY_ASSIGNMENTS):
                _add(result, "T1070.003", "disables shell history via variable assignment", tok)
        toks = _strip_wrappers(tokens)
        if not toks:
            continue
        cmd = SimpleCommand(program=toks[0], args=tuple(toks[1:]))
        result.commands.append(cmd)
        _classify(cmd, result, _cd_hint(result.cd_targets))
    return result


def _cd_hint(cd_targets: list[str]) -> str | None:
    """Combine the `cd` targets seen so far on this line into one target."""
    hint: str | None = None
    for target in cd_targets:
        if target in ("~", "") or target.startswith(("/", "~")) or hint is None:
            hint = target
        else:
            hint = posixpath.join(hint, target)
    return hint


def _add(result: CommandAnalysis, tid: str, reason: str, value: str) -> None:
    result.indicators.append(Indicator(tid, reason, value))


def _classify(cmd: SimpleCommand, result: CommandAnalysis, cd_hint: str | None) -> None:
    prog_path = cmd.program
    prog = basename(prog_path)
    args = cmd.args
    operands = _non_options(args)
    text = " ".join((prog_path, *args))

    if prog == "cd":
        result.cd_targets.append(operands[0] if operands else "~")
        return

    if prog in _FILE_READERS:
        read_operands = operands[:-1] if prog in _COPY_PROGRAMS and len(operands) > 1 else operands
        result.file_reads.extend((path, cd_hint) for path in read_operands)
        for path in read_operands:
            if _matches_any(path, _SYSINFO_FILES) or (path.startswith("/etc/") and path.endswith("release")):
                _add(result, "T1082", f"reads OS/hardware info file {path}", text)
            if _matches_any(path, _ACCOUNT_FILES):
                _add(result, "T1087.001", f"reads local account database {path}", text)
            if _matches_any(path, _SHADOW_FILES):
                _add(result, "T1003.008", f"reads password hash file {path}", text)
            if _matches_any(path, _NETCONF_FILES) or path.startswith("/etc/netplan/"):
                _add(result, "T1016", f"reads network configuration file {path}", text)
            if basename(path) in CREDENTIAL_FILE_NAMES:
                _add(result, "T1552.001", f"reads credential-bearing file {path}", text)

    if prog in _SYSINFO_PROGRAMS:
        _add(result, "T1082", f"runs system information tool `{prog}`", text)
    elif prog in _OWNER_PROGRAMS:
        _add(result, "T1033", f"runs user/owner discovery tool `{prog}`", text)
    elif prog == "getent" and operands and operands[0] in ("passwd", "group"):
        _add(result, "T1087.001", f"enumerates the {operands[0]} database with getent", text)
    elif prog in ("lastlog", "last") or (prog == "compgen" and "-u" in args):
        _add(result, "T1087.001", f"lists local accounts with `{prog}`", text)
    elif prog == "unshadow":
        _add(result, "T1003.008", "combines passwd/shadow with unshadow", text)
    elif prog in _FILE_DISCOVERY_PROGRAMS:
        _add(result, "T1083", f"lists/searches files with `{prog}`", text)
    elif prog in _NETCONF_PROGRAMS:
        _add(result, "T1016", f"runs network configuration tool `{prog}`", text)
    elif prog == "ip" and operands and operands[0] in _IP_NETCONF_SUBCOMMANDS:
        _add(result, "T1016", f"runs `ip {operands[0]}`", text)
    elif prog == "hostname" and any(a in ("-I", "-i", "--all-ip-addresses") for a in args):
        _add(result, "T1016", "lists host IP addresses with hostname", text)
    elif prog in _NETCONN_PROGRAMS or (prog == "lsof" and any(a.startswith("-i") for a in args)):
        _add(result, "T1049", f"lists network connections with `{prog}`", text)
    elif prog in _PROCESS_PROGRAMS:
        _add(result, "T1057", f"lists processes with `{prog}`", text)
    elif prog == "iptables" and any(a in ("-L", "-S", "--list") for a in args):
        _add(result, "T1016", "lists firewall rules with iptables", text)

    if prog in _DOWNLOADERS:
        urls = [a for a in args if _URL.match(a)]
        if prog in ("tftp", "ftpget") and not urls and operands:
            urls = [operands[0]]
        for url in urls:
            result.download_urls.append(url)
            _add(result, "T1105", f"attempts to download a remote file with `{prog}`", url)
        explicit_output = False
        # wget -O FILE / curl -o FILE (curl's -O takes no value: it saves under the URL name).
        value_opts = {"wget": ("-O", "--output-document"), "curl": ("-o", "--output")}.get(prog, ())
        for i, arg in enumerate(args):
            if arg in value_opts and i + 1 < len(args):
                result.download_outputs.append(args[i + 1])
                explicit_output = True
            elif arg.startswith(("--output-document=", "--output=")):
                result.download_outputs.append(arg.split("=", 1)[1])
                explicit_output = True
        if not explicit_output:
            # wget / curl -O save under the URL's last path segment.
            for url in urls:
                name = basename(url.split("?", 1)[0].rstrip("/"))
                if name and "://" not in name:
                    result.download_outputs.append(name)

    if prog == "chmod" and operands:
        mode, targets = operands[0], operands[1:]
        symbolic_exec = re.search(r"[+=][rwxXst]*x", mode) is not None
        octal_exec = re.fullmatch(r"[0-7]{3,4}", mode) is not None and any(int(d) & 1 for d in mode[-3:])
        if symbolic_exec or octal_exec:
            result.chmod_exec_targets.extend(targets)
            _add(result, "T1222.002", f"makes file(s) executable (chmod {mode})", text)

    if "/" in prog_path and prog not in _INTERPRETERS:
        result.executed_paths.append(prog_path)
    elif prog in _INTERPRETERS and operands and not operands[0].startswith("-"):
        result.executed_paths.append(operands[0])

    _classify_history_tampering(prog, args, operands, text, result)


def _classify_history_tampering(
    prog: str, args: tuple[str, ...], operands: list[str], text: str, result: CommandAnalysis
) -> None:
    if prog == "history" and "-c" in args:
        _add(result, "T1070.003", "clears shell history (history -c)", text)
    elif prog == "unset" and any(o in ("HISTFILE", "HISTSIZE") for o in operands):
        _add(result, "T1070.003", "disables shell history (unset HISTFILE)", text)
    elif prog == "export" and any(o.startswith(_HISTORY_ASSIGNMENTS) for o in operands):
        _add(result, "T1070.003", "redirects/disables shell history", text)
    elif prog in ("rm", "shred", "truncate") and any(basename(o).endswith("_history") for o in operands):
        _add(result, "T1070.003", "deletes a shell history file", text)
    elif prog == "ln" and "/dev/null" in operands and any(basename(o).endswith("_history") for o in operands):
        _add(result, "T1070.003", "links shell history to /dev/null", text)

