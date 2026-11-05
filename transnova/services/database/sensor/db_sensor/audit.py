"""Parse MariaDB server_audit lines.

Format, verified against MariaDB 11.4.9:
    20261031 14:54:45,HOST,decoy_user,127.0.0.2,7,135,QUERY,transnova_logistics,'SELECT 1',0

The usernames in FAILED_CONNECT lines are attacker-chosen and are not escaped, so a plain
comma split could be steered by an attacker. The regex anchors on the numeric connection and
query ids plus the fixed operation names, and takes the client host as the last comma field
before them. Everything else is parsed from the right.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone

_LINE = re.compile(
    r"^(?P<ts>\d{8} \d{2}:\d{2}:\d{2}),(?P<server>[^,]*),(?P<user>.*),(?P<host>[^,]*),"
    r"(?P<conn>\d+),(?P<qid>\d+),(?P<op>QUERY|CONNECT|FAILED_CONNECT|DISCONNECT|CHANGEUSER|"
    r"PROXY_CONNECT|READ|WRITE|CREATE|ALTER|DROP|RENAME),(?P<rest>.*)$",
    re.DOTALL,
)
# Statement lines come from a logged-in account, whose name has no comma, so they are anchored
# from the left. _LINE's greedy username would otherwise run into attacker-chosen query text:
# SELECT ',1,2,READ,x,y' made a real statement parse as a READ of a table called x.
_STATEMENT = re.compile(
    r"^(?P<ts>\d{8} \d{2}:\d{2}:\d{2}),(?P<server>[^,]*),(?P<user>[^,]*),(?P<host>[^,]*),"
    r"(?P<conn>\d+),(?P<qid>\d+),(?P<op>QUERY|READ|WRITE|CREATE|ALTER|DROP|RENAME),(?P<rest>.*)$",
    re.DOTALL,
)
_PREFIX = re.compile(r"^\d{8} \d{2}:\d{2}:\d{2},")
_TAIL = re.compile(r",\d+,\d+,(FAILED_CONNECT|CONNECT|DISCONNECT),[^,]*,,\d+$")
_RETCODE = re.compile(r",(\d+)$")
QUERY_LOG_LIMIT = 131072  # server_audit_query_log_limit in conf/honeypot.cnf
TABLE_OPERATIONS = frozenset({"READ", "WRITE", "CREATE", "ALTER", "DROP", "RENAME"})
_UNESCAPE = re.compile(r"\\(.)", re.DOTALL)
_ESC = {"n": "\n", "r": "\r", "t": "\t", "\\": "\\", "'": "'"}


@dataclass(frozen=True)
class AuditRecord:
    timestamp: datetime
    server: str
    user: str
    host: str
    connection_id: int
    query_id: int
    operation: str
    database: str
    query: str
    retcode: int
    truncated: bool
    raw: str


def _unescape(text: str) -> str:
    return _UNESCAPE.sub(lambda m: _ESC.get(m.group(1), m.group(0)), text)


class LineAssembler:
    """Rejoin a record that a newline split across several physical lines.

    MariaDB writes usernames from failed logins unescaped, so a client can log in as
    "x\\n<a complete fake audit line>\\ny" before authenticating, and the fake line sits in the
    log looking genuine (reproduced on 11.4.9). Such a record starts with a timestamp and server
    name but has no operation fields. Everything up to the line that completes it belongs to
    that one record, including any line in between that looks valid on its own.
    """

    MAX_LINES = 8

    def __init__(self) -> None:
        self.buffer: list[str] = []

    def feed(self, line: str) -> list[str]:
        if self.buffer:
            self.buffer.append(line)
            joined = "\n".join(self.buffer)
            # Only login operations carry the unescaped username, so only their tail can close
            # the record. A complete QUERY line in between is the forgery, not the end.
            if _TAIL.search(line) and _LINE.match(joined):
                self.buffer = []
                return [joined]
            if len(self.buffer) >= self.MAX_LINES:
                self.buffer = []
                return [joined]
            return []
        if _LINE.match(line) or not _PREFIX.match(line):
            return [line]
        self.buffer = [line]
        return []


def parse_line(line: str) -> AuditRecord | None:
    """Returns None for a line that does not match; the caller keeps it as malformed."""
    # A login tail wins: that is the one line type where the username is attacker-chosen.
    m = (None if _TAIL.search(line) else _STATEMENT.match(line)) or _LINE.match(line)
    if not m:
        return None
    rest = m.group("rest")
    if m.group("op") in TABLE_OPERATIONS:  # READ,db,table, has no return code
        database, _, table = rest.partition(",")
        return AuditRecord(
            timestamp=datetime.strptime(m.group("ts"), "%Y%m%d %H:%M:%S").replace(tzinfo=timezone.utc),
            server=m.group("server"), user=m.group("user"), host=m.group("host"),
            connection_id=int(m.group("conn")), query_id=int(m.group("qid")), operation=m.group("op"),
            database=database, query=table.rstrip(","), retcode=0, truncated=False, raw=line)
    retcode = 0
    tail = _RETCODE.search(rest)
    truncated = False
    if tail:
        retcode = int(tail.group(1))
        rest = rest[: tail.start()]
    else:
        truncated = True  # a query cut at server_audit_query_log_limit loses its closing fields
    database, _, obj = rest.partition(",")
    if len(obj) >= QUERY_LOG_LIMIT:
        truncated = True  # the plugin closes a cut statement normally, so only length shows it
    if obj.startswith("'"):
        obj = obj[1:]
        if obj.endswith("'") and not obj.endswith("\\'"):
            obj = obj[:-1]
        else:
            truncated = True
    return AuditRecord(
        timestamp=datetime.strptime(m.group("ts"), "%Y%m%d %H:%M:%S").replace(tzinfo=timezone.utc),
        server=m.group("server"),
        user=m.group("user"),
        host=m.group("host"),
        connection_id=int(m.group("conn")),
        query_id=int(m.group("qid")),
        operation=m.group("op"),
        database=database,
        query=_unescape(obj),
        retcode=retcode,
        truncated=truncated,
        raw=line,
    )
