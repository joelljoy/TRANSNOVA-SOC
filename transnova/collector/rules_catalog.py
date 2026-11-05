"""Every detection rule the SOC knows about, with what it needs and how far it can be trusted.

The sensors decide *what matched* and say why in raw_evidence_redacted.detections[]. This catalogue
decides *what the collector does with a match*: `alerting=False` rules are recorded on the event as
a rule match (detection status "matched") but never open an alert on their own. That is how one
wrong password stays an event: W-AUTH-01, SOC-AUTH-00 and similar single-occurrence signals only
feed the threshold rules that sit above them.

`tested_by` names files and the text that ties them to the rule. tests/test_rules_catalog.py
checks every entry, so a coverage claim on the MITRE page cannot outlive its test. `kind: live`
tests need a running MariaDB or container and are not part of the unit run.

OWASP: sensors emit 2021-edition labels. The SOC reports the current edition, OWASP Top 10:2025,
through OWASP_2025 below, and always keeps the label the sensor actually sent.
"""

from __future__ import annotations

from typing import Any

OWASP_EDITION = "OWASP Top 10:2025"
OWASP_SOURCE = "https://owasp.org/Top10/2025/"
# 2021 label as emitted by the web sensor -> 2025 category. SSRF (A10:2021) was folded into
# Broken Access Control in the 2025 edition.
OWASP_2025 = {
    "A01:2021-Broken Access Control": "A01:2025-Broken Access Control",
    "A03:2021-Injection": "A05:2025-Injection",
    "A04:2021-Insecure Design": "A06:2025-Insecure Design",
    "A05:2021-Security Misconfiguration": "A02:2025-Security Misconfiguration",
    "A07:2021-Identification and Authentication Failures": "A07:2025-Authentication Failures",
    "A10:2021-Server-Side Request Forgery": "A01:2025-Broken Access Control",
}
OWASP_2025_CATEGORIES = [
    ("A01:2025", "Broken Access Control"), ("A02:2025", "Security Misconfiguration"),
    ("A03:2025", "Software Supply Chain Failures"), ("A04:2025", "Cryptographic Failures"),
    ("A05:2025", "Injection"), ("A06:2025", "Insecure Design"), ("A07:2025", "Authentication Failures"),
    ("A08:2025", "Software or Data Integrity Failures"), ("A09:2025", "Security Logging and Alerting Failures"),
    ("A10:2025", "Mishandling of Exceptional Conditions"),
]
# Categories the web decoy cannot observe from request/response evidence. Shown as gaps, not hidden.
OWASP_NOT_OBSERVABLE = {
    "A03:2025": "Supply-chain compromise happens in build and dependency pipelines, not in decoy traffic.",
    "A04:2025": "Weak cryptography is a property of the defended system; probes for it carry no distinct signature here.",
    "A08:2025": "No deserialization endpoint or signed-update flow exists on the decoy to target.",
    "A09:2025": "Logging failures describe the defender; the SOC itself is the control for this category.",
    "A10:2025": "The decoy returns fixed, handled errors, so there is no exceptional-condition behaviour to provoke.",
}

WEB_P0 = "services/web/tests/test_detection_p0.py"
WEB_P1 = "services/web/tests/test_detection_p1.py"
WEB_ANON = "services/web/tests/test_realism_anon.py"
WEB_ADAPT = "services/web/tests/test_adaptive.py"
DB_UNIT = "services/database/tests/test_sensor_unit.py"
DB_READY = "services/database/tests/audit/test_readiness.py"
DB_LIVE = "services/database/tests/live/test_live_e2e.py"
SSH_DET = "services/ssh/sensor/tests/test_detection.py"
COLLECTOR = "collector/tests/test_detection_policy.py"


def _t(path: str, needle: str, kind: str = "unit") -> dict[str, str]:
    return {"path": path, "needle": needle, "kind": kind}


def _r(rule_id: str, name: str, service: str, description: str, logic: str, evidence: str, severity: str,
       confidence: str, false_positives: str, attack: list[str], tested_by: list[dict[str, str]], *,
       owasp: str | None = None, alerting: bool = True, not_detected: str = "") -> dict[str, Any]:
    return {"rule_id": rule_id, "name": name, "service": service, "description": description, "logic": logic,
            "required_evidence": evidence, "default_severity": severity, "confidence_model": confidence,
            "false_positives": false_positives, "attack": attack, "owasp_2021": owasp,
            "owasp_2025": OWASP_2025.get(owasp or ""), "alerting": alerting, "does_not_detect": not_detected,
            "tested_by": tested_by}


A01, A03, A04 = "A01:2021-Broken Access Control", "A03:2021-Injection", "A04:2021-Insecure Design"
A05, A07, A10 = ("A05:2021-Security Misconfiguration", "A07:2021-Identification and Authentication Failures",
                 "A10:2021-Server-Side Request Forgery")

RULES: dict[str, dict[str, Any]] = {r["rule_id"]: r for r in [
    # Web decoy (services/web/web_decoy/detection). Web never claims an exploit succeeded.
    _r("W-ENUM-01", "Sensitive path requested", "web", "One request for an admin, backup, config or VCS path.",
       "Path matches the sensitive-path list.", "request_path", "low", "low: a single request",
       "Crawlers, link checkers and curious users request /admin or /.git routinely.", [],
       [_t(WEB_P0, "W-ENUM-01")], owasp=A05, alerting=False,
       not_detected="Whether the path exists or was readable."),
    _r("W-ENUM-02", "Route scan", "web", "Many distinct missing or forbidden paths from one source.",
       ">= 8 distinct 403/404/bait paths from one source within 60 s.", "request_path, http_status", "medium",
       "medium: volume over a window", "A broken client or stale bookmarks can 404 repeatedly, rarely 8 distinct paths.",
       ["T1595.003"], [_t(WEB_P0, "W-ENUM-02")], owasp=A05),
    _r("W-AUTH-01", "Failed web login", "web", "One failed login to the decoy portal.", "POST /login rejected.",
       "username, outcome", "low", "low: one attempt", "A mistyped password. This is an event, not an attack.",
       [], [_t(WEB_P0, "W-AUTH-01"), _t(COLLECTOR, "W-AUTH-01")], owasp=A07, alerting=False),
    _r("W-AUTH-02", "Repeated failed web logins", "web", "Repeated failures for one username from one source.",
       ">= 5 failures (medium) or >= 15 (high) for one username within 60 s.", "username, outcome, timestamps",
       "medium", "medium at 5, high at 15", "A user retrying a forgotten password can reach 5 quickly.",
       ["T1110.001"], [_t(WEB_P0, "W-AUTH-02")], owasp=A07),
    _r("W-AUTH-03", "Password spraying", "web", "Few attempts each across many usernames.",
       ">= 4 usernames with <= 2 tries each from one source within 5 min.", "username set, outcome", "medium",
       "medium", "Shared kiosks or NAT can mix several people's attempts.", ["T1110.003"], [_t(WEB_P0, "W-AUTH-03")],
       owasp=A07),
    _r("W-AUTH-04", "Decoy credential accepted", "web", "A login with a planted decoy credential succeeded.",
       "Successful login to a decoy-only account.", "username, outcome=succeeded", "high",
       "high: decoy accounts have no legitimate users", "Only a tester who knows the decoy credential.", ["T1078"],
       [_t(WEB_P0, "W-AUTH-04")], owasp=A07),
    _r("W-SQLI-01", "SQL injection-like input", "web", "Input resembling SQL injection.",
       "Normalised parameter matches SQL-injection signatures.", "field name (value withheld)", "medium",
       "medium: signature match", "Search terms with quotes or SQL keywords; the decoy runs no SQL, so success is impossible.",
       ["T1190"], [_t(WEB_P0, "W-SQLI-01")], owasp=A03, not_detected="Whether injection would have worked."),
    _r("W-XSS-01", "Script-injection-like input", "web", "Input resembling cross-site scripting.",
       "Markup or script patterns in a parameter.", "field name", "medium", "medium",
       "Users pasting HTML snippets.", ["T1189"], [_t(WEB_P0, "W-XSS-01")], owasp=A03),
    _r("W-PATH-01", "Path traversal-like input", "web", "Traversal sequences in a path or parameter.",
       "../ or encoded equivalents after normalisation.", "field name", "medium", "medium",
       "Rare in normal traffic.", ["T1190"], [_t(WEB_P0, "W-PATH-01")], owasp=A01),
    _r("W-SSRF-01", "Server-side request forgery-like input", "web", "A URL to an internal or metadata address in input.",
       "Parameter holds a URL to a private, loopback or metadata host.", "field name", "medium", "medium",
       "Legitimate webhooks to internal hosts.", ["T1190"], [_t(WEB_P0, "W-SSRF-01")], owasp=A10,
       not_detected="Any request: the decoy never fetches URLs."),
    _r("W-UPL-01", "Suspicious upload", "web", "Upload whose name or content type is executable.",
       "Executable extension or sniffed script type.", "upload name, sniffed type, sha256", "medium", "medium",
       "Developers uploading scripts.", ["T1105"], [_t(WEB_P1, "W-UPL-01")], owasp=A04),
    _r("W-IDOR-01", "Object-reference tampering", "web", "Sequential or foreign object IDs requested.",
       "Access to object IDs outside the session's own.", "request_path", "medium", "medium",
       "Users editing URLs by hand.", ["T1213"], [_t(WEB_P1, "W-IDOR-01")], owasp=A01),
    _r("W-SHELL-01", "Web shell path probe", "web", "Request for a known web-shell filename.",
       "Path matches web-shell names.", "request_path", "low", "low",
       "Scanners. A probe is not a deployed web shell, so T1505.003 is never emitted.", ["T1595.003"], [_t(WEB_P1, "W-SHELL-01")],
       owasp=A05),
    _r("W-ANON-01", "Visitor from a Tor exit node", "web", "A request to the web decoy came from a Tor exit node.",
       "Source address is on the Tor bulk exit list (services/anonintel, refreshed by scripts/refresh_anon_lists.py).",
       "source_ip, raw_evidence_redacted.anonymizer", "medium",
       "medium: the exit list is public and exact at fetch time, but exits change daily",
       "Privacy-conscious legitimate visitors also use Tor.", ["T1090.003"],
       [_t(WEB_ANON, "W-ANON-01")],
       not_detected="Who is behind the exit. Tor hides the real address; correlate with client_fp instead."),
    _r("W-ANON-02", "Visitor from a VPN or hosting range", "web",
       "A request to the web decoy came from a commercial VPN or a hosting/cloud range.",
       "Source address is inside a VPN or datacenter CIDR list (X4BNet lists_vpn snapshot).",
       "source_ip, raw_evidence_redacted.anonymizer", "low",
       "low: best effort; new or residential VPNs are not on any list",
       "Corporate VPNs, cloud-hosted monitoring, remote workers.", ["T1090"], [_t(WEB_ANON, "W-ANON-02")],
       alerting=False, not_detected="Residential proxies, private VPN servers, a friend's machine."),
    _r("W-ADAPT-01", "Adaptive bait taken", "web",
       "A source that had already shown attack intent opened a decoy backup link the portal revealed only to it.",
       "Request for a revealed adaptive bait path after the reveal (services/web adaptive deception).",
       "request_path, raw_evidence_redacted.adaptive", "high",
       "high: the link is shown only to sources that already scanned, injected or brute-forced",
       "None expected: ordinary visitors never see the link.", ["T1213"], [_t(WEB_ADAPT, "W-ADAPT-01")], owasp=A01,
       not_detected="Whether the attacker used the fake credentials inside the file elsewhere."),
    # Database honeypot (services/database/sensor). Detections exist only at MEDIUM severity or above.
    _r("D-SENS-01", "Sensitive decoy table read", "database", "A read of a table holding decoy credentials or contracts.",
       "SELECT on a sensitive table succeeded.", "command, table_names, rows_returned", "high", "high",
       "None for decoy_user: the account exists only on the decoy.", ["T1213", "T1552"],
       [_t(DB_READY, "D-SENS-01", "live"), _t("services/database/tests/test_collector.py", "D-SENS-01")]),
    _r("D-ADAPT-01", "Adaptive decoy table accessed", "database", "A table revealed by adaptive deception was then read.",
       "Read of an adaptive table after its GRANT.", "command, adaptation record", "critical", "high",
       "None: the table is invisible until behaviour reveals it.", ["T1213"], [_t(DB_READY, "D-ADAPT-01", "live")]),
    _r("D-RESTR-01", "Restricted table denied", "database", "A denied read of a restricted table.",
       "Server returned ER_TABLEACCESS_DENIED.", "command, server_error", "medium", "medium",
       "Clients that enumerate everything.", [], [_t(DB_READY, "D-RESTR-01", "live")]),
    _r("D-MOD-01", "Data modification attempt", "database", "INSERT/UPDATE/DELETE attempted.",
       "Write statement classified.", "command, outcome", "medium", "medium", "None for the read-only decoy account.",
       [], [_t(DB_READY, "D-MOD-01", "live")]),
    _r("D-DDL-01", "Schema change attempt", "database", "CREATE/ALTER/DROP attempted.", "DDL classified.",
       "command, outcome", "high", "high", "None for the decoy account.", [], [_t(DB_READY, "D-DDL-01", "live")]),
    _r("D-PRIV-01", "Privilege change attempt", "database", "GRANT, CREATE USER or similar attempted.",
       "Privilege statement classified.", "command, outcome", "high", "high", "None for the decoy account.", [],
       [_t(DB_READY, "D-PRIV-01", "live")]),
    _r("D-FILE-01", "Server file access attempt", "database", "LOAD_FILE, INTO OUTFILE or LOAD DATA.",
       "File-access function classified.", "command", "high", "high", "None for the decoy account.", [],
       [_t(DB_UNIT, "file_access_attempt")]),
    _r("D-RECON-01", "Repeated database enumeration", "database", "Repeated SHOW / information_schema queries.",
       "Reconnaissance risk crosses MEDIUM.", "command, session tracker", "medium", "medium",
       "GUI clients enumerate schemas on connect.", [], [_t(DB_UNIT, "reconnaissance")]),
    _r("D-AUTH-01", "Repeated failed database logins", "database", "Failed logins accumulating from one source.",
       "Failure risk crosses MEDIUM.", "username, outcome", "medium", "medium",
       "A client retrying a wrong saved password.", ["T1110.001", "T1110.003"], [_t(DB_LIVE, "D-AUTH-01", "live")]),
    _r("D-DATA-01", "Broad data exploration", "database", "Reads across many tables.",
       "Distinct tables read crosses the collection threshold.", "table_names", "medium", "medium",
       "Analysts exploring a new database.", ["T1213"], [_t(DB_UNIT, "data_exploration")]),
    _r("D-INJ-01", "Audit log injection attempt", "database", "Input crafted to forge audit log lines.",
       "Audit-line delimiters inside a statement.", "command", "high", "high", "None.", [],
       [_t(DB_UNIT, "D-INJ-01")]),
    _r("D-INJ-02", "Audit line with no matching login", "database", "A query line whose connection never logged in.",
       "Query for an unknown connection id.", "audit_connection_id", "high", "medium",
       "Sensor restarted mid-session.", [], [_t(DB_LIVE, "D-INJ-02", "live")]),
    # SSH honeypot (services/ssh/sensor/src/cowrie_soc/detection.py).
    _r("SSH-BRUTE-001", "Repeated failed SSH logins", "ssh", "Failed SSH logins from one source.",
       ">= 5 failures from one IP within 60 s, one finding per episode.", "usernames, outcome (passwords never kept)",
       "medium", "medium", "NAT can merge several clients.", ["T1110"], [_t(SSH_DET, "SSH-BRUTE-001")]),
    _r("SSH-AUTH-002", "Login to a decoy SSH account", "ssh", "Any successful SSH login: the decoy has no real users.",
       "login.success; escalated after >= 3 prior failures in 10 min.", "username, outcome", "medium",
       "medium, high when escalated", "Only the lab owner testing the decoy.", ["T1078", "T1110"],
       [_t(SSH_DET, "SSH-AUTH-002")]),
    _r("SSH-EXEC-001", "Commands ran in the emulated shell", "ssh", "First command in a session.",
       "First shell command.", "command", "low", "low", "None that is legitimate: the decoy has no real users, so any shell use is post-login activity.",
       ["T1059.004"], [_t(SSH_DET, "SSH-EXEC-001")]),
    _r("SSH-DISC-001", "Several discovery techniques in one session", "ssh", "Distinct discovery techniques in a session.",
       ">= 3 (medium) or >= 5 (high) techniques within 300 s.", "commands", "medium", "medium / high",
       "Administrators run uname, id and ls together.",
       ["T1082", "T1033", "T1087.001", "T1083", "T1016", "T1049", "T1057"], [_t(SSH_DET, "SSH-DISC-001")]),
    _r("SSH-CRED-001", "Credential file or honeytoken read", "ssh", "Read of a honeytoken or credential file.",
       "cat/less/... of a honeytoken path, /etc/shadow or a credential file name.", "command, resolved path",
       "high", "high (exact path), medium (suffix match)", "None for honeytokens.", ["T1552.001", "T1003.008"],
       [_t(SSH_DET, "SSH-CRED-001")]),
    _r("SSH-TOOL-001", "Remote file download attempted", "ssh", "wget/curl/tftp with a URL, or a file_download.",
       "Downloader with URL.", "command, url", "high", "high", "None in a decoy.", ["T1105"], [_t(SSH_DET, "SSH-TOOL-001")],
       not_detected="Whether the download completed."),
    _r("SSH-SEQ-001", "Download, chmod and execute", "ssh", "Dropper sequence in one session.",
       "download -> chmod +x -> execute same file within 300 s.", "commands", "critical", "high", "None.",
       ["T1105", "T1222.002", "T1059.004"], [_t(SSH_DET, "SSH-SEQ-001")]),
    _r("SSH-EVADE-001", "Shell history cleared or disabled", "ssh", "History tampering.",
       "history -c, unset HISTFILE, HISTSIZE=0, .bash_history removed.", "command", "high", "high", "None.",
       ["T1070.003"], [_t(SSH_DET, "SSH-EVADE-001")]),
    # Collector-side rules (collector/detections.py).
    _r("SOC-AUTH-00", "Failed console login", "soc", "One failed sign-in to the SOC console itself.",
       "Console login rejected.", "username attempted, outcome", "low", "low: one attempt",
       "A mistyped password. Never an alert on its own.", [], [_t(COLLECTOR, "SOC-AUTH-00")], alerting=False),
    _r("SOC-AUTH-01", "Repeated failed console logins", "soc", "Repeated failed sign-ins to the SOC console.",
       ">= 5 failures from one source, or >= 5 for one username, within 10 min.", "username, source, timestamps",
       "medium", "medium", "An analyst who forgot a password and keeps retrying.", ["T1110"],
       [_t(COLLECTOR, "SOC-AUTH-01")]),
    _r("X-CORR-01", "Same source active on several decoys", "multi", "One source IP seen on two or more decoys.",
       ">= 2 services from one IP within 30 min.", "source_ip, service, timestamps", "medium",
       "low: a shared IP is a hint, not proof of one actor", "NAT, shared lab hosts, the Docker gateway.", [],
       [_t(COLLECTOR, "X-CORR-01")]),
]}


def rule(rule_id: str) -> dict[str, Any] | None:
    return RULES.get(rule_id)


def alerting(rule_id: str) -> bool:
    """Unknown rules alert, so a new sensor rule is never silently dropped."""
    entry = RULES.get(rule_id)
    return True if entry is None else entry["alerting"]


def owasp_2025(label: str | None) -> str | None:
    return OWASP_2025.get(label or "")
