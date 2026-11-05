"""Explainable, configurable SSH detections over normalized Cowrie events.

Every finding records: the rule, the evidence event_ids, the observed values,
the time window and threshold that applied, severity, confidence, the ATT&CK
techniques the evidence supports, and a plain-language explanation.

Time is taken from event timestamps (not the wall clock), so replaying a log
produces the same findings as processing it live. State is kept in memory and
bounded; it is not persisted across collector restarts (documented limitation).
"""

from __future__ import annotations

import posixpath
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from cowrie_soc import attack, commands
from cowrie_soc.config import ConfigError
from cowrie_soc.parser import parse_timestamp
from cowrie_soc.schema import (
    CONFIDENCES,
    FINDING_SCHEMA_VERSION,
    RECORD_FINDING,
    SEVERITIES,
    deterministic_id,
)

MAX_EVIDENCE_IDS = 50
MAX_SESSIONS = 10_000
MAX_SOURCES = 10_000
MAX_FAILURES_PER_SOURCE = 1_000
MAX_SESSION_EVIDENCE = 100


class DetectionConfigError(ConfigError):
    pass


@dataclass(frozen=True)
class Evidence:
    event_id: str
    timestamp: str
    at: datetime


@dataclass
class SessionState:
    session_id: str
    source_ip: str | None
    username: str | None = None
    cwd: str | None = None
    home: str | None = None
    commands_seen: int = 0
    # Evidence lists keep only the newest MAX_SESSION_EVIDENCE items so a long or scripted
    # session cannot grow collector memory without bound.
    discovery: dict[str, deque[tuple[Evidence, str]]] = field(default_factory=dict)
    downloads: deque[tuple[Evidence, str, str]] = field(  # (ev, url, saved name)
        default_factory=lambda: deque(maxlen=MAX_SESSION_EVIDENCE))
    chmod_exec: deque[tuple[Evidence, str]] = field(default_factory=lambda: deque(maxlen=MAX_SESSION_EVIDENCE))
    executed: deque[tuple[Evidence, str]] = field(default_factory=lambda: deque(maxlen=MAX_SESSION_EVIDENCE))
    emitted: set[str] = field(default_factory=set)


@dataclass
class SourceState:
    # (evidence, username, password, session_id)
    failures: deque[tuple[Evidence, str, str | None, str]] = field(
        default_factory=lambda: deque(maxlen=MAX_FAILURES_PER_SOURCE)
    )
    episode_last: datetime | None = None
    episode_alerted: bool = False
    # Decoy-login bookkeeping: failures before this time already backed an escalation,
    # and the last time each username's login produced a finding.
    failures_consumed_until: datetime | None = None
    login_alerted: dict[str, datetime] = field(default_factory=dict)


@dataclass
class Context:
    """State shared by all rules, updated by the engine before rules run."""

    sessions: OrderedDict[str, SessionState] = field(default_factory=OrderedDict)
    sources: OrderedDict[str, SourceState] = field(default_factory=OrderedDict)
    user_homes: dict[str, str] = field(default_factory=dict)

    def session(self, event: dict[str, Any]) -> SessionState:
        sid = event["session_id"]
        state = self.sessions.get(sid)
        if state is None:
            state = SessionState(sid, event.get("source_ip"))
            self.sessions[sid] = state
            while len(self.sessions) > MAX_SESSIONS:
                self.sessions.popitem(last=False)
        else:
            self.sessions.move_to_end(sid)
        return state

    def source(self, ip: str) -> SourceState:
        state = self.sources.get(ip)
        if state is None:
            state = SourceState()
            self.sources[ip] = state
            while len(self.sources) > MAX_SOURCES:
                self.sources.popitem(last=False)
        else:
            self.sources.move_to_end(ip)
        return state


@dataclass
class EventView:
    """A normalized event plus derived values rules commonly need."""

    record: dict[str, Any]
    evidence: Evidence
    analysis: commands.CommandAnalysis | None

    @property
    def event_type(self) -> str:
        return self.record["event_type"]


class Rule:
    rule_id: ClassVar[str]
    name: ClassVar[str]
    config_key: ClassVar[str]
    defaults: ClassVar[dict[str, Any]] = {}
    recommended_action: ClassVar[str] = (
        "Review the session in the SOC timeline. Any containment (e.g. a lab-only block of the "
        "source) is an analyst decision; this sensor takes no automatic action."
    )

    def __init__(self, overrides: dict[str, Any], sensor_id: str, now: Callable[[], str]) -> None:
        unknown = set(overrides) - set(self.defaults) - {"enabled"}
        if unknown:
            raise DetectionConfigError(f"[detection.{self.config_key}] unknown keys: {sorted(unknown)}")
        self.cfg = {**self.defaults, **{k: v for k, v in overrides.items() if k != "enabled"}}
        for key, value in self.cfg.items():
            default = self.defaults[key]
            numeric = isinstance(default, (int, float)) and not isinstance(default, bool)
            if numeric and (not isinstance(value, (int, float)) or isinstance(value, bool)):
                raise DetectionConfigError(f"[detection.{self.config_key}] {key} must be a number")
            if not numeric and not isinstance(value, type(default)):
                raise DetectionConfigError(
                    f"[detection.{self.config_key}] {key} must be a {type(default).__name__}"
                )
            if "severity" in key and value not in SEVERITIES:
                raise DetectionConfigError(f"[detection.{self.config_key}] {key}={value!r} not in {SEVERITIES}")
        self.sensor_id = sensor_id
        self.now = now

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        raise NotImplementedError

    def finding(
        self,
        *,
        key: str,
        title: str,
        severity: str,
        confidence: str,
        techniques: list[str],
        evidence: list[Evidence],
        observed: dict[str, Any],
        explanation: str,
        source_ip: str | None,
        session_ids: list[str],
        username: str | None = None,
        window_seconds: float | None = None,
        threshold: Any = None,
    ) -> dict[str, Any]:
        assert severity in SEVERITIES and confidence in CONFIDENCES
        ordered = sorted(evidence, key=lambda e: e.at)
        ids: list[str] = []
        for ev in ordered:
            if ev.event_id not in ids:
                ids.append(ev.event_id)
        return {
            "record_type": RECORD_FINDING,
            "schema_version": FINDING_SCHEMA_VERSION,
            "finding_id": deterministic_id("cowrie-finding", self.sensor_id, self.rule_id, key),
            "rule_id": self.rule_id,
            "rule_name": self.name,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "created_at": self.now(),
            "first_seen": ordered[0].timestamp,
            "last_seen": ordered[-1].timestamp,
            "source_service": "ssh",
            "sensor_id": self.sensor_id,
            "source_ip": source_ip,
            "session_ids": session_ids,
            "username": username,
            "attack": attack.as_dicts(techniques),
            "evidence": {
                "event_ids": ids[:MAX_EVIDENCE_IDS],
                "event_count": len(ids),
                "observed": observed,
                "window_seconds": window_seconds,
                "threshold": threshold,
            },
            "explanation": explanation,
            "recommended_action": self.recommended_action,
        }


def _span(evidence: list[Evidence]) -> float:
    if not evidence:
        return 0.0
    return (max(e.at for e in evidence) - min(e.at for e in evidence)).total_seconds()


class BruteForceRule(Rule):
    rule_id = "SSH-BRUTE-001"
    name = "Repeated SSH authentication failures"
    config_key = "ssh_bruteforce"
    defaults = {
        "threshold": 5,
        "window_seconds": 60,
        "severity": "medium",
        "spray_min_usernames": 3,
        "spray_max_passwords": 2,
    }

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "authentication_failure" or not view.record.get("source_ip"):
            return []
        ip = view.record["source_ip"]
        src = ctx.source(ip)
        window = float(self.cfg["window_seconds"])
        now = view.evidence.at
        # A gap longer than the window ends the previous episode.
        if src.episode_last is not None and (now - src.episode_last).total_seconds() > window:
            src.episode_alerted = False
        src.episode_last = now
        in_window = [f for f in src.failures if (now - f[0].at).total_seconds() <= window]
        if len(in_window) < int(self.cfg["threshold"]) or src.episode_alerted:
            return []
        src.episode_alerted = True

        usernames = sorted({f[1] for f in in_window})
        passwords_known = all(f[2] is not None for f in in_window)
        n_passwords: int | None = len({f[2] for f in in_window}) if passwords_known else None
        if n_passwords is None:
            tid, style = "T1110", "passwords are redacted, so guessing vs. spraying cannot be determined"
        elif len(usernames) >= self.cfg["spray_min_usernames"] and n_passwords <= self.cfg["spray_max_passwords"]:
            tid, style = "T1110.003", "few passwords tried across many accounts (password spraying)"
        else:
            tid, style = "T1110.001", "many passwords tried against a small set of accounts (password guessing)"
        pw_text = "unknown (redacted)" if n_passwords is None else str(n_passwords)
        evidence = [f[0] for f in in_window]
        return [
            self.finding(
                key=f"{ip}|{in_window[0][0].timestamp}",
                title=f"SSH brute force from {ip}: {len(in_window)} failed logins in {_span(evidence):.0f}s",
                severity=self.cfg["severity"],
                confidence="high",
                techniques=[tid],
                evidence=evidence,
                observed={
                    "failed_attempts": len(in_window),
                    "distinct_usernames": len(usernames),
                    "usernames": usernames[:20],
                    "distinct_passwords": n_passwords,
                    "connections": len({f[3] for f in in_window}),
                },
                explanation=(
                    f"{len(in_window)} failed SSH logins from {ip} within {window:.0f}s "
                    f"(threshold {self.cfg['threshold']}); {len(usernames)} username(s), "
                    f"distinct passwords: {pw_text}; {style}. Mapped to {tid}."
                ),
                source_ip=ip,
                session_ids=sorted({f[3] for f in in_window}),
                window_seconds=window,
                threshold=self.cfg["threshold"],
            )
        ]


class DecoyLoginRule(Rule):
    rule_id = "SSH-AUTH-002"
    name = "Successful login to a decoy SSH account"
    config_key = "ssh_decoy_login"
    defaults = {
        "severity": "medium",
        "escalated_severity": "high",
        "min_prior_failures": 3,
        "lookback_seconds": 600,
    }

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "authentication_success":
            return []
        rec = view.record
        ip, user = rec.get("source_ip"), rec.get("username")
        lookback = float(self.cfg["lookback_seconds"])
        now = view.evidence.at
        prior: list[tuple[Evidence, str, str, str]] = []
        src = ctx.source(ip) if ip else None
        if src is not None:
            consumed = src.failures_consumed_until
            prior = [
                f for f in src.failures
                if 0 <= (now - f[0].at).total_seconds() <= lookback and (consumed is None or f[0].at > consumed)
            ]
        escalate = len(prior) >= int(self.cfg["min_prior_failures"])
        if src is not None:
            last = src.login_alerted.get(str(user))
            if not escalate and last is not None and (now - last).total_seconds() <= lookback:
                return []  # plain repeat login: same account, same source, already reported
            src.login_alerted[str(user)] = now
            if escalate:
                src.failures_consumed_until = now
        if escalate:
            title = f"Decoy SSH login as '{user}' from {ip} after {len(prior)} failed attempts"
            # T1110, not T1110.001: tried passwords are not recorded, so guessing and spraying look alike.
            techniques = ["T1110", "T1078"]
            explanation = (
                f"{ip} logged in to the decoy as '{user}' after {len(prior)} failed logins in the "
                f"previous {lookback:.0f}s (threshold {self.cfg['min_prior_failures']}), consistent with a "
                "brute-forced credential being used. Mapped to T1110 and T1078 (a decoy account was used; "
                "no production account is involved)."
            )
            severity = self.cfg["escalated_severity"]
        else:
            title = f"Decoy SSH login as '{user}' from {ip}"
            techniques = ["T1078"]
            explanation = (
                f"{ip} authenticated to the decoy as '{user}'. The decoy has no legitimate users, so any "
                "successful login is suspicious. Mapped to T1078 (decoy account only)."
            )
            severity = self.cfg["severity"]
        return [
            self.finding(
                key=rec["session_id"],
                title=title,
                severity=severity,
                confidence="high",
                techniques=techniques,
                evidence=[*(f[0] for f in prior), view.evidence],
                observed={"username": user, "prior_failed_attempts": len(prior),
                          "prior_usernames": sorted({f[1] for f in prior})[:20]},
                explanation=explanation,
                source_ip=ip,
                session_ids=[rec["session_id"]],
                username=user,
                window_seconds=lookback,
                threshold=self.cfg["min_prior_failures"],
            )
        ]


class ShellActivityRule(Rule):
    rule_id = "SSH-EXEC-001"
    name = "Command execution in the emulated shell"
    config_key = "ssh_shell_activity"
    defaults = {"severity": "low"}

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "shell_command":
            return []
        state = ctx.session(view.record)
        if "exec" in state.emitted:
            return []
        state.emitted.add("exec")
        rec = view.record
        return [
            self.finding(
                key=rec["session_id"],
                title=f"Commands executed in decoy shell (session {rec['session_id']})",
                severity=self.cfg["severity"],
                confidence="high",
                techniques=["T1059.004"],
                evidence=[view.evidence],
                observed={"first_command": rec.get("command"), "username": state.username},
                explanation=(
                    "The client ran commands in Cowrie's emulated Unix shell (first: "
                    f"{rec.get('command')!r}). Commands are emulated and never run on the host."
                ),
                source_ip=rec.get("source_ip"),
                session_ids=[rec["session_id"]],
                username=state.username,
            )
        ]


class DiscoveryRule(Rule):
    rule_id = "SSH-DISC-001"
    name = "Multiple discovery techniques in one SSH session"
    config_key = "ssh_discovery"
    defaults = {"window_seconds": 300, "levels": [[3, "medium"], [5, "high"]]}

    def __init__(self, overrides: dict[str, Any], sensor_id: str, now: Callable[[], str]) -> None:
        super().__init__(overrides, sensor_id, now)
        levels = self.cfg["levels"]
        if not levels or any(len(lv) != 2 or lv[1] not in SEVERITIES for lv in levels):
            raise DetectionConfigError("[detection.ssh_discovery] levels must be [[count, severity], ...]")
        self.levels = sorted((int(c), s) for c, s in levels)

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "shell_command" or view.analysis is None:
            return []
        state = ctx.session(view.record)
        window = float(self.cfg["window_seconds"])
        now = view.evidence.at
        for ind in view.analysis.indicators:
            if ind.technique_id in attack.DISCOVERY_TECHNIQUES:
                state.discovery.setdefault(ind.technique_id, deque(maxlen=MAX_SESSION_EVIDENCE)).append(
                    (view.evidence, ind.reason)
                )
        active = {
            tid: [h for h in hits if (now - h[0].at).total_seconds() <= window]
            for tid, hits in state.discovery.items()
        }
        active = {tid: hits for tid, hits in active.items() if hits}
        out = []
        for count, severity in self.levels:
            marker = f"disc:{count}"
            if len(active) < count or marker in state.emitted:
                continue
            state.emitted.add(marker)
            techniques = sorted(active)
            evidence = [h[0] for hits in active.values() for h in hits]
            out.append(
                self.finding(
                    key=f"{state.session_id}|{count}",
                    title=f"Discovery burst: {len(techniques)} ATT&CK discovery techniques in session {state.session_id}",
                    severity=severity,
                    confidence="high",
                    techniques=techniques,
                    evidence=evidence,
                    observed={
                        "techniques": {tid: sorted({h[1] for h in hits}) for tid, hits in sorted(active.items())},
                    },
                    explanation=(
                        f"Within {window:.0f}s the session ran commands matching {len(techniques)} distinct "
                        f"discovery techniques ({', '.join(techniques)}); level threshold {count} -> {severity}. "
                        "Each technique is backed by the listed command evidence."
                    ),
                    source_ip=view.record.get("source_ip"),
                    session_ids=[state.session_id],
                    username=state.username,
                    window_seconds=window,
                    threshold=count,
                )
            )
        return out


class CredentialAccessRule(Rule):
    rule_id = "SSH-CRED-001"
    name = "Access to credential files or honeytokens"
    config_key = "ssh_credential_access"
    defaults = {
        "severity": "high",
        "honeytoken_severity": "critical",
        "honeytoken_paths": [],
    }

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "shell_command" or view.analysis is None:
            return []
        state = ctx.session(view.record)
        out: list[dict[str, Any]] = []
        honeytokens = set(self.cfg["honeytoken_paths"])
        for path, cd_hint in view.analysis.file_reads:
            resolved = _resolve(path, state, cd_hint)
            match, how = None, None
            if resolved in honeytokens:
                match, how = resolved, "exact path"
            elif resolved is None:
                suffix = "/" + path.lstrip("./")
                candidates = [h for h in honeytokens if h.endswith(suffix)]
                if len(candidates) == 1:
                    match, how = candidates[0], "path suffix (working directory unknown)"
            if match:
                out += self._emit(view, state, f"ht:{match}", match, "T1552.001",
                                  self.cfg["honeytoken_severity"], "high" if how == "exact path" else "medium",
                                  f"read planted honeytoken file {match} (matched by {how})", honeytoken=True)
        for ind in view.analysis.indicators:
            if ind.technique_id in ("T1003.008", "T1552.001"):
                out += self._emit(view, state, f"{ind.technique_id}:{ind.reason}", ind.reason, ind.technique_id,
                                  self.cfg["severity"], "medium" if ind.technique_id == "T1552.001" else "high",
                                  ind.reason, honeytoken=False)
        return out

    def _emit(self, view: EventView, state: SessionState, marker: str, target: str, tid: str,
              severity: str, confidence: str, reason: str, honeytoken: bool) -> list[dict[str, Any]]:
        if marker in state.emitted:
            return []
        if not honeytoken and any(m.startswith("ht:") for m in state.emitted) and tid == "T1552.001":
            return []  # already reported as a honeytoken hit
        state.emitted.add(marker)
        rec = view.record
        label = "Honeytoken credential file read" if honeytoken else "Credential material accessed"
        return [
            self.finding(
                key=f"{state.session_id}|{marker}",
                title=f"{label}: {target}",
                severity=severity,
                confidence=confidence,
                techniques=[tid],
                evidence=[view.evidence],
                observed={"command": rec.get("command"), "target": target, "working_directory": state.cwd,
                          "honeytoken": honeytoken},
                explanation=f"The session {reason}. Command: {rec.get('command')!r}. Mapped to {tid}.",
                source_ip=rec.get("source_ip"),
                session_ids=[state.session_id],
                username=state.username,
            )
        ]


class IngressToolTransferRule(Rule):
    rule_id = "SSH-TOOL-001"
    name = "Remote file download attempt"
    config_key = "ssh_ingress_tool_transfer"
    defaults = {"severity": "high"}

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        rec = view.record
        urls: list[str] = []
        how = ""
        if view.event_type == "shell_command" and view.analysis is not None:
            urls, how = view.analysis.download_urls, "download command"
        elif view.event_type == "file_download":
            url = rec["details"].get("url")
            urls, how = ([url] if isinstance(url, str) else []), f"Cowrie {rec['raw']['cowrie_eventid']} event"
        if not urls:
            return []
        state = ctx.session(rec)
        out = []
        for url in urls:
            marker = f"dl:{url}"
            if marker in state.emitted:
                continue
            state.emitted.add(marker)
            out.append(
                self.finding(
                    key=f"{state.session_id}|{url}",
                    title=f"Download attempt from {url}",
                    severity=self.cfg["severity"],
                    confidence="high",
                    techniques=["T1105"],
                    evidence=[view.evidence],
                    observed={"url": url, "command": rec.get("command"), "outcome": rec.get("outcome")},
                    explanation=(
                        f"The session tried to fetch {url} ({how}). Cowrie's outbound connections are "
                        "bound to loopback, so the transfer cannot reach the network. Mapped to T1105."
                    ),
                    source_ip=rec.get("source_ip"),
                    session_ids=[state.session_id],
                    username=state.username,
                )
            )
        return out


class DownloadExecuteRule(Rule):
    rule_id = "SSH-SEQ-001"
    name = "Download, make executable, run sequence"
    config_key = "ssh_download_execute"
    defaults = {"severity": "critical", "window_seconds": 300}

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "shell_command" or view.analysis is None:
            return []
        state = ctx.session(view.record)
        if "seq" in state.emitted or not state.downloads:
            return []
        window = float(self.cfg["window_seconds"])
        now = view.evidence.at
        for dl_ev, url, saved in state.downloads:
            if (now - dl_ev.at).total_seconds() > window:
                continue
            name = posixpath.basename(saved)
            chmods = [c for c in state.chmod_exec if posixpath.basename(c[1]) == name and c[0].at >= dl_ev.at]
            runs = [x for x in state.executed if posixpath.basename(x[1]) == name and x[0].at >= dl_ev.at]
            if not (chmods and runs):
                continue
            state.emitted.add("seq")
            rec = view.record
            return [
                self.finding(
                    key=state.session_id,
                    title=f"Dropper sequence: download -> chmod +x -> execute '{name}'",
                    severity=self.cfg["severity"],
                    confidence="high",
                    techniques=["T1105", "T1222.002", "T1059.004"],
                    evidence=[dl_ev, chmods[0][0], runs[0][0]],
                    observed={"url": url, "file": saved, "chmod_target": chmods[0][1], "executed": runs[0][1]},
                    explanation=(
                        f"In one session the client downloaded {url} to {saved!r}, made it executable and ran "
                        f"it within {window:.0f}s - the typical malware dropper pattern. Execution is emulated."
                    ),
                    source_ip=rec.get("source_ip"),
                    session_ids=[state.session_id],
                    username=state.username,
                    window_seconds=window,
                )
            ]
        return []


class HistoryTamperingRule(Rule):
    rule_id = "SSH-EVADE-001"
    name = "Shell history tampering"
    config_key = "ssh_history_tampering"
    defaults = {"severity": "high"}

    def process(self, view: EventView, ctx: Context) -> list[dict[str, Any]]:
        if view.event_type != "shell_command" or view.analysis is None:
            return []
        hits = [i for i in view.analysis.indicators if i.technique_id == "T1070.003"]
        state = ctx.session(view.record)
        if not hits or "hist" in state.emitted:
            return []
        state.emitted.add("hist")
        rec = view.record
        return [
            self.finding(
                key=state.session_id,
                title="Shell history cleared or disabled",
                severity=self.cfg["severity"],
                confidence="high",
                techniques=["T1070.003"],
                evidence=[view.evidence],
                observed={"command": rec.get("command"), "reasons": [h.reason for h in hits]},
                explanation=f"The session {hits[0].reason}: {rec.get('command')!r}. Mapped to T1070.003.",
                source_ip=rec.get("source_ip"),
                session_ids=[state.session_id],
                username=state.username,
            )
        ]


RULE_CLASSES: list[type[Rule]] = [
    BruteForceRule,
    DecoyLoginRule,
    ShellActivityRule,
    DiscoveryRule,
    CredentialAccessRule,
    IngressToolTransferRule,
    DownloadExecuteRule,
    HistoryTamperingRule,
]


def _resolve(path: str, state: SessionState, cd_hint: str | None = None) -> str | None:
    """Resolve a path typed in the session to an absolute virtual path, if possible.

    cd_hint is a `cd` target that ran earlier on the same command line.
    """
    if path.startswith("~"):
        if state.home is None:
            return None
        path = state.home + path[1:]
    if path.startswith("/"):
        return posixpath.normpath(path)
    if cd_hint is not None:
        base = state.home if cd_hint in ("~", "") else _resolve(cd_hint, state)
    else:
        base = state.cwd if state.cwd is not None else state.home
    if base is None:
        return None
    return posixpath.normpath(posixpath.join(base, path))


class DetectionEngine:
    def __init__(
        self,
        config: dict[str, dict[str, Any]] | None = None,
        sensor_id: str = "cowrie",
        now: Callable[[], str] | None = None,
        user_homes: dict[str, str] | None = None,
    ) -> None:
        from cowrie_soc.normalize import utc_now_iso

        config = dict(config or {})
        known = {cls.config_key for cls in RULE_CLASSES}
        unknown = set(config) - known
        if unknown:
            raise DetectionConfigError(f"unknown detection sections: {sorted(unknown)}")
        self.rules: list[Rule] = []
        for cls in RULE_CLASSES:
            section = config.get(cls.config_key, {})
            if section.get("enabled", True):
                self.rules.append(cls(section, sensor_id, now or utc_now_iso))
        self.ctx = Context(user_homes=dict(user_homes or {}))

    def process(self, record: dict[str, Any]) -> list[dict[str, Any]]:
        if record.get("record_type") != "event":
            return []
        at = parse_timestamp(record["timestamp"])
        ev = Evidence(record["event_id"], record["timestamp"], at)
        analysis = None
        if record["event_type"] == "shell_command" and isinstance(record.get("command"), str):
            analysis = commands.analyze(record["command"])
        view = EventView(record, ev, analysis)
        self._update_context(view)
        findings: list[dict[str, Any]] = []
        for rule in self.rules:
            findings.extend(rule.process(view, self.ctx))
        self._post_update(view)
        return findings

    def _update_context(self, view: EventView) -> None:
        rec, ctx = view.record, self.ctx
        etype = rec["event_type"]
        if etype == "authentication_failure" and rec.get("source_ip"):
            ctx.source(rec["source_ip"]).failures.append(
                # password is None when redacted (include_passwords = false) or absent
                (view.evidence, str(rec.get("username")), rec.get("password"), rec["session_id"])
            )
        elif etype == "authentication_success":
            state = ctx.session(rec)
            state.username = rec.get("username")
            if state.username:
                state.home = ctx.user_homes.get(
                    state.username, "/root" if state.username == "root" else f"/home/{state.username}"
                )
        elif etype == "shell_command" and view.analysis is not None:
            state = ctx.session(rec)
            state.commands_seen += 1
            a = view.analysis
            for url, saved in zip(a.download_urls, a.download_outputs or [""] * len(a.download_urls)):
                state.downloads.append((view.evidence, url, saved or posixpath.basename(url)))
            state.chmod_exec.extend((view.evidence, t) for t in a.chmod_exec_targets)
            state.executed.extend((view.evidence, p) for p in a.executed_paths)

    def _post_update(self, view: EventView) -> None:
        rec, ctx = view.record, self.ctx
        if view.analysis is not None and rec["session_id"] in ctx.sessions:
            state = ctx.sessions[rec["session_id"]]
            for target in view.analysis.cd_targets:  # cd takes effect after the line runs
                state.cwd = _resolve(target, state) if target not in ("~", "") else state.home
        if rec["event_type"] == "session_closed":
            ctx.sessions.pop(rec["session_id"], None)
