"""Alert layer: turn sensor detections into deduplicated, prioritized alerts.

Sensors decide what is suspicious and say why, in raw_evidence_redacted.detections[]. Web and
database use the same shape, so this layer has no per-service logic. One alert exists per
(rule, source); repeats update it instead of flooding the analyst.

A match is not an alert: rules_catalog marks single-occurrence signals (one failed login, one
sensitive-path request) as non-alerting. Those stay visible on the event as a rule match and feed
the threshold rules above them, which are the ones that alert.
"""

from __future__ import annotations

import os

import uuid
from datetime import datetime, timedelta
from typing import Any

from . import rules_catalog
from .storage import Store

ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}
CONFIDENCE_SEVERITY = {"low": "low", "medium": "medium", "high": "high"}
MAX_RELATED = 200
CORRELATION_WINDOW = timedelta(minutes=30)
SOC_AUTH_WINDOW = timedelta(minutes=10)
# Threshold rules whose sensor reports only the event that crossed the line. The events that led up
# to it are linked as evidence: (precursor rule, window, same username). Windows match the sensor's.
PRECURSORS = {
    "W-AUTH-02": ("W-AUTH-01", timedelta(seconds=60), True),
    "W-AUTH-03": ("W-AUTH-01", timedelta(minutes=5), False),
    "W-ENUM-02": ("W-ENUM-01", timedelta(seconds=60), False),
}
SOC_AUTH_THRESHOLD = 5
TITLES = {
    "D-SENS-01": "Sensitive decoy table read", "D-ADAPT-01": "Adaptive decoy table accessed after reveal",
    "D-RESTR-01": "Access to restricted table denied", "D-MOD-01": "Data modification attempt",
    "D-DDL-01": "Schema change attempt", "D-PRIV-01": "Privilege change attempt",
    "D-FILE-01": "Server file access attempt", "D-RECON-01": "Repeated database enumeration",
    "D-AUTH-01": "Repeated failed database logins", "D-DATA-01": "Broad data exploration",
    "D-INJ-01": "Audit log injection attempt", "D-INJ-02": "Audit line with no matching login",
    "X-CORR-01": "Same source active on several decoys",
    "SSH-BRUTE-001": "Repeated failed SSH logins", "SSH-AUTH-002": "Login to a decoy SSH account",
    "SSH-EXEC-001": "Commands ran in the emulated SSH shell", "SSH-DISC-001": "Several discovery techniques in one SSH session",
    "SSH-CRED-001": "Credential file or honeytoken read over SSH", "SSH-TOOL-001": "Remote file download attempted over SSH",
    "SSH-SEQ-001": "Download, chmod and execute sequence over SSH", "SSH-EVADE-001": "Shell history cleared or disabled over SSH",
    "SOC-AUTH-01": "Repeated failed SOC console logins",
}
ACTIONS = {
    "D-SENS-01": "Review which synthetic records were read; treat listed credentials as burned decoys.",
    "D-ADAPT-01": "Confirm the follow-up in the Adaptive Deception view; keep observing, then apply a lab-only block.",
    "D-RESTR-01": "Review the denied statements for targeting patterns.",
    "D-MOD-01": "Confirm the server denied it; record the attempt in the incident.",
    "D-DDL-01": "Confirm the server denied it; record the attempt in the incident.",
    "D-PRIV-01": "Treat as privilege escalation intent; recommend a lab-only block of the source.",
    "D-FILE-01": "Confirm no file was read; recommend a lab-only block of the source.",
    "D-AUTH-01": "Review attempted usernames; recommend a lab-only block if it continues.",
    "D-INJ-01": "Treat the source as aware of the sensor; compare the raw audit log with SOC events.",
    "D-INJ-02": "Do not trust this line's fields; compare the raw audit log around it.",
    "X-CORR-01": "Open the source profile and review the cross-service timeline.",
    "SSH-BRUTE-001": "Review attempted usernames; recommend a lab-only block if it continues.",
    "SSH-AUTH-002": "Open the session timeline to see what was done after the decoy login.",
    "SSH-EXEC-001": "Review the commands; they ran only in the emulated shell.",
    "SSH-DISC-001": "Review the session for what the source was looking for.",
    "SSH-CRED-001": "Treat the decoy credentials as burned; watch for their use on other decoys.",
    "SSH-TOOL-001": "Review the URL and any captured file; a completed transfer is not proven.",
    "SSH-SEQ-001": "Review the captured file and session; it ran only in the emulated shell.",
    "SSH-EVADE-001": "Treat the source as aware of logging; review the full session.",
    "SOC-AUTH-01": "Check with the account owner before treating this as an attack; repeated typos look the same.",
}


def _severity(detection: dict[str, Any]) -> str:
    sev = str(detection.get("severity") or "").lower()
    if sev in ORDER:
        return sev
    return CONFIDENCE_SEVERITY.get(str(detection.get("confidence", "low")).lower(), "low")


def _upsert(store: Store, key: str, event: dict[str, Any], *, rule: str, title: str, severity: str, confidence: str,
            rationale: str, attack: list[dict[str, Any]], stage: str | None, evidence_ids: list[str] = ()) -> None:
    alert = store.get_alert(key)
    if alert is None:
        alert = {
            "alert_id": str(uuid.uuid4()), "rule": rule, "title": title, "severity": severity, "confidence": confidence,
            "first_seen": event["timestamp"], "last_seen": event["timestamp"], "source_ip": event["source_ip"],
            "service": event["service"], "related_event_ids": [], "event_count": 0, "rationale": rationale,
            "attack": [], "attack_ids": [], "kill_chain_stage": stage,
            "recommended_action": ACTIONS.get(rule, "Review the evidence."), "status": "open",
        }
    alert["last_seen"] = max(alert["last_seen"], event["timestamp"])
    alert["event_count"] += 1
    linked = [event["event_id"], *evidence_ids]
    for event_id in linked:
        if len(alert["related_event_ids"]) < MAX_RELATED and event_id not in alert["related_event_ids"]:
            alert["related_event_ids"].append(event_id)
    if ORDER[severity] > ORDER[alert["severity"]]:
        alert["severity"], alert["rationale"] = severity, rationale
    known = {a.get("technique") for a in alert["attack"]}
    for item in attack:
        if item.get("technique") not in known:
            alert["attack"].append(item)
            known.add(item.get("technique"))
    alert["attack_ids"] = sorted(k for k in known if k)
    store.put_alert(key, alert, linked)


def auto_block_rules() -> set[str]:
    """Rules that block the source on the main site automatically (USP 1). Only zero-false-positive
    signals by default: a planted decoy credential was used, or a bait only shown to attackers was taken."""
    raw = os.environ.get("AUTO_BLOCK_RULES", "W-AUTH-04,W-ADAPT-01")
    return {r.strip() for r in raw.split(",") if r.strip()}


def block_ttl_s() -> int:
    try:
        return max(60, min(int(os.environ.get("BLOCK_TTL_S", "86400")), 30 * 86400))
    except ValueError:
        return 86400


def _auto_block(store: Store, event: dict[str, Any], rule: str) -> None:
    ip = event["source_ip"]
    if rule not in auto_block_rules() or event["service"] != "web" or store.is_blocked(ip):
        return
    alert = store.get_alert(f"{rule}|{ip}") or {}
    store.add_block(ip, actor="auto", rule=rule, alert_id=alert.get("alert_id"), ttl_s=block_ttl_s(),
                    reason=f"{rule} on the honeypot: no legitimate user can trigger it")


def process_event(store: Store, event: dict[str, Any]) -> None:
    evidence = event.get("raw_evidence_redacted") or {}
    for d in evidence.get("detections") or []:
        if not isinstance(d, dict) or "rule" not in d:
            continue
        rule = str(d["rule"])
        if not rules_catalog.alerting(rule):
            continue
        evidence_ids = d.get("evidence_event_ids") or [] if rule.startswith("SSH-") else []
        if rule in PRECURSORS:
            evidence_ids = _precursors(store, event, *PRECURSORS[rule])
        _upsert(store, f"{rule}|{event['source_ip']}", event, rule=rule,
                title=TITLES.get(rule, str(d.get("label", rule))), severity=_severity(d),
                confidence=str(d.get("confidence", "low")), rationale=str(d.get("rationale", "")),
                attack=[a for a in d.get("attack") or [] if isinstance(a, dict)], stage=evidence.get("attack_stage"),
                evidence_ids=evidence_ids)
        _auto_block(store, event, rule)
    if event["service"] == "soc":
        _console_auth(store, event)
    _correlate(store, event)


def _precursors(store: Store, event: dict[str, Any], rule: str, window: timedelta, same_user: bool) -> list[str]:
    end = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
    fmt = lambda t: t.isoformat(timespec="milliseconds").replace("+00:00", "Z")  # noqa: E731
    user = event.get("username") if same_user else None
    if same_user and not user:
        return []
    return [i for i in store.recent_rule_events(event["source_ip"], rule, fmt(end - window), event["timestamp"], user)
            if i != event["event_id"]]


def _console_auth(store: Store, event: dict[str, Any]) -> None:
    """SOC-AUTH-01. One failed console login is an event (SOC-AUTH-00, never an alert). Five in ten
    minutes from one source, or against one username, is worth a look, at medium severity, because
    an analyst who forgot a password produces exactly the same evidence."""
    if event["event_type"] != "authentication" or event["outcome"] != "failed":
        return
    since = (datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) - SOC_AUTH_WINDOW)
    since_s = since.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    by_source = store.recent_auth_failures("soc", since_s, source_ip=event["source_ip"])
    by_user = store.recent_auth_failures("soc", since_s, username=event["username"]) if event.get("username") else []
    hits = by_source if len(by_source) >= len(by_user) else by_user
    if len(hits) < SOC_AUTH_THRESHOLD:
        return
    basis = "source" if hits is by_source else "username"
    _upsert(store, f"SOC-AUTH-01|{event['source_ip']}", event, rule="SOC-AUTH-01", title=TITLES["SOC-AUTH-01"],
            severity="medium", confidence="medium",
            rationale=f"{len(hits)} failed console logins for one {basis} within 10 minutes (threshold "
                      f"{SOC_AUTH_THRESHOLD}). Repeated mistyped passwords produce the same pattern.",
            attack=[{"technique": "T1110", "name": "Brute Force", "status": "candidate", "confidence": "medium",
                     "rationale": "repeated authentication failures; tried passwords are never recorded"}],
            stage="credential_access", evidence_ids=hits[-MAX_RELATED:])


def _correlate(store: Store, event: dict[str, Any]) -> None:
    """Shared IP is a hint, not proof of one actor; the rationale says so.

    An unknown-ssh- source is a label for one session with no address, not an address, so it links
    to nothing. A forged audit line can put that label on a Database event, and this keeps it inert.
    """
    if event["source_ip"].startswith("unknown-ssh-") or event["service"] == "soc":
        return
    since =(datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) - CORRELATION_WINDOW)
    since_s = since.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    services = store.services_for_source(event["source_ip"], since_s)
    if len(services) >= 2:
        _upsert(store, f"X-CORR-01|{event['source_ip']}", event, rule="X-CORR-01", title=TITLES["X-CORR-01"],
                severity="medium", confidence="low",
                rationale=f"Source IP active on {', '.join(sorted(services))} within 30 minutes. "
                          "A shared IP does not prove a single actor.", attack=[], stage=None,
                evidence_ids=[i for svc, i in store.latest_per_service(event["source_ip"], since_s).items()
                              if svc != event["service"]])
