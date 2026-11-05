"""Explainable risk scoring and evidence-based ATT&CK mapping.

score = category base + behaviour modifiers, capped at 100. Every point is listed in `reasons`.
Bands come from rules.json. A plain SELECT on an ordinary table stays LOW however often it
runs; it only rises when the surrounding behaviour justifies it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .classify import Classification
from .state import SourceTracker


@dataclass
class Assessment:
    risk_score: int
    severity: str
    attack_stage: str | None
    reasons: list[str] = field(default_factory=list)
    mitre: list[dict[str, Any]] = field(default_factory=list)


def severity_for(score: int, rules: dict[str, Any]) -> str:
    for name, floor in sorted(rules["severity_thresholds"].items(), key=lambda kv: -kv[1]):
        if score >= floor:
            return name
    return "LOW"


def technique(rules: dict[str, Any], tid: str, status: str, confidence: str, rationale: str) -> dict[str, Any]:
    spec = rules["mitre"][tid]
    return {"technique": tid, "name": spec["name"], "tactic": spec["tactic"], "status": status,
            "confidence": confidence, "rationale": rationale}


def assess_query(c: Classification, outcome: str, tracker: SourceTracker, rules: dict[str, Any]) -> Assessment:
    cat = rules["categories"][c.category]
    mods = rules["modifiers"]
    score = cat["base"]
    reasons = [f"+{cat['base']} base for category {c.category}"]

    def add(key: str) -> None:
        nonlocal score
        score += mods[key]["points"]
        reasons.append(f"+{mods[key]['points']} {mods[key]['reason']}")

    is_read_target = c.category in ("sensitive_access", "adaptive_decoy_access")
    sensitive = set(rules["sensitive_tables"]) | set(rules["adaptive_tables"])
    sensitive_read = len(sensitive & set(tracker.table_hits))
    if c.category == "reconnaissance" and tracker.enumeration_count >= mods["repeated_enumeration"]["threshold"]:
        add("repeated_enumeration")
    if c.category == "data_exploration" and tracker.distinct_tables >= mods["multi_table_sweep"]["threshold"]:
        add("multi_table_sweep")
    if is_read_target and sensitive_read >= mods["multi_sensitive"]["threshold"]:
        add("multi_sensitive")
    if is_read_target and tracker.enumeration_count > 0:
        add("enumeration_then_sensitive")
    if outcome == "blocked" and tracker.denied_count >= mods["repeated_denials"]["threshold"]:
        add("repeated_denials")
    if c.unbounded and c.category != "client_noise":
        add("unbounded_select")
    if c.has_join:
        add("join")
    score = min(score, 100)
    return Assessment(score, severity_for(score, rules), cat["stage"], reasons,
                      map_mitre(c, outcome, tracker, rules))


def map_mitre(c: Classification, outcome: str, tracker: SourceTracker, rules: dict[str, Any]) -> list[dict[str, Any]]:
    """Mapped only from a table that holds that kind of data, or from a real sweep. A denied
    statement is reported as `attempted`: the server refused it, so nothing was collected."""
    if c.category not in ("sensitive_access", "adaptive_decoy_access", "restricted_access", "reconnaissance",
                          "data_exploration"):
        return []
    status = "observed" if outcome == "succeeded" else "attempted"
    confidence = "medium" if outcome == "succeeded" else "low"
    found: dict[str, dict[str, Any]] = {}
    for table in c.tables:
        tid = rules["mitre_table_map"].get(table)
        if tid:
            verb = "read" if outcome == "succeeded" else "denied access to"
            found.setdefault(tid, technique(rules, tid, status, confidence, f"{verb} {table}"))
    if outcome == "succeeded" and "T1213" not in found \
            and tracker.distinct_tables >= rules["mitre_collection_table_threshold"] and c.category == "data_exploration":
        found["T1213"] = technique(rules, "T1213", "observed", "low",
                                   f"{tracker.distinct_tables} distinct tables read from the repository")
    return list(found.values())


def assess_auth_failure(tracker: SourceTracker, rules: dict[str, Any]) -> Assessment:
    cat = rules["categories"]["authentication_failed"]
    mod = rules["modifiers"]["brute_force"]
    score = cat["base"]
    reasons = [f"+{cat['base']} failed database login"]
    mitre: list[dict[str, Any]] = []
    if len(tracker.failed_logins) >= mod["threshold"]:
        score += mod["points"]
        reasons.append(f"+{mod['points']} {mod['reason']}")
        users = len(set(tracker.failed_usernames))
        if users >= rules["spraying_username_threshold"]:
            mitre.append(technique(rules, "T1110.003", "observed", "medium",
                                   f"{len(tracker.failed_logins)} failures across {users} usernames in the window"))
        else:
            mitre.append(technique(rules, "T1110.001", "observed", "medium",
                                   f"{len(tracker.failed_logins)} failures across {users} username(s) in the window"))
    return Assessment(score, severity_for(score, rules), cat["stage"], reasons, mitre)
