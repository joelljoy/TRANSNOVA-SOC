"""MITRE Engage: which deception activity exposed each detection (USP 2).

ATT&CK answers "what did the attacker do". Engage, MITRE's framework for adversary engagement and
deception, answers "which of our deceptions made that visible". Activity names, goals (Expose, Affect,
Elicit) and approaches (Collect, Detect, Prevent, Direct, Disrupt, Reassure, Motivate) follow the Engage
matrix (https://engage.mitre.org/matrix/). Engage activity IDs are deliberately NOT shown: we could
not verify them from an authoritative source, and a wrong ID is worse than none.
"""

from __future__ import annotations

from typing import Any

MATRIX_URL = "https://engage.mitre.org/matrix/"

ACTIVITIES: dict[str, str] = {
    "Decoy System": "A system that exists only to be found and touched; every interaction with it is suspect.",
    "Decoy Account": "An account with no legitimate user, so any use of it is adversary activity.",
    "Decoy Credential": "Planted credentials whose use reveals that someone harvested them.",
    "Decoy Content": "Seeded, synthetic records and files that look valuable and steer the adversary.",
    "Lures": "Breadcrumbs (robots.txt entries, leaked comments, revealed links) that lead the adversary to the decoys.",
    "Introduced Vulnerabilities": "Weaknesses that appear exploitable (legacy endpoints, injectable-looking inputs) "
                                  "so attempts are exposed safely.",
    "Network Monitoring": "Watching connection metadata, such as anonymizer origin, to expose the adversary.",
    "Isolation": "Containing the adversary so their actions cannot reach real assets.",
    "Security Controls": "Changing defences in response to what the deception revealed, e.g. blocking on the real site.",
}

# rule -> list of (activity, goal, approach)
RULE_ACTIVITIES: dict[str, list[tuple[str, str, str]]] = {
    "W-ENUM-01": [("Lures", "Expose", "Detect"), ("Decoy System", "Expose", "Detect")],
    "W-ENUM-02": [("Lures", "Expose", "Detect"), ("Decoy System", "Expose", "Detect")],
    "W-AUTH-01": [("Decoy System", "Expose", "Detect")],
    "W-AUTH-02": [("Decoy System", "Expose", "Detect")],
    "W-AUTH-03": [("Decoy System", "Expose", "Detect")],
    "W-AUTH-04": [("Decoy Credential", "Expose", "Detect"), ("Decoy Account", "Elicit", "Motivate")],
    "W-SQLI-01": [("Introduced Vulnerabilities", "Expose", "Detect")],
    "W-XSS-01": [("Introduced Vulnerabilities", "Expose", "Detect")],
    "W-PATH-01": [("Introduced Vulnerabilities", "Expose", "Detect")],
    "W-SSRF-01": [("Introduced Vulnerabilities", "Expose", "Detect"), ("Lures", "Elicit", "Motivate")],
    "W-UPL-01": [("Introduced Vulnerabilities", "Expose", "Collect")],
    "W-IDOR-01": [("Decoy Content", "Elicit", "Reassure")],
    "W-SHELL-01": [("Decoy System", "Expose", "Detect")],
    "W-ANON-01": [("Network Monitoring", "Expose", "Collect")],
    "W-ANON-02": [("Network Monitoring", "Expose", "Collect")],
    "W-ADAPT-01": [("Lures", "Elicit", "Motivate"), ("Decoy Content", "Expose", "Detect")],
    "D-SENS-01": [("Decoy Content", "Expose", "Detect")],
    "D-ADAPT-01": [("Lures", "Elicit", "Motivate"), ("Decoy Content", "Expose", "Detect")],
    "X-CORR-01": [("Network Monitoring", "Expose", "Collect")],
}
# Response actions are themselves Engage "Affect" activities.
BLOCK_ACTIVITY = [("Security Controls", "Affect", "Prevent")]


def for_rule(rule: str) -> list[dict[str, Any]]:
    pairs = RULE_ACTIVITIES.get(rule)
    if pairs is None:
        if rule.startswith("SSH-"):
            pairs = [("Decoy System", "Expose", "Detect")]
        elif rule.startswith("D-"):
            pairs = [("Decoy System", "Expose", "Detect")]
        else:
            pairs = []
    return [{"activity": a, "goal": g, "approach": ap, "description": ACTIVITIES[a]} for a, g, ap in pairs]
