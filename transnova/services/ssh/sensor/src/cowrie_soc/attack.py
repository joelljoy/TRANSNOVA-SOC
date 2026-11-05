"""MITRE ATT&CK (Enterprise) techniques this sensor can map to.

Only techniques for which a Cowrie event can provide direct evidence are
listed. Mappings are applied by the command classifier and detection rules,
never wholesale. Names follow ATT&CK v15+ wording.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str

    def as_dict(self) -> dict[str, str]:
        return {"technique_id": self.technique_id, "name": self.name, "tactic": self.tactic}


_CATALOG = [
    Technique("T1110", "Brute Force", "credential-access"),
    Technique("T1110.001", "Brute Force: Password Guessing", "credential-access"),
    Technique("T1110.003", "Brute Force: Password Spraying", "credential-access"),
    Technique("T1078", "Valid Accounts", "initial-access"),
    Technique("T1059.004", "Command and Scripting Interpreter: Unix Shell", "execution"),
    Technique("T1082", "System Information Discovery", "discovery"),
    Technique("T1033", "System Owner/User Discovery", "discovery"),
    Technique("T1087.001", "Account Discovery: Local Account", "discovery"),
    Technique("T1083", "File and Directory Discovery", "discovery"),
    Technique("T1016", "System Network Configuration Discovery", "discovery"),
    Technique("T1049", "System Network Connections Discovery", "discovery"),
    Technique("T1057", "Process Discovery", "discovery"),
    Technique("T1003.008", "OS Credential Dumping: /etc/passwd and /etc/shadow", "credential-access"),
    Technique("T1552.001", "Unsecured Credentials: Credentials In Files", "credential-access"),
    Technique("T1105", "Ingress Tool Transfer", "command-and-control"),
    Technique("T1222.002", "File and Directory Permissions Modification: Linux and Mac", "defense-evasion"),
    Technique("T1070.003", "Indicator Removal: Clear Command History", "defense-evasion"),
]

TECHNIQUES: dict[str, Technique] = {t.technique_id: t for t in _CATALOG}

DISCOVERY_TECHNIQUES = frozenset(t.technique_id for t in _CATALOG if t.tactic == "discovery")


def technique(technique_id: str) -> Technique:
    return TECHNIQUES[technique_id]


def as_dicts(technique_ids: list[str] | tuple[str, ...]) -> list[dict[str, str]]:
    seen: list[str] = []
    for tid in technique_ids:
        if tid not in seen:
            seen.append(tid)
    return [TECHNIQUES[tid].as_dict() for tid in seen]
