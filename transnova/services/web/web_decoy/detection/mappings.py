"""Rule catalogue: one place for labels, OWASP categories, ATT&CK candidates.

ATT&CK discipline (HANDOFF §10, PLAN §9 decision 6):
- Every ATT&CK entry is status "candidate"; the collector's alert layer decides.
- T1190 for exploitation ATTEMPTS against the public app (SQLi, path traversal, SSRF).
- T1505.003 is NEVER emitted: a webshell path probe or upload is not a deployed webshell
  (probe -> T1595.003 wordlist scanning; upload -> T1105 ingress tool transfer attempt).
- Phase 3 (2026-11-01) added candidates so every attack-type rule maps to a technique:
  W-AUTH-04 T1078, W-IDOR-01 T1213, W-UPL-01 T1105, W-SHELL-01 T1595.003, W-PATH-01/W-SSRF-01 T1190,
  W-XSS-01 T1189 (low). Single-occurrence signals (W-ENUM-01, W-AUTH-01) stay unmapped.
"""

from __future__ import annotations

from typing import Any

NO_SUCCESS = "attempt observed; no evidence of success"

A01 = "A01:2021-Broken Access Control"
A03 = "A03:2021-Injection"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A07 = "A07:2021-Identification and Authentication Failures"
A10 = "A10:2021-Server-Side Request Forgery"

RULES: dict[str, dict[str, Any]] = {
    "W-ENUM-01": {"label": "enum:sensitive_path", "category": "probe_detected", "owasp": A05,
                  "confidence": "low", "attack": []},
    "W-ENUM-02": {"label": "enum:route_scan", "category": "behavior_detected", "owasp": A05,
                  "confidence": "medium",
                  "attack": [("T1595.003", "medium", "many distinct missing/forbidden paths from one source: "
                                                     "wordlist scanning pattern")]},
    "W-AUTH-01": {"label": "auth:failed", "category": "behavior_detected", "owasp": A07,
                  "confidence": "low", "attack": []},
    "W-AUTH-02": {"label": "auth:bruteforce", "category": "behavior_detected", "owasp": A07,
                  "confidence": "medium",
                  "attack": [("T1110.001", None, "repeated failed passwords for one username from one source")]},
    "W-AUTH-03": {"label": "auth:spraying", "category": "behavior_detected", "owasp": A07,
                  "confidence": "medium",
                  "attack": [("T1110.003", "medium", "few attempts each across many usernames from one source")]},
    "W-AUTH-04": {"label": "auth:decoy_success", "category": "decoy_interaction", "owasp": A07,
                  "confidence": "high",
                  "attack": [("T1078", "high", "a planted decoy account was used to sign in: valid-account use")]},
    "W-SQLI-01": {"label": "probe:sqli", "category": "probe_detected", "owasp": A03,
                  "confidence": "medium",
                  "attack": [("T1190", "medium", "SQL injection-like input to a public-facing application; "
                                                 + NO_SUCCESS)]},
    "W-XSS-01": {"label": "probe:xss", "category": "probe_detected", "owasp": A03,
                 "confidence": "medium",
                 "attack": [("T1189", "low", "script-injection attempt aimed at site visitors' browsers (drive-by); "
                                             + NO_SUCCESS)]},
    "W-PATH-01": {"label": "probe:path_traversal", "category": "probe_detected", "owasp": A01,
                  "confidence": "medium",
                  "attack": [("T1190", "medium", "path traversal against a public-facing application; " + NO_SUCCESS)]},
    "W-SSRF-01": {"label": "probe:ssrf", "category": "probe_detected", "owasp": A10,
                  "confidence": "medium",
                  "attack": [("T1190", "medium", "server-side request forgery attempt against a public-facing "
                                                 "application; " + NO_SUCCESS)]},
    "W-UPL-01": {"label": "upload:suspicious", "category": "probe_detected", "owasp": A04,
                 "confidence": "medium",
                 "attack": [("T1105", "medium", "attempt to transfer a script or executable onto the server; "
                                                "never stored or executed")]},
    "W-IDOR-01": {"label": "authz:idor_attempt", "category": "probe_detected", "owasp": A01,
                  "confidence": "medium",
                  "attack": [("T1213", "medium", "reading other customers' records from the portal's data store")]},
    "W-SHELL-01": {"label": "probe:webshell_path", "category": "probe_detected", "owasp": A05,
                   "confidence": "low",
                   "attack": [("T1595.003", "low", "request for a known web-shell filename: wordlist probing, "
                                                   "not a deployed web shell")]},
    # Adaptive deception (USP 6): a bait only revealed to sources that already showed intent.
    "W-ADAPT-01": {"label": "decoy:adaptive_bait", "category": "decoy_interaction", "owasp": A01,
                   "confidence": "high",
                   "attack": [("T1213", "high", "opened a database export that was revealed only to this source "
                                                "after it showed attack intent")]},
    # Anonymizer labels (Phase 2). The portal ALLOWS these visitors (we want their activity);
    # the public main site blocks them. Tor exits are a public list, so this is strong;
    # VPN/hosting ranges are best effort.
    "W-ANON-01": {"label": "anon:tor", "category": "behavior_detected", "owasp": None,
                  "confidence": "medium",
                  "attack": [("T1090.003", "medium", "traffic arrives from a Tor exit node: multi-hop proxy")]},
    "W-ANON-02": {"label": "anon:vpn_or_hosting", "category": "behavior_detected", "owasp": None,
                  "confidence": "low",
                  "attack": [("T1090", "low", "traffic arrives from a VPN or hosting range: consistent with "
                                              "proxying, but could be a legitimate cloud client")]},
}


def make(rule: str, field: str, rationale: str, confidence: str | None = None,
         attack_confidence: str | None = None) -> dict[str, Any]:
    """Build a detection dict. Never pass request VALUES in `rationale`; describe them."""
    spec = RULES[rule]
    conf = confidence or spec["confidence"]
    out = {
        "rule": rule,
        "category": spec["category"],
        "label": spec["label"],
        "field": field,
        "owasp": spec["owasp"],
        "confidence": conf,
        "rationale": rationale,
        "attack": [
            {"technique": tech, "status": "candidate", "rationale": why,
             "confidence": attack_confidence or tconf or conf}
            for tech, tconf, why in spec["attack"]
        ],
    }
    if out["owasp"] is None:
        del out["owasp"]
    return out
