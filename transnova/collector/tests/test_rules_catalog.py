"""The rule catalogue cannot claim what the code and tests do not back."""

from __future__ import annotations

import json
import re

from conftest import ROOT

from collector import rules_catalog
from collector.console_api import KNOWN_GAPS, TECHNIQUES

FIELDS = {"rule_id", "name", "service", "description", "logic", "required_evidence", "default_severity",
          "confidence_model", "false_positives", "attack", "tested_by"}


def test_every_rule_is_complete():
    for rid, entry in rules_catalog.RULES.items():
        assert FIELDS <= set(entry), rid
        assert all(entry[f] not in ("", None) for f in FIELDS - {"attack"}), rid
        assert entry["default_severity"] in ("low", "medium", "high", "critical"), rid


def test_every_technique_exists_in_the_attack_dataset():
    for rid, entry in rules_catalog.RULES.items():
        for tid in entry["attack"]:
            assert tid in TECHNIQUES, f"{rid} cites {tid}, which is not a current ATT&CK technique"
    for tid in KNOWN_GAPS:
        assert tid in TECHNIQUES, tid


def test_every_technique_a_sensor_emits_is_valid():
    found = set()
    for folder in ("services/web/web_decoy", "services/database/sensor", "services/ssh/sensor/src"):
        for path in (ROOT / folder).rglob("*"):
            if path.suffix in (".py", ".json"):
                found |= set(re.findall(r"\bT1\d{3}(?:\.\d{3})?\b", path.read_text(encoding="utf-8", errors="ignore")))
    found.discard("T1505.003")  # documented as never emitted (web mappings.py)
    assert found and found <= set(TECHNIQUES), found - set(TECHNIQUES)


def test_declared_tests_exist_and_name_the_rule():
    for rid, entry in rules_catalog.RULES.items():
        assert entry["tested_by"], rid
        for t in entry["tested_by"]:
            text = (ROOT / t["path"]).read_text(encoding="utf-8")
            assert t["needle"] in text, f"{rid}: {t['path']} does not mention {t['needle']}"


def test_every_sensor_rule_is_catalogued():
    web = json.dumps(open(ROOT / "services/web/web_decoy/detection/mappings.py", encoding="utf-8").read())
    for rid in re.findall(r'"(W-[A-Z]+-\d\d)"', web):
        assert rid in rules_catalog.RULES, rid
    from collector.ssh_ingest import RULES as SSH_RULES
    assert set(SSH_RULES) <= set(rules_catalog.RULES)


def test_owasp_mapping_targets_real_2025_categories():
    codes = {c for c, _ in rules_catalog.OWASP_2025_CATEGORIES}
    assert len(codes) == 10
    for label in rules_catalog.OWASP_2025.values():
        assert label.split("-")[0] in codes


def test_single_occurrence_signals_never_alert():
    for rid in ("W-AUTH-01", "W-ENUM-01", "SOC-AUTH-00"):
        assert rules_catalog.alerting(rid) is False
    assert rules_catalog.alerting("SOMETHING-NEW") is True
