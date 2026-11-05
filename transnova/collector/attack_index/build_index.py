"""Build enterprise_index.json from MITRE's official Enterprise ATT&CK STIX bundle.

    python -I collector/attack_index/build_index.py <enterprise-attack.json>

Source: https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json).
Only current objects are kept: revoked and deprecated techniques are dropped, so an ID that is no
longer valid fails validation instead of being shown as a live technique.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

OUT = Path(__file__).with_name("enterprise_index.json")


def main(path: str) -> None:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = bundle["objects"]
    version = next((o.get("x_mitre_version") for o in objects if o["type"] == "x-mitre-collection"), None)
    modified = next((o.get("modified") for o in objects if o["type"] == "x-mitre-collection"), None)
    matrix = next(o for o in objects if o["type"] == "x-mitre-matrix" and not o.get("revoked"))
    tactic_by_ref = {o["id"]: o for o in objects if o["type"] == "x-mitre-tactic"}
    tactics = []
    for ref in matrix["tactic_refs"]:
        t = tactic_by_ref[ref]
        ext = next(r for r in t["external_references"] if r.get("source_name") == "mitre-attack")
        tactics.append({"id": ext["external_id"], "shortname": t["x_mitre_shortname"], "name": t["name"]})
    techniques = {}
    for o in objects:
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext:
            continue
        tid = ext["external_id"]
        techniques[tid] = {
            "name": o["name"],
            "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            "subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "url": ext.get("url"),
        }
    OUT.write_text(json.dumps({"source": "mitre-attack/attack-stix-data enterprise-attack.json",
                               "attack_version": version, "modified": modified, "tactics": tactics,
                               "techniques": dict(sorted(techniques.items()))}, separators=(",", ":")),
                   encoding="utf-8")
    print(f"ATT&CK {version}: {len(tactics)} tactics, {len(techniques)} techniques -> {OUT}")


if __name__ == "__main__":
    main(sys.argv[1])
