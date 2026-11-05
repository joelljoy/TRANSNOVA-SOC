import { ArrowLeft, ArrowRight } from "lucide-react";
import type { AttackRef, Detection, ExplainedDetection } from "../api/types";

// ATT&CK Enterprise tactic order (kill-chain left to right), used to sort and label tactics.
export const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution", "persistence", "privilege-escalation",
  "stealth", "defense-evasion", "defense-impairment", "credential-access", "discovery", "lateral-movement",
  "collection", "command-and-control", "exfiltration", "impact",
];

export const tacticName = (s: string) =>
  s.split("-").map((w) => (w === "and" ? w : w.charAt(0).toUpperCase() + w.slice(1))).join(" ");

const tacticRank = (s?: string) => {
  const i = TACTIC_ORDER.indexOf(s ?? "");
  return i === -1 ? 99 : i;
};

export interface MapRow {
  rule: string; ruleName?: string | null; confidence?: string | null; owasp?: string | null;
  technique: string; name?: string | null; tactics: string[]; url?: string | null; status?: string; why?: string | null;
}

export function rowsFromDetections(dets: ExplainedDetection[]): MapRow[] {
  const rows: MapRow[] = [];
  for (const d of dets) {
    for (const a of d.attack ?? []) {
      if (!a.technique) continue;
      rows.push({ rule: d.rule, ruleName: d.name, confidence: a.confidence ?? d.confidence, owasp: d.owasp_2025 ?? d.owasp_2021,
        technique: a.technique, name: a.name, tactics: a.tactics ?? [], url: a.url, status: a.status, why: a.rationale });
    }
  }
  return rows.sort((x, y) => tacticRank(x.tactics[0]) - tacticRank(y.tactics[0]));
}

export function rowsFromAttack(rule: string, ruleName: string | null | undefined, owasp: string | null | undefined,
  attack: AttackRef[]): MapRow[] {
  return attack.filter((a) => a.technique).map((a) => ({
    rule, ruleName, owasp, confidence: a.confidence, technique: a.technique!, name: a.name, tactics: a.tactics ?? [],
    url: a.url, status: a.status, why: a.rationale,
  }));
}

/** Technique IDs carried by an event's sensor detections (for table columns; no names needed). */
export function eventTechniques(dets: Detection[] | undefined): string[] {
  const out = new Set<string>();
  for (const d of dets ?? []) for (const a of d.attack ?? []) if (a.technique) out.add(a.technique);
  return [...out];
}

export function AttackMap({ rows, empty }: { rows: MapRow[]; empty?: string }) {
  if (!rows.length) {
    return <p className="small muted">{empty ?? "No ATT&CK technique is mapped. The matching rules don't claim one."}</p>;
  }
  return (
    <ol className="attack-map" aria-label="ATT&CK mapping">
      {rows.map((r, i) => (
        <li className="am-row" key={`${r.rule}-${r.technique}-${i}`}>
          <div className="am-cell am-tactic">
            <span className="am-k">Tactic</span>
            <span className="am-v">{r.tactics.length ? r.tactics.map(tacticName).join(" · ") : "Not in dataset"}</span>
          </div>
          <ArrowRight className="am-arrow" aria-hidden size={18} />
          <div className="am-cell am-tech">
            <span className="am-k">Technique</span>
            <span className="am-v">
              {r.url ? <a href={r.url} target="_blank" rel="noreferrer noopener" className="mono">{r.technique}</a>
                : <span className="mono">{r.technique}</span>}{" "}
              {r.name ?? <span className="bad-ink">unknown to ATT&amp;CK v20</span>}
            </span>
          </div>
          <ArrowLeft className="am-arrow" aria-hidden size={18} />
          <div className="am-cell am-rule">
            <span className="am-k">Detected by</span>
            <span className="am-v"><span className="mono">{r.rule}</span>{r.ruleName ? ` ${r.ruleName}` : ""}</span>
          </div>
          <div className="am-meta small">
            <span className={`am-basis ${r.status === "observed" ? "is-observed" : "is-candidate"}`}>
              {r.status === "observed" ? "Supported by evidence" : "inferred by rule (candidate)"}
            </span>
            {r.confidence && <span>confidence <b>{r.confidence}</b></span>}
            {r.owasp && <span>{r.owasp}</span>}
            {r.why && <span className="muted">{r.why}</span>}
          </div>
        </li>
      ))}
    </ol>
  );
}
