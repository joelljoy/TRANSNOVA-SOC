import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useMitre, useRules } from "../api/hooks";
import { getData } from "../api/client";
import type { MitreRow } from "../api/types";
import { TACTIC_ORDER } from "../components/AttackMap";
import { Empty, ErrorState, KV, Loading, PageHeader, Panel } from "../components/ui";
import { plural, SERVICE_LABEL, words } from "../lib/format";

const STATUS: Record<MitreRow["status"], { label: string; help: string }> = {
  evidence: { label: "Supported by evidence", help: "A sensor observed this technique directly in a stored event." },
  rule_inferred: { label: "Inferred by a rule", help: "A rule matched and names this technique as a candidate; the evidence does not prove it." },
  implemented_not_observed: { label: "Detection ready, not seen", help: "A rule can map this technique, but no stored event has triggered it." },
  gap: { label: "Known gap", help: "The decoys could plausibly see this technique, and no rule detects it." },
};

export function Mitre() {
  const mitre = useMitre();
  const rules = useRules();
  const [pick, setPick] = useState<string | null>(null);
  const [filter, setFilter] = useState<MitreRow["status"] | "">("");
  const [exportError, setExportError] = useState<string | null>(null);
  const downloadLayer = async () => {
    setExportError(null);
    try {
      const layer = await getData<Record<string, unknown>>("navigator");
      const url = URL.createObjectURL(new Blob([JSON.stringify(layer, null, 2)], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `transnova-attack-layer-${new Date().toISOString().slice(0, 10)}.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setExportError((e as Error).message);
    }
  };
  const grouped = useMemo(() => {
    if (!mitre.data) return [];
    return mitre.data.tactics.map((t) => ({
      tactic: t, rows: mitre.data!.techniques.filter((r) => r.tactics.includes(t.shortname) && (!filter || r.status === filter)),
    })).filter((g) => g.rows.length);
  }, [mitre.data, filter]);
  if (mitre.isLoading) return <div className="page"><PageHeader title="MITRE ATT&CK" /><Loading rows={8} /></div>;
  if (mitre.isError) return <div className="page"><PageHeader title="MITRE ATT&CK" /><Panel><ErrorState error={mitre.error} /></Panel></div>;
  const m = mitre.data!;
  const sel = m.techniques.find((r) => r.technique === pick);
  const counts = m.techniques.reduce<Record<string, number>>((a, r) => ({ ...a, [r.status]: (a[r.status] ?? 0) + 1 }), {});
  const seen = (r: MitreRow) => r.evidence_observed + r.evidence_candidate;
  const maxSeen = Math.max(1, ...m.techniques.map(seen));
  const heat = [...m.tactics]
    .sort((a, b) => TACTIC_ORDER.indexOf(a.shortname) - TACTIC_ORDER.indexOf(b.shortname))
    .map((t) => ({ tactic: t, rows: m.techniques.filter((r) => r.tactics.includes(t.shortname) && seen(r) > 0)
      .sort((a, b) => seen(b) - seen(a)) }))
    .filter((g) => g.rows.length);
  const seenTotal = m.techniques.filter((r) => seen(r) > 0).length;
  return (
    <div className="page">
      <PageHeader title="MITRE ATT&CK" actions={<button className="btn" onClick={downloadLayer}>Download Navigator layer</button>} lede={<>Coverage of the {m.total_techniques} techniques in ATT&amp;CK Enterprise v{m.attack_version}, validated against MITRE's STIX dataset. Only techniques a rule can map, or a known gap, are listed. This is not a claim to detect the framework.</>} />
      {exportError && <p className="notice bad" role="alert">Export failed: {exportError}</p>}
      <Panel title="Observed attacker behaviour" id="heat"
        aside={<span className="small muted">{plural(seenTotal, "technique")} seen across {plural(heat.length, "tactic")}</span>}>
        {heat.length === 0 ? <Empty title="No technique observed yet">Attack a decoy and the techniques its rules map will appear here, left to right in kill-chain order.</Empty> : (
          <div className="heat" role="list">
            {heat.map(({ tactic, rows }) => (
              <div className="heat-col" key={tactic.id} role="listitem">
                <div className="heat-head">{tactic.name}<span className="mono">{tactic.id}</span></div>
                {rows.map((r) => {
                  const n = seen(r);
                  const level = Math.min(4, Math.ceil((n / maxSeen) * 4));
                  return (
                    <button key={r.technique} className={`heat-cell lvl-${level}`} aria-pressed={pick === r.technique}
                      onClick={() => setPick(r.technique)} title={`${r.technique} ${r.name ?? ""}: ${plural(n, "event")}`}>
                      <span className="mono">{r.technique}</span>
                      <span className="heat-name">{r.name}</span>
                      <span className="heat-n num">{n}</span>
                    </button>
                  );
                })}
              </div>
            ))}
          </div>
        )}
        <p className="small muted" style={{ marginTop: 12 }}>Darker = more events. Web rules report techniques as <b>candidates</b> (the rule saw the attempt, not proof it worked), so they count under "Inferred by a rule"; "Supported by evidence" is reserved for sensors that observe the technique directly (e.g. an SSH command that was actually run).</p>
      </Panel>
      <Panel>
        <div className="row" role="group" aria-label="Filter by coverage">
          <button className="btn" aria-pressed={filter === ""} onClick={() => setFilter("")}>All ({m.techniques.length})</button>
          {(Object.keys(STATUS) as MitreRow["status"][]).map((k) => (
            <button key={k} className="btn" aria-pressed={filter === k} onClick={() => setFilter(k)} title={STATUS[k].help}>
              {STATUS[k].label} ({counts[k] ?? 0})
            </button>
          ))}
        </div>
      </Panel>
      <div className="grid-2">
        <Panel title="By tactic" id="matrix">
          {grouped.length === 0 ? <Empty title="No technique in this group" /> : (
            <div className="tactics">
              {grouped.map(({ tactic, rows }) => (
                <div className="tactic" key={tactic.id}>
                  <h3>{tactic.name} <span className="muted mono">{tactic.id}</span></h3>
                  {rows.map((r) => (
                    <button key={r.technique} className={`tech cov-${r.status}`} aria-pressed={pick === r.technique} onClick={() => setPick(r.technique)}>
                      <span className="tid">{r.technique}</span> {r.name}
                      <div className="small muted">{STATUS[r.status].label}{r.evidence_observed + r.evidence_candidate ? ` · ${plural(r.evidence_observed + r.evidence_candidate, "event")}` : ""}</div>
                    </button>
                  ))}
                </div>
              ))}
            </div>
          )}
        </Panel>
        <Panel title={sel ? `${sel.technique} ${sel.name}` : "Technique detail"} id="detail">
          {!sel ? <p className="small muted">Choose a technique to see the rules, tests and evidence behind its status.</p> : (
            <div className="stack">
              <p className="small">{STATUS[sel.status].help}</p>
              <KV rows={[
                ["Tactics", sel.tactics.map(words).join(", ")],
                ["Decoys", sel.services.map((s) => SERVICE_LABEL[s] ?? s).join(", ") || null],
                ["Rules", sel.rules.length ? sel.rules.join(", ") : "none"],
                ["Rules with tests", sel.rules_tested.length ? sel.rules_tested.join(", ") : "none"],
                ["Events (observed)", sel.evidence_observed],
                ["Events (rule candidate)", sel.evidence_candidate],
                ["Alerts", sel.alerts],
                ["Reference", sel.url && <a href={sel.url} target="_blank" rel="noreferrer noopener">attack.mitre.org</a>],
              ]} />
              {sel.gap_reason && <p className="notice">{sel.gap_reason}</p>}
              {sel.evidence_observed + sel.evidence_candidate > 0 && <Link className="btn" to={`/events?technique=${sel.technique}`}>Show the events</Link>}
              {rules.data?.rules.filter((r) => sel.rules.includes(r.rule_id)).map((r) => (
                <div className="slip kind-rule" key={r.rule_id}>
                  <div className="slip-top"><span className="slip-id">{r.rule_id}</span></div>
                  <div className="slip-title">{r.name}</div>
                  <div className="slip-det">{r.logic}<br />Tests: {r.tested_by.map((t) => `${t.path.split("/").pop()} (${t.kind})`).join(", ")}</div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
      <p className="small muted">Source: {m.source}, modified {m.modified?.slice(0, 10)}. AI explanations never add a mapping here.</p>
    </div>
  );
}
