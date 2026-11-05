import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { X } from "lucide-react";
import { useAlerts, useRules } from "../api/hooks";
import { Empty, ErrorState, Loading, PageHeader, Pager, Panel, Severity, SourceLink, Status, When } from "../components/ui";
import { SERVICE_LABEL, STATUS_LABEL } from "../lib/format";
import { isNew, useSeenSince } from "../lib/seen";

const PAGE = 25;
const KEYS = ["status", "severity", "rule", "source_ip", "service", "technique", "tactic", "owasp", "since", "until"];

export function Alerts() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const since = useSeenSince("alerts");
  const rules = useRules();
  const offset = Number(params.get("offset") ?? 0);
  const sort = params.get("sort") === "recent" ? "recent" : "severity";
  const query: Record<string, string | number> = { limit: PAGE, offset, sort };
  for (const k of KEYS) { const v = params.get(k); if (v) query[k] = v; }
  const alerts = useAlerts(query);
  const set = (k: string, v: string) => {
    const n = new URLSearchParams(params);
    if (v) n.set(k, v); else n.delete(k);
    n.delete("offset");
    setParams(n, { replace: true });
  };
  const active = KEYS.filter((k) => params.get(k));

  return (
    <div className="page">
      <PageHeader title="Alerts" lede="Alerts open only when a rule's documented condition is met, and one alert per rule and source is updated rather than repeated. Single failed logins stay events." />
      <Panel>
        <div className="filters">
          <label className="field">Status
            <select className="select" value={params.get("status") ?? ""} onChange={(e) => set("status", e.target.value)}>
              <option value="">All</option>
              {Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
          </label>
          <label className="field">Severity
            <select className="select" value={params.get("severity") ?? ""} onChange={(e) => set("severity", e.target.value)}>
              <option value="">All</option>
              {["critical", "high", "medium", "low"].map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
          </label>
          <label className="field">Decoy
            <select className="select" value={params.get("service") ?? ""} onChange={(e) => set("service", e.target.value)}>
              <option value="">All</option>
              {["web", "database", "ssh", "soc"].map((s) => <option key={s} value={s}>{SERVICE_LABEL[s]}</option>)}
            </select>
          </label>
          <label className="field">Rule
            <select className="select" value={params.get("rule") ?? ""} onChange={(e) => set("rule", e.target.value)}>
              <option value="">Any</option>
              {rules.data?.rules.filter((r) => r.alerting).map((r) => <option key={r.rule_id} value={r.rule_id}>{r.rule_id} {r.name}</option>)}
            </select>
          </label>
          <label className="field">Source
            <input className="input" defaultValue={params.get("source_ip") ?? ""} placeholder="IP address"
              onKeyDown={(e) => { if (e.key === "Enter") set("source_ip", (e.target as HTMLInputElement).value.trim()); }}
              onBlur={(e) => set("source_ip", e.target.value.trim())} />
          </label>
          <label className="field">Technique
            <input className="input" defaultValue={params.get("technique") ?? ""} placeholder="T1110"
              onBlur={(e) => set("technique", e.target.value.trim().toUpperCase())} />
          </label>
          <label className="field">Order
            <select className="select" value={sort} onChange={(e) => set("sort", e.target.value === "recent" ? "recent" : "")}>
              <option value="severity">Severity, then most recent</option>
              <option value="recent">Most recent activity</option>
            </select>
          </label>
        </div>
        {active.length > 0 && (
          <div className="chips" style={{ marginTop: 12 }}>
            {active.map((k) => <span className="chip" key={k}>{k.replace("_", " ")}: <span className="mono">{params.get(k)}</span>
              <button aria-label={`Remove ${k} filter`} onClick={() => set(k, "")}><X size={14} /></button></span>)}
          </div>
        )}
      </Panel>
      <Panel flush title={alerts.data ? `${alerts.data.total} alerts` : "Alerts"} id="alerts">
        {alerts.isLoading ? <Loading rows={6} /> : alerts.isError ? <ErrorState error={alerts.error} retry={() => alerts.refetch()} /> :
          alerts.data!.items.length === 0 ? (
            active.length ? <Empty title="No alerts match these filters" /> :
              <Empty title="No alerts">Nothing has met an alerting rule's threshold. Every interaction is still recorded in All events.</Empty>
          ) : (
            <>
              <div className="table-wrap">
                <table className="data">
                  <caption className="sr-only">Alerts</caption>
                  <thead><tr>
                    <th scope="col">Severity</th><th scope="col">Alert</th><th scope="col">Source</th><th scope="col">Events</th>
                    <th scope="col">Confidence</th><th scope="col">ATT&amp;CK</th><th scope="col">Last activity</th><th scope="col">Status</th>
                  </tr></thead>
                  <tbody>
                    {alerts.data!.items.map((a) => (
                      <tr key={a.alert_id} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a")) navigate(`/alerts/${a.alert_id}`); }}>
                        <td><Severity value={a.severity} /></td>
                        <td>
                          {isNew(a.last_seen, since) && <span className="new-mark" title="New activity since your last visit" aria-label="new" />}
                          <Link to={`/alerts/${a.alert_id}`} style={{ color: "inherit", fontWeight: 700, textDecoration: "none" }}>{a.title}</Link>
                          <div className="small muted"><span className="mono">{a.rule}</span> · {SERVICE_LABEL[a.service] ?? a.service}</div>
                        </td>
                        <td className="nowrap"><SourceLink ip={a.source_ip} /></td>
                        <td className="num">{a.event_count}</td>
                        <td>{a.confidence ?? "—"}</td>
                        <td className="nowrap">{a.attack_ids.length ? a.attack_ids.map((t) => <span className="tchip" key={t}>{t}</span>) : <span className="muted small">none</span>}</td>
                        <td className="nowrap"><When iso={a.last_seen} full /></td>
                        <td className="nowrap"><Status value={a.status} />{a.activity_after_status && <div className="small" style={{ color: "var(--amber-ink)" }}>new activity since</div>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <Pager total={alerts.data!.total} limit={PAGE} offset={offset} noun="alerts"
                onChange={(o) => { const n = new URLSearchParams(params); n.set("offset", String(o)); setParams(n); }} />
            </>
          )}
      </Panel>
    </div>
  );
}
