import { Link } from "react-router-dom";
import { useEvents, useOwasp, useRules } from "../api/hooks";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorState, Loading, PageHeader, Panel, When } from "../components/ui";
import { useSearchParams } from "react-router-dom";

export function Owasp() {
  const owasp = useOwasp();
  const rules = useRules();
  const [params, setParams] = useSearchParams();
  const code = params.get("category");
  const events = useEvents({ service: "web", owasp: code ?? undefined, detection: code ? undefined : "matched", limit: 20 });
  if (owasp.isLoading) return <div className="page"><PageHeader title="OWASP web security" /><Loading rows={8} /></div>;
  if (owasp.isError) return <div className="page"><PageHeader title="OWASP web security" /><Panel><ErrorState error={owasp.error} /></Panel></div>;
  const o = owasp.data!;
  const cat = o.categories.find((c) => c.code === code);
  const ruleInfo = (id: string) => rules.data?.rules.find((r) => r.rule_id === id);
  return (
    <div className="page">
      <PageHeader title="OWASP web security" lede={<>Web decoy traffic classified against the <a href={o.source} target="_blank" rel="noreferrer noopener">{o.edition}</a>. The sensor emits {o.sensor_edition}; both labels are kept. A match means the request looked like an attack, never that it succeeded: the decoy has nothing real to exploit.</>} />
      <Panel flush title={`${o.web_events.toLocaleString()} web decoy events`} id="cats">
        <div className="table-wrap"><table className="data">
          <caption className="sr-only">OWASP categories</caption>
          <thead><tr><th scope="col">Category</th><th scope="col">Rules</th><th scope="col">Matches</th><th scope="col">Last match</th><th scope="col">Coverage</th></tr></thead>
          <tbody>{o.categories.map((c) => (
            <tr key={c.code} className={c.observable ? "clickable" : undefined} aria-selected={code === c.code}
              onClick={() => c.observable && setParams(code === c.code ? {} : { category: c.code }, { replace: true })}>
              <td><span className="mono">{c.code}</span> {c.name}</td>
              <td className="mono small">{c.rules.join(", ") || "—"}</td>
              <td className="num">{c.matches}</td>
              <td><When iso={c.last_seen} full /></td>
              <td className="small">{c.observable ? (c.rules.length ? "Rule-based detection" : "Observable, no rule") : <span className="muted">{c.not_observable_reason}</span>}</td>
            </tr>
          ))}</tbody>
        </table></div>
      </Panel>
      <div className="grid-2">
        <Panel flush title={cat ? `${cat.code} ${cat.name}: matching requests` : "Web requests with a rule match"} id="ev"
          aside={cat && <button className="btn quiet small" onClick={() => setParams({}, { replace: true })}>Show all categories</button>}>
          {events.isLoading ? <Loading /> : events.isError ? <ErrorState error={events.error} /> : events.data!.items.length === 0 ? (
            <Empty title="No matching web traffic">This category has not been seen in decoy traffic.</Empty>
          ) : <EventTable events={events.data!.items} caption="Matching web events" columns={["time", "source", "what", "outcome", "attack", "detection"]} />}
          {events.data && events.data.total > 20 && <p className="small" style={{ padding: "8px 20px" }}><Link to={`/events?service=web${code ? `&owasp=${code}` : "&detection=matched"}`}>All {events.data.total} in All events</Link></p>}
        </Panel>
        <Panel title={cat ? "Rules in this category" : "How web rules decide"} id="rules">
          {(cat ? cat.rules : []).length === 0 && !cat && <p className="small muted">Choose a category to see its rules, their evidence and what they cannot tell.</p>}
          <div className="slips">
            {cat?.rules.map((id) => { const r = ruleInfo(id); const hits = cat.by_rule.filter((b) => b.rule === id).reduce((a, b) => a + b.matches, 0); return r && (
              <div className="slip kind-rule" key={id}>
                <div className="slip-top"><span className="slip-id">{id}</span><span className="badge">{hits} matches</span></div>
                <div className="slip-title">{r.name}</div>
                <div className="slip-det">{r.logic}<br /><b>Evidence:</b> {r.required_evidence} · <b>confidence</b> {r.confidence_model}<br /><b>False positives:</b> {r.false_positives}
                  {r.does_not_detect && <><br /><b>Cannot tell:</b> {r.does_not_detect}</>}<br />{r.alerting ? "Can open an alert" : "Signal only, never an alert alone"}
                  {r.attack.length > 0 && <> · ATT&amp;CK {r.attack.join(", ")}</>}</div>
              </div>
            ); })}
          </div>
        </Panel>
      </div>
    </div>
  );
}
