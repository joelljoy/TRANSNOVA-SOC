import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { useEvents, useSource, useSources } from "../api/hooks";
import { ApiError } from "../api/client";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorState, KV, Loading, PageHeader, Pager, Panel, ServiceTag, Severity, Status, When } from "../components/ui";
import { plural, SERVICE_LABEL, duration, words } from "../lib/format";

const KIND: Record<string, string> = {
  private: "Private address", public: "Public address", loopback: "Loopback", unresolved: "Session with no address", label: "Label",
};

export function Sources() {
  const [params, setParams] = useSearchParams();
  const navigate = useNavigate();
  const [q, setQ] = useState(params.get("q") ?? "");
  const offset = Number(params.get("offset") ?? 0);
  const sort = (params.get("sort") as "recent" | "events" | "alerts") ?? "recent";
  const list = useSources({ limit: 50, offset, sort, q: params.get("q") ?? undefined });
  const set = (k: string, v: string) => { const n = new URLSearchParams(params); if (v) n.set(k, v); else n.delete(k); n.delete("offset"); setParams(n, { replace: true }); };
  return (
    <div className="page">
      <PageHeader title="Sources" lede="Every network source the decoys observed. A source is an address, not a person: addresses are shared, reassigned and translated, so profiles never claim an identity." />
      <Panel>
        <form className="filters" onSubmit={(e) => { e.preventDefault(); set("q", q.trim()); }}>
          <label className="field grow">Find a source<input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="Part of an IP address" /></label>
          <label className="field">Order
            <select className="select" value={sort} onChange={(e) => set("sort", e.target.value)}>
              <option value="recent">Most recent activity</option><option value="events">Most events</option><option value="alerts">Most alerts</option>
            </select>
          </label>
          <button className="btn primary">Find</button>
        </form>
      </Panel>
      <Panel flush title={list.data ? `${list.data.total} sources` : "Sources"} id="src">
        {list.isLoading ? <Loading rows={6} /> : list.isError ? <ErrorState error={list.error} /> : list.data!.items.length === 0 ? (
          <Empty title={params.get("q") ? "No source matches" : "No sources observed yet"}>Console sign-ins are kept out of this list; they appear in All events.</Empty>
        ) : (
          <>
            <div className="table-wrap"><table className="data">
              <caption className="sr-only">Observed sources</caption>
              <thead><tr><th scope="col">Source</th><th scope="col">Kind</th><th scope="col">Decoys</th><th scope="col">Events</th><th scope="col">Sessions</th><th scope="col">Alerts</th><th scope="col">First seen</th><th scope="col">Last seen</th></tr></thead>
              <tbody>{list.data!.items.map((s) => (
                <tr key={s.source_ip} className="clickable" onClick={(e) => { if (!(e.target as HTMLElement).closest("a")) navigate(`/sources/${encodeURIComponent(s.source_ip)}`); }}>
                  <td><Link className="mono" to={`/sources/${encodeURIComponent(s.source_ip)}`}>{s.source_ip}</Link></td>
                  <td className="small">{KIND[s.kind] ?? s.kind}</td>
                  <td><span className="row" style={{ gap: 10 }}>{s.services.map((x) => <ServiceTag key={x} service={x} />)}</span></td>
                  <td className="num">{s.event_count}</td><td className="num">{s.sessions}</td><td className="num">{s.alert_count}</td>
                  <td className="nowrap"><When iso={s.first_seen} full /></td><td className="nowrap"><When iso={s.last_seen} full /></td>
                </tr>
              ))}</tbody>
            </table></div>
            <Pager total={list.data!.total} limit={50} offset={offset} noun="sources" onChange={(o) => { const n = new URLSearchParams(params); n.set("offset", String(o)); setParams(n); }} />
          </>
        )}
      </Panel>
    </div>
  );
}

export function SourceProfile() {
  const { ip } = useParams();
  const p = useSource(ip);
  const [offset, setOffset] = useState(0);
  const timeline = useEvents({ source_ip: ip ?? "", limit: 25, offset });
  if (p.isLoading) return <div className="page"><Loading rows={10} /></div>;
  if (p.isError) {
    const missing = p.error instanceof ApiError && p.error.status === 404;
    return <div className="page"><PageHeader title={ip ?? "Source"} crumb={<Link to="/sources">Sources</Link>} />
      <Panel>{missing ? <Empty title="No source events are available">Nothing has been recorded from this address.</Empty> : <ErrorState error={p.error} />}</Panel></div>;
  }
  const s = p.data!;
  const longest = Math.max(1, ...s.sessions.map((x) => x.duration_s));
  const auth = s.breakdown.filter((b) => b.event_type === "authentication");
  const authOk = auth.filter((b) => b.outcome === "succeeded").reduce((a, b) => a + b.count, 0);
  const authFail = auth.filter((b) => b.outcome === "failed").reduce((a, b) => a + b.count, 0);
  // Session links are already the Sessions table; this panel keeps the links that reach further.
  const links = s.correlations.filter((c) => c.rule !== "C-SESS-01");
  const sessionLinks = s.correlations.length - links.length;
  return (
    <div className="page">
      <PageHeader title={s.source_ip} crumb={<Link to="/sources">Sources</Link>}
        lede={<>{KIND[s.kind] ?? s.kind} · {s.event_count} events across {s.services.map((x) => SERVICE_LABEL[x] ?? x).join(", ")} · {s.alert_count} alerts</>} />
      <p className="notice" style={{ background: "var(--panel-sunk)", borderColor: "var(--line)", color: "var(--ink-2)" }}>{s.attribution}</p>
      <div className="grid-2">
        <div className="stack-lg">
          <Panel title="Timeline" id="tl" flush aside={<Link to={`/events?source_ip=${encodeURIComponent(s.source_ip)}`}>Open in All events</Link>}>
            {timeline.isLoading ? <Loading /> : timeline.isError ? <ErrorState error={timeline.error} /> : (
              <>
                <EventTable events={timeline.data!.items} caption="Source timeline" columns={["time", "service", "type", "what", "outcome", "attack", "detection"]} />
                <Pager total={timeline.data!.total} limit={25} offset={offset} onChange={setOffset} noun="events" />
              </>
            )}
          </Panel>
          <Panel title="Sessions" id="sessions" aside="Bar length is the session's real duration">
            {s.sessions.length === 0 ? <p className="small muted">The decoys assigned no session identifiers to this source's events.</p> : (
              <div className="table-wrap"><table className="data">
                <caption className="sr-only">Sessions</caption>
                <thead><tr><th scope="col">Session</th><th scope="col">Decoy</th><th scope="col">Events</th><th scope="col">Started</th><th scope="col" style={{ width: "30%" }}>Duration</th></tr></thead>
                <tbody>{s.sessions.map((x) => (
                  <tr key={`${x.service}:${x.session_id}`}>
                    <td><Link className="mono small" to={`/events?session_id=${encodeURIComponent(x.session_id)}`}>{x.session_id.slice(0, 18)}</Link>
                      {x.usernames.length > 0 && <div className="small muted">as {x.usernames.join(", ")}</div>}</td>
                    <td><ServiceTag service={x.service} /></td><td className="num">{x.event_count}</td><td className="nowrap"><When iso={x.first_seen} full /></td>
                    <td><div className="duration" title={duration(x.duration_s)}><span style={{ width: `${(x.duration_s / longest) * 100}%` }} /></div>
                      <div className="small muted num">{duration(x.duration_s)}</div></td>
                  </tr>
                ))}</tbody>
              </table></div>
            )}
          </Panel>
          <div className="grid-halves">
            <Panel title="Commands seen" id="cmd">
              {s.commands.length === 0 ? <p className="small muted">No shell commands observed.</p> :
                <ul className="list-rows">{s.commands.map((c) => <li key={c.event_id}><Link to={`/events/${c.event_id}`} className="code-line" style={{ color: "inherit", textDecoration: "none" }}>{c.command}</Link> <span className="small muted"><When iso={c.timestamp} /></span></li>)}</ul>}
            </Panel>
            <Panel title="Database statements" id="sql">
              {s.sql_queries.length === 0 ? <p className="small muted">No SQL observed.</p> :
                <ul className="list-rows">{s.sql_queries.map((c) => <li key={c.event_id}><Link to={`/events/${c.event_id}`} className="code-line" style={{ color: "inherit", textDecoration: "none" }}>{c.command ?? "(no text)"}</Link> <span className="small muted">{words(c.outcome)}</span></li>)}</ul>}
            </Panel>
          </div>
          <Panel title="Web requests" id="http">
            {s.http_requests.length === 0 ? <p className="small muted">No web requests observed.</p> : (
              <div className="table-wrap"><table className="data"><caption className="sr-only">Web requests</caption>
                <thead><tr><th scope="col">Request</th><th scope="col">Times</th><th scope="col">Last</th></tr></thead>
                <tbody>{s.http_requests.map((r, i) => <tr key={i}><td className="mono trunc">{r.method} {r.path}</td><td className="num">{r.count}</td><td><When iso={r.last_seen} /></td></tr>)}</tbody>
              </table></div>
            )}
          </Panel>
        </div>
        <div className="stack-lg">
          <Panel title="Identity" id="id">
            <KV rows={[
              ["Address", <span className="mono">{s.source_ip}</span>], ["Kind", KIND[s.kind] ?? s.kind],
              ["First observed", <When iso={s.first_seen} full />], ["Last observed", <When iso={s.last_seen} full />],
              ["Events", s.event_count], ["Sessions", s.sessions.length],
              ["Logins", auth.length ? `${authOk} succeeded, ${authFail} failed` : "none observed"],
            ]} />
            {s.authentication.length > 0 && (
              <ul className="list-rows small" style={{ marginTop: 12 }}>
                {s.authentication.map((u, i) => <li key={i}><span className="mono">{u.username}</span> on {SERVICE_LABEL[u.service] ?? u.service}: {u.count} {words(u.outcome)}</li>)}
              </ul>
            )}
          </Panel>
          <Panel title="Related activity" id="corr">
            {sessionLinks > 0 && <p className="small muted" style={{ marginBottom: 12 }}>C-SESS-01 ties {sessionLinks} multi-event session{sessionLinks === 1 ? "" : "s"} together by the decoy's own session ID (confidence high); see Sessions.</p>}
            {links.length === 0 ? <p className="small muted">No correlation rule links this source to other decoys, sources or campaigns.</p> : (
              <div className="slips">{links.map((c) => (
                <div className="slip kind-rule" key={c.correlation_id}>
                  <div className="slip-top"><span className="slip-id">{c.rule}</span><span className="badge">confidence {c.confidence}</span></div>
                  <div className="slip-title">{c.title}</div>
                  <div className="slip-det">{c.reason}
                    {c.window && <><br /><When iso={c.window.first} full /> – <When iso={c.window.last} full /></>}
                    {c.related_sources && c.related_sources.length > 1 && <><br />Also labelled: {c.related_sources.filter((x) => x !== s.source_ip).map((x) => <Link key={x} className="mono" to={`/sources/${encodeURIComponent(x)}`} style={{ marginRight: 8 }}>{x}</Link>)}</>}
                    {c.related_event_ids.length > 0 && <><br />{c.related_event_ids.slice(0, 6).map((id) => <Link key={id} className="mono" to={`/events/${id}`} style={{ marginRight: 8 }}>{id.slice(0, 8)}</Link>)}</>}
                  </div>
                </div>
              ))}</div>
            )}
          </Panel>
          <Panel title="Techniques observed" id="tech">
            {s.techniques.length === 0 ? <p className="small muted">No ATT&amp;CK technique is supported by this source's events.</p> : (
              <ul className="list-rows small">{s.techniques.map((t) => (
                <li key={t.technique}><Link className="mono" to={`/events?source_ip=${encodeURIComponent(s.source_ip)}&technique=${t.technique}`}>{t.technique}</Link> {t.name}
                  <div className="muted">{t.basis === "evidence" ? "supported by event evidence" : "inferred by a rule (candidate)"} · {plural(t.event_ids.length, "event")}{t.rules.length ? ` · ${t.rules.join(", ")}` : ""}</div></li>
              ))}</ul>
            )}
            <p className="small muted" style={{ marginTop: 12 }}>Tool attribution is not inferred: behaviour that resembles a tool is not evidence of it.</p>
          </Panel>
          <Panel title="Alerts" id="al">
            {s.alerts.length === 0 ? <p className="small muted">No alert involves this source.</p> : (
              <div className="slips">{s.alerts.map((a) => (
                <Link className="slip" key={a.alert_id} to={`/alerts/${a.alert_id}`}>
                  <div className="slip-top"><span className="slip-id">{a.rule}</span><Severity value={a.severity} /></div>
                  <div className="slip-title">{a.title}</div>
                  <div className="slip-det"><Status value={a.status} /> · {plural(a.event_count, "event")} · last <When iso={a.last_seen} /></div>
                </Link>
              ))}</div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
