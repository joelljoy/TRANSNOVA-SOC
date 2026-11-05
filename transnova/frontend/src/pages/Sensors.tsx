import { Link } from "react-router-dom";
import { useAdaptations, useSensors, useSummary } from "../api/hooks";
import { Empty, ErrorState, Health, KV, Loading, PageHeader, Panel, ServiceTag, SourceLink, When } from "../components/ui";
import { ago, count, dateTime, words } from "../lib/format";

const EXPECTED = [
  { sensor: "web-01", service: "web", note: "Web decoy telemetry. It sends events but no heartbeat, so its health is judged from its last event." },
  { sensor: "db-01", service: "database", note: "Database decoy sensor. It sends a heartbeat every few seconds." },
  { sensor: "ssh-01", service: "ssh", note: "Cowrie SSH sensor. It delivers only once the collector's SSH token and read token are configured." },
];

export function Sensors() {
  const sensors = useSensors();
  const summary = useSummary();
  const adaptations = useAdaptations();
  const seen = new Set((sensors.data ?? []).map((s) => s.sensor_id));
  return (
    <div className="page">
      <PageHeader title="Sensors" lede="Health comes from each sensor's own heartbeat and its last delivered event. A sensor is never shown healthy because it is configured." />
      <Panel flush title="Registered sensors" id="sensors">
        {sensors.isLoading ? <Loading /> : sensors.isError ? <ErrorState error={sensors.error} /> : sensors.data!.length === 0 ? (
          <Empty title="No sensor has checked in">Start the stack; each sensor appears after its first heartbeat or event.</Empty>
        ) : (
          <div className="table-wrap"><table className="data">
            <caption className="sr-only">Sensors</caption>
            <thead><tr><th scope="col">Sensor</th><th scope="col">Health</th><th scope="col">Last heartbeat</th><th scope="col">Last event</th>
              <th scope="col">Events (5 min / 1 h / all)</th><th scope="col">Reported details</th></tr></thead>
            <tbody>{sensors.data!.map((s) => (
              <tr key={s.sensor_id}>
                <td><span className="mono">{s.sensor_id}</span><div>{s.service && <ServiceTag service={s.service} />}</div></td>
                <td><Health value={s.health} /><div className="small muted" style={{ maxWidth: 260 }}>{s.health_reason}</div></td>
                <td className="nowrap">{s.last_heartbeat_at ? <><When iso={s.last_heartbeat_at} /><div className="small muted">{ago(s.last_heartbeat_at)}</div></> : <span className="muted">none sent</span>}</td>
                <td className="nowrap">{s.last_event_at ? <><When iso={s.last_event_at} full /><div className="small muted">{ago(s.last_event_at)}</div></> : <span className="muted">none yet</span>}</td>
                <td className="num">{count(s.events_5m)} / {count(s.events_1h)} / {count(s.events_total)}</td>
                <td className="small">{Object.keys(s.details).length === 0 ? <span className="muted">—</span> :
                  Object.entries(s.details).slice(0, 6).map(([k, v]) => <div key={k}>{words(k)}: <span className="mono">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span></div>)}</td>
              </tr>
            ))}</tbody>
          </table></div>
        )}
      </Panel>
      {sensors.data && EXPECTED.some((e) => !seen.has(e.sensor)) && (
        <Panel title="Not heard from" id="missing">
          <ul className="list-rows small">
            {EXPECTED.filter((e) => !seen.has(e.sensor)).map((e) => <li key={e.sensor}><span className="mono">{e.sensor}</span> has sent nothing to this collector. {e.note}</li>)}
          </ul>
        </Panel>
      )}
      <div className="grid-halves">
        <Panel title="Ingestion refusals" id="ingest" aside={summary.data && `since collector start ${dateTime(summary.data.ingestion.since)}`}>
          {!summary.data ? <Loading rows={2} /> : summary.data.ingestion.total === 0 ? <p className="small muted">The collector has refused no request since it started.</p> : (
            <ul className="list-rows small">{summary.data.ingestion.reasons.map((r) => <li key={r.reason}><b>{r.count}</b> × {r.reason} <span className="muted">· last {r.last_at}</span></li>)}</ul>
          )}
          {summary.data && summary.data.ingestion.other.length > 0 && (
            <details style={{ marginTop: 12 }}>
              <summary className="small">Other refused requests (reads and analyst actions): {summary.data.ingestion.other.reduce((a, r) => a + r.count, 0)}</summary>
              <ul className="list-rows small">{summary.data.ingestion.other.map((r) => <li key={r.kind + r.reason}><b>{r.count}</b> × {r.reason} <span className="muted">· {r.kind} · last {r.last_at}</span></li>)}</ul>
            </details>
          )}
        </Panel>
        <Panel title="Adaptive deception (database decoy)" id="adapt">
          {adaptations.isLoading ? <Loading rows={2} /> : adaptations.isError ? <ErrorState error={adaptations.error} /> : adaptations.data!.length === 0 ? (
            <p className="small muted">No decoy table has been revealed. Tables stay hidden until behaviour triggers a rule.</p>
          ) : (
            <ul className="list-rows small">{adaptations.data!.map((r) => (
              <li key={r.adaptation_id}><b>{r.rule_id}</b> revealed <span className="mono">{r.asset_revealed}</span> ({r.status}) after <Link to={`/events/${r.trigger_event_id}`}>a trigger event</Link> from <SourceLink ip={r.source_ip} />
                <div className="muted">{r.trigger_reason} · <When iso={r.timestamp} full /> · {r.followup_event_ids.length ? `${r.followup_event_ids.length} follow-up reads` : "not read since"}</div></li>
            ))}</ul>
          )}
        </Panel>
      </div>
      {sensors.data?.filter((s) => s.sessions && s.sessions.length).map((s) => (
        <Panel key={s.sensor_id} title={`Live sessions reported by ${s.sensor_id}`} id={`sess-${s.sensor_id}`}>
          <KV rows={(s.sessions ?? []).slice(-8).reverse().map((x) => [
            <span className="mono small">{String(x.session_id ?? "").slice(0, 16)}</span>,
            <span className="small">{String(x.username ?? "?")} from <span className="mono">{String(x.source_ip ?? "?")}</span> · {String(x.query_count ?? 0)} queries · risk {String(x.risk_score ?? "—")}</span>,
          ])} />
        </Panel>
      ))}
    </div>
  );
}
