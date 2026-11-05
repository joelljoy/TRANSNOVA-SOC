import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useClassify, useEvent } from "../api/hooks";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { AttackMap, rowsFromDetections } from "../components/AttackMap";
import { ENGAGE_URL, EngageList } from "../components/Engage";
import { EventTable } from "../components/EventTable";
import {
  ClassBadge, DetectionBadge, Empty, ErrorState, Evidence, KV, Loading, PageHeader, Panel, ServiceTag, Severity,
  SourceLink, Status, When,
} from "../components/ui";
import { plural, CLASS_LABEL, describe, words } from "../lib/format";

export function EventDetail() {
  const { id } = useParams();
  const q = useEvent(id);
  const { canWrite } = useAuth();
  const classify = useClassify();
  const [cls, setCls] = useState("benign");
  const [reason, setReason] = useState("");

  if (q.isLoading) return <div className="page"><Loading rows={10} /></div>;
  if (q.isError) {
    const missing = q.error instanceof ApiError && q.error.status === 404;
    return <div className="page"><PageHeader title="Event" crumb={<Link to="/events">All events</Link>} />
      <Panel>{missing ? <Empty title="No such event">It may have been typed wrong. Events are never deleted.</Empty> : <ErrorState error={q.error} />}</Panel></div>;
  }
  const { event: e, annotations, alerts, session_events, source_recent, detections } = q.data!;
  return (
    <div className="page">
      <PageHeader title={describe(e)} crumb={<><Link to="/events">All events</Link> / <span className="mono">{e.event_id}</span></>}
        lede={<span className="row"><ServiceTag service={e.service} /> <DetectionBadge value={e.detection_status} /> <ClassBadge value={e.classification} /></span>} />
      <Panel title="MITRE ATT&CK mapping" id="attack-map"
        aside={<Link to="/mitre">Coverage matrix</Link>}>
        <AttackMap rows={rowsFromDetections(detections)}
          empty={detections.length ? "The rules that matched don't map to an ATT&CK technique (single-occurrence signals)." : "No rule matched this event, so nothing is mapped."} />
        {detections.some((d) => d.engage?.length) && (
          <div className="engage-block">
            <h3 className="sub-h">Which deception exposed it <a className="small" href={ENGAGE_URL} target="_blank" rel="noreferrer noopener">MITRE Engage</a></h3>
            <EngageList items={detections.map((d) => ({ rule: d.rule, engage: d.engage ?? [] }))} rules />
          </div>
        )}
      </Panel>
      <div className="grid-2">
        <div className="stack-lg">
          <Panel title="Observation" id="obs">
            <KV rows={[
              ["Event ID", <span className="mono">{e.event_id}</span>],
              ["Time", <When iso={e.timestamp} full />],
              ["Source", <span><SourceLink ip={e.source_ip} />{e.source_port ? <span className="muted num"> port {e.source_port}</span> : null}</span>],
              ["Decoy / sensor", <span>{e.destination_service} · <span className="mono">{e.sensor_id}</span></span>],
              ["Type / action", `${words(e.event_type)} · ${words(e.action)}`],
              ["Outcome", words(e.outcome)],
              ["User", e.username],
              ["Session", e.session_id && <Link className="mono" to={`/events?session_id=${encodeURIComponent(e.session_id)}`}>{e.session_id}</Link>],
              ["Request", e.request_path && <span className="code-line">{e.http_method} {e.request_path}{e.http_status ? ` → ${e.http_status}` : ""}</span>],
              ["Command / query", e.command && <span className="code-line">{e.command}</span>],
              ["Tables", e.table_names.length ? e.table_names.join(", ") : null],
              ["User agent", e.user_agent],
              ["Campaign", e.campaign_id],
              ["Tags", e.tags.length ? e.tags.join(", ") : null],
            ]} />
          </Panel>
          <Panel title="Raw evidence (redacted at the sensor)" id="raw">
            <Evidence value={e.raw_evidence_redacted} />
          </Panel>
          {session_events.length > 1 && (
            <Panel title={`This session (${session_events.length} events)`} id="sess" flush>
              <EventTable events={session_events} selected={e.event_id} caption="Events in the same session" columns={["time", "type", "what", "outcome", "detection"]} />
            </Panel>
          )}
          <Panel title="Recent events from the same source" id="near" flush aside={<Link to={`/sources/${encodeURIComponent(e.source_ip)}`}>Source profile</Link>}>
            {source_recent.length ? <EventTable events={source_recent} caption="Recent events from the same source" columns={["time", "service", "type", "what", "outcome", "detection"]} />
              : <Empty title="No other events from this source" />}
          </Panel>
        </div>
        <div className="stack-lg">
          <Panel title="Determination" id="det">
            <div className="slips">
              {detections.length === 0 && (
                <div className="slip kind-rule"><div className="slip-label">Rule evaluation</div>
                  <div className="slip-title">No detection rule matched</div>
                  <div className="slip-det">Recorded as an observation. That is not a judgement that it is benign.</div></div>
              )}
              {detections.map((d, i) => (
                <div className="slip kind-rule" key={i}>
                  <div className="slip-top"><span className="slip-id">{d.rule}</span>{d.severity && <Severity value={d.severity.toLowerCase()} />}</div>
                  <div className="slip-title">{d.name}</div>
                  <div className="slip-det">
                    {d.rationale}{d.field ? <> · field <span className="mono">{d.field}</span></> : null}<br />
                    confidence <b>{d.confidence ?? "—"}</b> · {d.alerting ? "can open an alert" : "signal only, never an alert on its own"}
                    {d.owasp_2025 && <><br />{d.owasp_2025} <span className="muted">(sensor label {d.owasp_2021})</span></>}
                    {d.attack.map((a) => <span key={a.technique}><br /><span className="mono">{a.technique}</span> {a.name ?? "unknown technique"} · {a.status ?? "candidate"}</span>)}
                  </div>
                </div>
              ))}
              {annotations.map((a, i) => (
                <div className="slip kind-analyst" key={i}>
                  <div className="slip-label">Analyst classification · {a.actor} · <When iso={a.ts} full /></div>
                  <div className="slip-title">{CLASS_LABEL[a.classification]}</div>
                  <div className="slip-det">{a.reason}{a.previous ? <> · replaced {CLASS_LABEL[a.previous] ?? a.previous}</> : null}</div>
                </div>
              ))}
            </div>
            {canWrite && (
              <form className="stack" style={{ marginTop: 16 }} onSubmit={(ev) => {
                ev.preventDefault();
                classify.mutate({ id: e.event_id, body: { classification: cls, reason } }, { onSuccess: () => setReason("") });
              }}>
                <label className="field">Add a classification
                  <select className="select" value={cls} onChange={(ev) => setCls(ev.target.value)}>
                    {Object.entries(CLASS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                  </select>
                </label>
                <label className="field">Reason (kept with your name and the time)
                  <textarea className="textarea" required value={reason} maxLength={2000} onChange={(ev) => setReason(ev.target.value)} />
                </label>
                {classify.isError && <p className="notice bad" role="alert">{(classify.error as Error).message}</p>}
                <button className="btn primary" disabled={!reason.trim() || classify.isPending}>{classify.isPending ? "Saving…" : "Add classification"}</button>
              </form>
            )}
          </Panel>
          <Panel title="Alerts that include this event" id="alerts">
            {alerts.length === 0 ? <p className="muted small">None. This event is not part of any alert.</p> : (
              <div className="slips">
                {alerts.map((a) => (
                  <Link className="slip" key={a.alert_id} to={`/alerts/${a.alert_id}`}>
                    <div className="slip-top"><span className="slip-id">{a.rule}</span><Severity value={a.severity} /></div>
                    <div className="slip-title">{a.title}</div>
                    <div className="slip-det"><Status value={a.status} /> · {plural(a.event_count, "event")}</div>
                  </Link>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}
