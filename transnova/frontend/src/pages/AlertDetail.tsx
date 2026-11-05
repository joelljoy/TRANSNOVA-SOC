import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Sparkles } from "lucide-react";
import { useAlert, useAlertNote, useAlertStatus, useBlock, useExplain, useUnblock } from "../api/hooks";
import { ApiError } from "../api/client";
import type { AlertStatus, StoredExplanation } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AttackMap, rowsFromAttack } from "../components/AttackMap";
import { ENGAGE_URL, EngageList } from "../components/Engage";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorState, KV, Loading, PageHeader, Panel, Severity, SourceLink, Status, When } from "../components/ui";
import { plural, SERVICE_LABEL, STATUS_LABEL, words } from "../lib/format";

const ACTIONS: Record<AlertStatus, { action: string; label: string; needsNote?: boolean }[]> = {
  open: [{ action: "investigate", label: "Start investigating" }, { action: "confirm", label: "Confirm malicious", needsNote: true },
    { action: "false_positive", label: "Mark false positive", needsNote: true }, { action: "resolve", label: "Resolve" }],
  investigating: [{ action: "confirm", label: "Confirm malicious", needsNote: true },
    { action: "false_positive", label: "Mark false positive", needsNote: true }, { action: "resolve", label: "Resolve" }],
  confirmed_malicious: [{ action: "resolve", label: "Resolve" }, { action: "reopen", label: "Reopen" }],
  false_positive: [{ action: "reopen", label: "Reopen" }],
  resolved: [{ action: "reopen", label: "Reopen" }],
};

function List({ items }: { items: string[] }) {
  return items.length ? <ul className="list-rows small">{items.map((x, i) => <li key={i}>{x}</li>)}</ul> : <p className="small muted">None given.</p>;
}

function ExplanationSlip({ x }: { x: StoredExplanation }) {
  const e = x.explanation;
  return (
    <div className="slip kind-ai">
      <div className="slip-label">AI interpretation · {x.model} · requested by {x.actor} · <When iso={x.ts} full /></div>
      <p style={{ margin: "6px 0 10px" }}>{e.summary}</p>
      <div className="stack small">
        <div><b>Observed facts</b>
          <ul className="list-rows">{e.observed_facts.map((f, i) => <li key={i}>{f.fact} <span className="mono muted">{f.event_ids.map((id) => id.slice(0, 8)).join(", ")}</span></li>)}</ul></div>
        <div><b>What the rule concluded</b><p>{e.rule_conclusion}</p></div>
        <div><b>Interpretation (not verified)</b><p>{e.interpretation}</p></div>
        <div><b>Possible benign explanations</b><List items={e.benign_explanations} /></div>
        <div className="grid-halves" style={{ gap: 16 }}>
          <div><b>Supports the alert</b><List items={e.supporting_evidence} /></div>
          <div><b>Weakens the alert</b><List items={e.weakening_evidence} /></div>
        </div>
        <div><b>What the evidence cannot establish</b><List items={e.missing_context} /></div>
        <div><b>Suggested next steps</b><List items={e.next_steps} /></div>
        <p className="muted">{e.confidence_note}</p>
      </div>
    </div>
  );
}

export function AlertDetail() {
  const { id } = useParams();
  const q = useAlert(id);
  const { canWrite } = useAuth();
  const status = useAlertStatus();
  const note = useAlertNote();
  const explain = useExplain();
  const [text, setText] = useState("");

  if (q.isLoading) return <div className="page"><Loading rows={10} /></div>;
  if (q.isError) {
    const missing = q.error instanceof ApiError && q.error.status === 404;
    return <div className="page"><PageHeader title="Alert" crumb={<Link to="/alerts">Alerts</Link>} />
      <Panel>{missing ? <Empty title="No such alert" /> : <ErrorState error={q.error} />}</Panel></div>;
  }
  const d = q.data!;
  const a = d.alert;
  const latestAi = d.explanations[d.explanations.length - 1];
  const act = (action: string, needsNote?: boolean) => {
    if (needsNote && !text.trim()) return;
    status.mutate({ id: a.alert_id, body: { action, note: text.trim() || undefined } }, { onSuccess: () => setText("") });
  };

  return (
    <div className="page">
      <PageHeader title={a.title} crumb={<><Link to="/alerts">Alerts</Link> / <span className="mono">{a.rule}</span></>}
        lede={<span className="row"><Severity value={a.severity} /> <Status value={a.status} />
          <span className="muted small">confidence {a.confidence ?? "—"} · {plural(a.event_count, "event")} · {SERVICE_LABEL[a.service] ?? a.service}</span></span>} />
      {a.activity_after_status && <p className="notice">New events arrived after this alert was marked {STATUS_LABEL[a.status].toLowerCase()}. Consider reopening it.</p>}
      <Panel title="MITRE ATT&CK mapping" id="attack" aside={<Link to="/mitre">Coverage matrix</Link>}>
        <AttackMap rows={rowsFromAttack(a.rule, d.rule?.name ?? a.title, a.owasp_2025, d.attack)}
          empty="No technique is mapped. The rule does not claim one." />
        {!!d.engage?.length && (
          <div className="engage-block">
            <h3 className="sub-h">Which deception exposed it <a className="small" href={d.engage_matrix ?? ENGAGE_URL} target="_blank" rel="noreferrer noopener">MITRE Engage</a></h3>
            <EngageList items={[{ rule: a.rule, engage: d.engage }]} />
          </div>
        )}
      </Panel>
      <ResponsePanel ip={a.source_ip} alertId={a.alert_id} block={d.block ?? null} canWrite={canWrite} />
      <div className="grid-2">
        <div className="stack-lg">
          <Panel title="Why this alert exists" id="why">
            <div className="slips">
              <div className="slip kind-rule">
                <div className="slip-label">Rule conclusion · {a.rule}</div>
                <div className="slip-title">{d.rule?.name ?? a.title}</div>
                <div className="slip-det">
                  <b>Condition:</b> {d.rule?.logic ?? "Not catalogued; see the sensor's rationale."}<br />
                  <b>This time:</b> {d.rationale || "The sensor gave no rationale."}<br />
                  <b>Required evidence:</b> {d.rule?.required_evidence ?? "—"}<br />
                  <b>Confidence model:</b> {d.rule?.confidence_model ?? a.confidence ?? "—"}
                </div>
              </div>
              <div className="slip kind-rule">
                <div className="slip-label">Limits of this detection</div>
                <div className="slip-det" style={{ borderTop: 0, marginTop: 0, paddingTop: 0 }}>
                  <b>Known false positives:</b> {d.rule?.false_positives ?? "Not documented."}<br />
                  {d.rule?.does_not_detect && <><b>Cannot establish:</b> {d.rule.does_not_detect}<br /></>}
                  <b>Attribution:</b> {d.source?.attribution ?? "Unknown source."}
                </div>
              </div>
            </div>
          </Panel>
          <Panel title={`Evidence (${d.events.length}${d.events_truncated ? ` of ${a.event_count}` : ""} events)`} id="ev" flush
            aside={d.evidence_window && <span className="span-guide"><When iso={d.evidence_window.first} full /> – <When iso={d.evidence_window.last} full /></span>}>
            {d.events.length ? <EventTable events={d.events} caption="Events supporting this alert" columns={["time", "service", "source", "what", "outcome", "attack", "detection"]} />
              : <Empty title="No linked events found" />}
            {d.events_truncated && <p className="small muted" style={{ padding: "8px 20px" }}>Only the first linked events are listed. Use All events with this source to see every one.</p>}
          </Panel>
          <Panel title="Matched rule conditions" id="matched">
            {d.matched_detections.length === 0 ? <p className="small muted">This alert is collector-side (for example a threshold or correlation), so no single event carries the match.</p> : (
              <ul className="list-rows small">
                {d.matched_detections.slice(0, 30).map((m, i) => (
                  <li key={i}><When iso={m.timestamp} /> · <Link className="mono" to={`/events/${m.event_id}`}>{m.event_id?.slice(0, 8)}</Link> · {m.rationale ?? "no rationale"}
                    {m.field && <> · field <span className="mono">{m.field}</span></>} · confidence {m.confidence ?? "—"}</li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Explainable AI" id="xai" aside="Interpretation only; it never changes the alert">
            {latestAi ? <ExplanationSlip x={latestAi} /> : <p className="small muted">No AI explanation has been requested for this alert.</p>}
            {explain.isError && <p className="notice" role="alert" style={{ marginTop: 12 }}>{(explain.error as Error).message} The evidence and rule above are unaffected.</p>}
            {canWrite && (
              <button className="btn" style={{ marginTop: 12 }} disabled={explain.isPending} onClick={() => explain.mutate({ id: a.alert_id, body: {} })}>
                <Sparkles aria-hidden /> {explain.isPending ? "Asking the model…" : latestAi ? "Explain again from current evidence" : "Explain this alert"}
              </button>
            )}
          </Panel>
        </div>
        <div className="stack-lg">
          <Panel title="Summary" id="sum">
            <KV rows={[
              ["Alert ID", <span className="mono small">{a.alert_id}</span>],
              ["Source", <SourceLink ip={a.source_ip} />],
              ["First observed", <When iso={a.first_seen} full />],
              ["Last observed", <When iso={a.last_seen} full />],
              ["Stage", a.kill_chain_stage ? words(a.kill_chain_stage) : null],
              ["OWASP", a.owasp_2025],
              ["Recommended", d.recommended_action],
            ]} />
          </Panel>
          <Panel title="Disposition" id="disp">
            {canWrite ? (
              <div className="stack">
                <label className="field">Note or reason (required to confirm or mark a false positive)
                  <textarea className="textarea" value={text} maxLength={4000} onChange={(e) => setText(e.target.value)} />
                </label>
                <div className="row">
                  {ACTIONS[a.status].map((x) => (
                    <button key={x.action} className={`btn${x.action === "confirm" ? " danger" : ""}`}
                      disabled={status.isPending || (x.needsNote && !text.trim())} onClick={() => act(x.action, x.needsNote)}>{x.label}</button>
                  ))}
                  <button className="btn quiet" disabled={!text.trim() || note.isPending}
                    onClick={() => note.mutate({ id: a.alert_id, body: { note: text.trim() } }, { onSuccess: () => setText("") })}>Add note only</button>
                </div>
                {(status.isError || note.isError) && <p className="notice bad" role="alert">{((status.error ?? note.error) as Error).message}</p>}
              </div>
            ) : <p className="small muted">Your role can view alerts but not change them.</p>}
          </Panel>
          <Panel title="Investigation history" id="hist">
            {d.history.length === 0 ? <p className="small muted">No analyst action yet. The alert has been open since <When iso={a.first_seen} full />.</p> : (
              <div className="slips">
                {[...d.history].reverse().map((h, i) => (
                  <div className="slip kind-analyst" key={i}>
                    <div className="slip-label">{h.actor} · <When iso={h.ts} full /></div>
                    <div className="slip-title">{h.action === "note" ? "Note" : `${STATUS_LABEL[h.from_status ?? ""] ?? h.from_status} → ${STATUS_LABEL[h.to_status ?? ""] ?? h.to_status}`}</div>
                    {h.note && <div className="slip-det">{h.note}</div>}
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ResponsePanel({ ip, alertId, block, canWrite }: { ip: string; alertId: string; block: import("../api/types").Block | null; canWrite: boolean }) {
  const blockIt = useBlock();
  const unblock = useUnblock();
  const [reason, setReason] = useState("");
  const busy = blockIt.isPending || unblock.isPending;
  const err = (blockIt.error ?? unblock.error) as Error | null;
  return (
    <Panel title="Response on the real site" id="response" aside={<Link to="/response">All blocks</Link>}>
      {block ? (
        <p className="response-state is-blocked">
          <b className="mono">{ip}</b> is blocked on the TransNova main site until <When iso={block.expires_at} full />.
          {" "}{block.actor === "auto" ? <>Blocked automatically because <span className="mono">{block.rule}</span> fired.</> : <>Blocked by {block.actor}: {block.reason}</>}
        </p>
      ) : (
        <p className="response-state">
          <b className="mono">{ip}</b> can still open the main site. The honeypot keeps recording either way.
        </p>
      )}
      {canWrite && (
        <form className="row" style={{ marginTop: 12 }} onSubmit={(ev) => {
          ev.preventDefault();
          const body = { ip, reason: reason.trim() || (block ? "lifted by analyst" : "blocked from alert"), alert_id: alertId };
          if (block) unblock.mutate({ id: ip, body: { ip, reason: body.reason } }, { onSuccess: () => setReason("") });
          else blockIt.mutate({ id: ip, body }, { onSuccess: () => setReason("") });
        }}>
          <input className="input" placeholder={block ? "Reason for lifting (optional)" : "Reason (optional)"} value={reason}
            maxLength={500} onChange={(e) => setReason(e.target.value)} aria-label="Reason" />
          <button className={`btn${block ? "" : " danger"}`} disabled={busy}>{busy ? "Saving…" : block ? "Lift block" : "Block on main site"}</button>
        </form>
      )}
      {err && <p className="notice bad" role="alert">{err.message}</p>}
    </Panel>
  );
}
