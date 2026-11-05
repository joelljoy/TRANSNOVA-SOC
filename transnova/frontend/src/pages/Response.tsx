import { useState } from "react";
import { Link } from "react-router-dom";
import { useBlock, useBlocklist, useUnblock } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { EngageList } from "../components/Engage";
import { Empty, ErrorState, Loading, PageHeader, Panel, SourceLink, When } from "../components/ui";
import { duration, plural } from "../lib/format";

export function Response() {
  const q = useBlocklist();
  const { canWrite } = useAuth();
  const blockIt = useBlock();
  const unblock = useUnblock();
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("");
  if (q.isLoading) return <div className="page"><PageHeader title="Response" /><Loading rows={6} /></div>;
  if (q.isError) return <div className="page"><PageHeader title="Response" /><Panel><ErrorState error={q.error} /></Panel></div>;
  const b = q.data!;
  const err = (blockIt.error ?? unblock.error) as Error | null;
  return (
    <div className="page">
      <PageHeader title="Response"
        lede={<>Attackers caught by the honeypot are refused by the real TransNova website. The main site pulls this list every few seconds. Automatic blocks come from {b.auto_rules.map((r, i) => <span key={r}>{i ? ", " : ""}<span className="mono">{r}</span></span>)}, rules no legitimate visitor can trigger, and last {duration(b.ttl_s)}.</>} />
      <div className="grid-2">
        <Panel title={`Blocked on the main site (${b.active.length})`} id="active" flush>
          {b.active.length === 0 ? <div style={{ padding: 20 }}><Empty title="Nobody is blocked">When someone uses the decoy login or takes adaptive bait, their address appears here.</Empty></div> : (
            <div className="table-wrap">
              <table className="data">
                <caption className="sr-only">Active blocks</caption>
                <thead><tr><th scope="col">Address</th><th scope="col">Why</th><th scope="col">Until</th>{canWrite && <th scope="col"><span className="sr-only">Action</span></th>}</tr></thead>
                <tbody>
                  {b.active.map((x) => (
                    <tr key={x.ip}>
                      <td className="nowrap"><SourceLink ip={x.ip} /></td>
                      <td>{x.actor === "auto" ? <>Automatic: <span className="mono">{x.rule}</span></> : <>{x.actor}: {x.reason}</>}
                        {x.alert_id && <> · <Link to={`/alerts/${x.alert_id}`}>alert</Link></>}</td>
                      <td className="nowrap"><When iso={x.expires_at} full /></td>
                      {canWrite && <td><button className="btn quiet" disabled={unblock.isPending}
                        onClick={() => unblock.mutate({ id: x.ip, body: { ip: x.ip, reason: "lifted from response page" } })}>Lift</button></td>}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        <div className="stack-lg">
          {canWrite && (
            <Panel title="Block an address by hand" id="manual">
              <form className="stack" onSubmit={(ev) => {
                ev.preventDefault();
                blockIt.mutate({ id: ip, body: { ip: ip.trim(), reason: reason.trim() || "manual block" } }, { onSuccess: () => { setIp(""); setReason(""); } });
              }}>
                <label className="field">IP address<input className="input mono" value={ip} required maxLength={64} onChange={(e) => setIp(e.target.value)} placeholder="192.168.43.77" /></label>
                <label className="field">Reason<input className="input" value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} /></label>
                <button className="btn danger" disabled={!ip.trim() || blockIt.isPending}>Block on main site</button>
              </form>
              {err && <p className="notice bad" role="alert" style={{ marginTop: 12 }}>{err.message}</p>}
            </Panel>
          )}
          <Panel title="Deception framing" id="engage">
            <p className="small">Blocking on the real service after the decoy exposed the attacker is a MITRE Engage <b>Affect</b> activity.</p>
            <EngageList items={[{ engage: b.engage }]} />
          </Panel>
        </div>
      </div>
      <Panel title={`History (${plural(b.history.length, "change")})`} id="history" flush>
        {b.history.length === 0 ? <div style={{ padding: 20 }}><Empty title="No block has been placed yet" /></div> : (
          <div className="table-wrap">
            <table className="data">
              <caption className="sr-only">Block history</caption>
              <thead><tr><th scope="col">Time (UTC)</th><th scope="col">Change</th><th scope="col">Address</th><th scope="col">By</th><th scope="col">Reason</th></tr></thead>
              <tbody>
                {b.history.map((h, i) => (
                  <tr key={i}><td className="nowrap"><When iso={h.ts} /></td><td>{h.action === "block" ? "Blocked" : "Lifted"}</td>
                    <td className="nowrap"><SourceLink ip={h.ip} /></td><td>{h.actor}</td><td>{h.reason ?? ""}</td></tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  );
}
