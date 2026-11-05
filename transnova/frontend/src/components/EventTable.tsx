import { useNavigate } from "react-router-dom";
import type { SocEvent } from "../api/types";
import { describe, words } from "../lib/format";
import { isNew } from "../lib/seen";
import { eventTechniques } from "./AttackMap";
import { ClassBadge, DetectionBadge, ServiceTag, SourceLink, When } from "./ui";

type Column = "time" | "service" | "source" | "type" | "what" | "outcome" | "detection" | "id" | "attack";
const ALL: Column[] = ["time", "service", "source", "type", "what", "outcome", "attack", "detection"];

export function EventTable({ events, columns = ALL, since = null, selected, caption, onOpen }: {
  events: SocEvent[]; columns?: Column[]; since?: string | null; selected?: string; caption: string;
  onOpen?: (id: string) => void;
}) {
  const navigate = useNavigate();
  const open = onOpen ?? ((id: string) => navigate(`/events/${id}`));
  const has = (c: Column) => columns.includes(c);
  return (
    <div className="table-wrap">
      <table className="data">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr>
            {has("time") && <th scope="col">Time (UTC)</th>}
            {has("id") && <th scope="col">Event</th>}
            {has("service") && <th scope="col">Decoy</th>}
            {has("source") && <th scope="col">Source</th>}
            {has("type") && <th scope="col">Type</th>}
            {has("what") && <th scope="col">What happened</th>}
            {has("outcome") && <th scope="col">Outcome</th>}
            {has("attack") && <th scope="col">ATT&amp;CK</th>}
            {has("detection") && <th scope="col">Detection</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.event_id} className="clickable" aria-selected={selected === e.event_id}
              onClick={(ev) => { if (!(ev.target as HTMLElement).closest("a,button")) open(e.event_id); }}>
              {has("time") && (
                <td className="nowrap">
                  {isNew(e.timestamp, since) && <span className="new-mark" title="New since your last visit" aria-label="new" />}
                  <When iso={e.timestamp} />
                </td>
              )}
              {has("id") && <td className="mono nowrap">{e.event_id.slice(0, 8)}</td>}
              {has("service") && <td className="nowrap"><ServiceTag service={e.service} /></td>}
              {has("source") && <td className="nowrap"><SourceLink ip={e.source_ip} /></td>}
              {has("type") && <td className="nowrap">{words(e.event_type)}</td>}
              {has("what") && (
                <td className="trunc">
                  <button className="btn quiet" style={{ all: "unset", cursor: "pointer" }} onClick={() => open(e.event_id)}
                    title={describe(e)}>
                    <span className={e.command || e.request_path ? "mono" : undefined}>{describe(e)}</span>
                  </button>
                </td>
              )}
              {has("outcome") && <td className="nowrap">{words(e.outcome)}</td>}
              {has("attack") && (
                <td className="nowrap">
                  {eventTechniques(e.raw_evidence_redacted.detections).map((t) => <span className="tchip" key={t}>{t}</span>)}
                </td>
              )}
              {has("detection") && (
                <td className="nowrap">
                  <span className="row" style={{ gap: 6 }}>
                    <DetectionBadge value={e.detection_status} />
                    <ClassBadge value={e.classification} />
                  </span>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
