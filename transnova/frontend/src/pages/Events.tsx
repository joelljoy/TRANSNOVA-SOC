import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ArrowDown, ArrowUp, X } from "lucide-react";
import { useEvents, useFacets } from "../api/hooks";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorState, Loading, PageHeader, Pager, Panel, When } from "../components/ui";
import { SERVICE_LABEL, words } from "../lib/format";
import { useSeenSince } from "../lib/seen";

const PAGE = 50;
const FILTERS = ["q", "service", "event_type", "outcome", "detection", "rule", "source_ip", "session_id", "technique", "owasp", "since", "until"] as const;
const LABELS: Record<string, string> = {
  q: "Search", service: "Decoy", event_type: "Type", outcome: "Outcome", detection: "Detection", rule: "Rule",
  source_ip: "Source", session_id: "Session", technique: "Technique", owasp: "OWASP", since: "From", until: "To",
};

const toLocal = (iso: string | null) => (iso ? iso.slice(0, 16) : "");
const fromLocal = (v: string) => (v ? `${v}:00.000Z` : "");

export function Events() {
  const [params, setParams] = useSearchParams();
  const facets = useFacets();
  const since = useSeenSince("events");
  const offset = Number(params.get("offset") ?? 0);
  const order = params.get("order") === "asc" ? "asc" : "desc";
  const query: Record<string, string | number> = { limit: PAGE, offset, order };
  for (const f of FILTERS) { const v = params.get(f); if (v) query[f] = v; }
  const events = useEvents(query);
  const [q, setQ] = useState(params.get("q") ?? "");

  const set = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    next.delete("offset");
    setParams(next, { replace: true });
  };
  const active = FILTERS.filter((f) => params.get(f));
  const opts = (key: string) => facets.data?.[key] ?? [];

  return (
    <div className="page">
      <PageHeader title="All events" lede="Every interaction the decoys and the console recorded, newest first. Original evidence is never edited; classifications are added beside it." />
      <Panel>
        <form className="filters" role="search" onSubmit={(e) => { e.preventDefault(); set("q", q.trim()); }}>
          <label className="field grow">Search source, path, command, user or event ID
            <input className="input" value={q} onChange={(e) => setQ(e.target.value)} placeholder="for example /admin or 172.28.0.50" maxLength={100} />
          </label>
          <label className="field">Decoy
            <select className="select" value={params.get("service") ?? ""} onChange={(e) => set("service", e.target.value)}>
              <option value="">All</option>
              {opts("service").map((o) => <option key={o.value} value={o.value}>{SERVICE_LABEL[o.value] ?? o.value} ({o.count})</option>)}
            </select>
          </label>
          <label className="field">Type
            <select className="select" value={params.get("event_type") ?? ""} onChange={(e) => set("event_type", e.target.value)}>
              <option value="">All</option>
              {opts("event_type").map((o) => <option key={o.value} value={o.value}>{words(o.value)} ({o.count})</option>)}
            </select>
          </label>
          <label className="field">Outcome
            <select className="select" value={params.get("outcome") ?? ""} onChange={(e) => set("outcome", e.target.value)}>
              <option value="">All</option>
              {opts("outcome").map((o) => <option key={o.value} value={o.value}>{words(o.value)} ({o.count})</option>)}
            </select>
          </label>
          <label className="field">Detection
            <select className="select" value={params.get("detection") ?? ""} onChange={(e) => set("detection", e.target.value)}>
              <option value="">All</option>
              <option value="observed">Observed only</option>
              <option value="matched">Rule matched, no alert</option>
              <option value="alerted">In an alert</option>
            </select>
          </label>
          <label className="field">Rule
            <select className="select" value={params.get("rule") ?? ""} onChange={(e) => set("rule", e.target.value)}>
              <option value="">Any</option>
              {opts("rule").map((o) => <option key={o.value} value={o.value}>{o.value} ({o.count})</option>)}
            </select>
          </label>
          <label className="field">From (UTC)
            <input className="input" type="datetime-local" value={toLocal(params.get("since"))} onChange={(e) => set("since", fromLocal(e.target.value))} />
          </label>
          <label className="field">To (UTC)
            <input className="input" type="datetime-local" value={toLocal(params.get("until"))} onChange={(e) => set("until", fromLocal(e.target.value))} />
          </label>
          <button className="btn primary" type="submit">Search</button>
        </form>
        {active.length > 0 && (
          <div className="chips" style={{ marginTop: 12 }} aria-label="Active filters">
            {active.map((f) => (
              <span className="chip" key={f}>{LABELS[f]}: <span className="mono">{params.get(f)}</span>
                <button aria-label={`Remove ${LABELS[f]} filter`} onClick={() => { if (f === "q") setQ(""); set(f, ""); }}><X size={14} /></button>
              </span>
            ))}
            <button className="btn quiet small" onClick={() => { setQ(""); setParams(new URLSearchParams(), { replace: true }); }}>Clear all</button>
          </div>
        )}
      </Panel>
      <Panel flush title={events.data ? `${events.data.total.toLocaleString()} events` : "Events"} id="events"
        aside={events.data?.span && (
          <span className="span-guide" title="First and last timestamp on this page">
            <When iso={events.data.span.first} full /> – <When iso={events.data.span.last} full />
          </span>
        )}>
        <div style={{ padding: "0 20px 8px" }}>
          <button className="btn quiet small" onClick={() => set("order", order === "desc" ? "asc" : "")}>
            {order === "desc" ? <ArrowDown aria-hidden /> : <ArrowUp aria-hidden />} {order === "desc" ? "Newest first" : "Oldest first"}
          </button>
        </div>
        {events.isLoading ? <Loading rows={8} /> : events.isError ? <ErrorState error={events.error} retry={() => events.refetch()} /> :
          events.data!.items.length === 0 ? (
            active.length ? <Empty title="No events match these filters">Remove a filter to widen the search.</Empty>
              : <Empty title="No events received yet">Interact with any decoy, or sign in to the console, and the event appears here.</Empty>
          ) : (
            <>
              <EventTable events={events.data!.items} since={since} caption="All events" columns={["time", "id", "service", "source", "type", "what", "outcome", "attack", "detection"]} />
              <Pager total={events.data!.total} limit={PAGE} offset={offset} noun="events"
                onChange={(o) => { const n = new URLSearchParams(params); n.set("offset", String(o)); setParams(n); }} />
            </>
          )}
      </Panel>
    </div>
  );
}
