import { Link } from "react-router-dom";
import { useAlerts, useEvents, useSummary } from "../api/hooks";
import type { Sensor, Summary } from "../api/types";
import { ActivityChart } from "../components/ActivityChart";
import { EventTable } from "../components/EventTable";
import { Empty, ErrorState, Loading, PageHeader, Panel, Severity, SourceLink, Status, When } from "../components/ui";
import { plural, ago, count, dateTime } from "../lib/format";
import { useSeenSince } from "../lib/seen";

function sensorSentence(sensors: Sensor[]): { tone: string; text: string } {
  const decoys = sensors.filter((s) => s.health !== "internal");
  if (decoys.length === 0) return { tone: "idle", text: "No sensor has sent an event or heartbeat yet." };
  const bad = decoys.filter((s) => s.health === "stale" || s.health === "degraded");
  const unknown = decoys.filter((s) => s.health === "unknown");
  if (bad.length) return { tone: "warn", text: `${bad.length} of ${decoys.length} sensors need attention: ${bad.map((s) => `${s.sensor_id} (${s.health})`).join(", ")}.` };
  if (unknown.length === decoys.length) {
    return { tone: "ok", text: `No sensor sends a heartbeat yet; ${unknown.map((s) => s.sensor_id).join(", ")} ${unknown.length === 1 ? "has" : "have"} delivered events.` };
  }
  if (unknown.length) {
    const healthy = decoys.length - unknown.length;
    return { tone: "ok", text: `${healthy} sensor${healthy === 1 ? " reports" : "s report"} healthy; ${unknown.map((s) => s.sensor_id).join(", ")} ${unknown.length === 1 ? "sends" : "send"} events but no heartbeat.` };
  }
  return { tone: "ok", text: `All ${decoys.length} sensors report healthy.` };
}

function collectorSentence(s: Summary): { tone: string; text: string } {
  if (!s.last_event_at) return { tone: "idle", text: "The collector is reachable and has stored no events yet." };
  const ageMin = (Date.now() - new Date(s.last_event_at).getTime()) / 60000;
  return { tone: ageMin > 60 ? "idle" : "ok", text: `The collector has stored ${count(s.events_total)} events; the newest arrived ${ago(s.last_event_at)}.` };
}

export function Overview() {
  const summary = useSummary();
  const since = useSeenSince("overview");
  const events = useEvents({ limit: 8 });
  const alerts = useAlerts({ status: "open", limit: 5, sort: "severity" });
  const investigating = useAlerts({ status: "investigating", limit: 5, sort: "severity" });

  if (summary.isError) return <div className="page"><PageHeader title="Overview" /><Panel><ErrorState error={summary.error} retry={() => summary.refetch()} /></Panel></div>;
  const s = summary.data;
  const collector = s && collectorSentence(s);
  const sensors = s && sensorSentence(s.sensors);
  const attention = s ? Object.values(s.alerts_needing_attention).reduce((a, b) => a + (b ?? 0), 0) : 0;
  const queue = [...(alerts.data?.items ?? []), ...(investigating.data?.items ?? [])].slice(0, 5);

  return (
    <div className="page">
      <PageHeader title="Overview" lede="What the SOC has observed, and what is worth a look next." />
      <section className="panel state-strip" aria-label="SOC state">
        {!s ? <Loading rows={1} /> : (
          <>
            <p><span className={`dot ${collector!.tone}`} aria-hidden />{collector!.text}</p>
            <p><span className={`dot ${sensors!.tone}`} aria-hidden />{sensors!.text}</p>
            <p>
              <span className={`dot ${attention ? (s.alerts_needing_attention.critical || s.alerts_needing_attention.high ? "bad" : "warn") : "ok"}`} aria-hidden />
              {attention ? `${attention} alert${attention === 1 ? "" : "s"} open or under investigation.` : "No alert is waiting for review."}
            </p>
            {s.ingestion.total > 0 && (
              <p><span className="dot warn" aria-hidden />{s.ingestion.total} ingest request{s.ingestion.total === 1 ? " was" : "s were"} refused since {dateTime(s.ingestion.since)}. <Link to="/sensors">See why</Link></p>
            )}
          </>
        )}
      </section>
      {s?.read_capped_at && (
        <p className="notice">Some lists may be incomplete: stored events were too large to read in one pass (last at {s.read_capped_at}). Nothing was deleted.</p>
      )}
      <div className="grid-2">
        <div className="stack-lg">
          <Panel title="Newest events" id="newest" flush
            aside={events.data?.span ? <span className="span-guide"><When iso={events.data.span.first} /> – <When iso={events.data.span.last} /> · <Link to="/events">All events</Link></span> : <Link to="/events">All events</Link>}>
            {events.isLoading ? <Loading /> : events.isError ? <ErrorState error={events.error} /> :
              events.data!.items.length === 0 ? (
                <Empty title="No events received yet">Interact with a decoy (open the web decoy, connect to the database decoy, or SSH to the SSH decoy) and each interaction appears here.</Empty>
              ) : <EventTable events={events.data!.items} since={since} columns={["time", "service", "source", "what", "outcome", "attack", "detection"]} caption="Newest events" />}
          </Panel>
          <Panel title="Events in the last 24 hours" id="activity">
            {!s ? <Loading rows={3} /> : s.activity_24h.length === 0 ? <Empty title="No events in the last 24 hours" /> : <ActivityChart rows={s.activity_24h} />}
          </Panel>
        </div>
        <Panel title="Waiting for review" id="queue" aside={<Link to="/alerts">All alerts</Link>}>
          {alerts.isLoading ? <Loading rows={3} /> : alerts.isError ? <ErrorState error={alerts.error} /> : queue.length === 0 ? (
            <Empty title="No open alerts">Events are still recorded and rule matches are visible in All events. An alert opens only when a rule's documented threshold is met.</Empty>
          ) : (
            <div className="slips">
              {queue.map((a) => (
                <Link key={a.alert_id} className="slip" to={`/alerts/${a.alert_id}`}>
                  <div className="slip-top"><span className="slip-id">{a.rule} · <span className="mono">{a.source_ip}</span></span><Severity value={a.severity} /></div>
                  <div className="slip-title">{a.title}</div>
                  <div className="slip-det">det. <b>rule match</b> · confidence {a.confidence ?? "—"} · {plural(a.event_count, "event")} · last <When iso={a.last_seen} /> · <Status value={a.status} /></div>
                </Link>
              ))}
            </div>
          )}
          {s && s.sources_observed > 0 && (
            <p className="small muted" style={{ marginTop: 16 }}>
              {count(s.sources_observed)} network sources observed. {queue[0] && <>Start with <SourceLink ip={queue[0].source_ip} />.</>}
            </p>
          )}
        </Panel>
      </div>
    </div>
  );
}
