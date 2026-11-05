import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { AlertTriangle, ChevronLeft, ChevronRight, Inbox, RefreshCw } from "lucide-react";
import { ApiError } from "../api/client";
import {
  CLASS_LABEL, DETECTION_LABEL, SERVICE_LABEL, STATUS_LABEL, dateTime, time as hhmmss, words,
} from "../lib/format";

export function PageHeader({ title, lede, actions, crumb }: { title: string; lede?: ReactNode; actions?: ReactNode; crumb?: ReactNode }) {
  return (
    <header className="page-head">
      <div>
        {crumb && <div className="crumb">{crumb}</div>}
        <h1>{title}</h1>
        {lede && <p>{lede}</p>}
      </div>
      {actions && <div className="actions">{actions}</div>}
    </header>
  );
}

export function Panel({ title, aside, children, flush, id }: { title?: ReactNode; aside?: ReactNode; children: ReactNode; flush?: boolean; id?: string }) {
  return (
    <section className={`panel${flush ? " flush" : ""}`} aria-labelledby={id}>
      {title && (
        <div className="panel-head">
          <h2 id={id}>{title}</h2>
          {aside && <div className="aside">{aside}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function Loading({ rows = 4, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div className="skeleton" role="status" aria-live="polite">
      <span className="sr-only">{label}</span>
      {Array.from({ length: rows }, (_, i) => <i key={i} />)}
    </div>
  );
}

export function ErrorState({ error, retry }: { error: unknown; retry?: () => void }) {
  const msg = error instanceof ApiError ? error.message : "Something went wrong reading this data.";
  const collector = error instanceof ApiError && (error.status === 502 || error.status === 0);
  return (
    <div className="state error" role="alert">
      <AlertTriangle size={20} aria-hidden />
      <h3>{collector ? "Data unavailable" : "Could not load this"}</h3>
      <p>{msg} Nothing on this view is shown from cache or estimated while it is unavailable.</p>
      {retry && <button className="btn" onClick={retry}><RefreshCw aria-hidden /> Try again</button>}
    </div>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="state">
      <Inbox size={20} aria-hidden />
      <h3>{title}</h3>
      {children && <p>{children}</p>}
    </div>
  );
}

export function Severity({ value }: { value: string }) {
  return <span className={`badge sev-${value}`}>{value}</span>;
}

export function Status({ value }: { value: string }) {
  return <span className={`badge st-${value}`}>{STATUS_LABEL[value] ?? words(value)}</span>;
}

export function DetectionBadge({ value }: { value: string }) {
  return <span className={`badge det-${value}`}>{DETECTION_LABEL[value] ?? words(value)}</span>;
}

export function ClassBadge({ value }: { value: string }) {
  if (value === "unclassified") return null;
  return <span className="badge cls" title="Analyst classification">{CLASS_LABEL[value]}</span>;
}

export function Health({ value }: { value: string }) {
  const label: Record<string, string> = { healthy: "Healthy", degraded: "Degraded", stale: "Stale", unknown: "Health unknown", internal: "Internal" };
  return <span className={`badge h-${value}`}>{label[value] ?? value}</span>;
}

export function ServiceTag({ service }: { service: string }) {
  return <span className="badge svc" style={{ ["--c" as string]: `var(--series-${service}, #999)` }}>{SERVICE_LABEL[service] ?? service}</span>;
}

export function SourceLink({ ip }: { ip: string }) {
  return <Link className="mono" to={`/sources/${encodeURIComponent(ip)}`}>{ip}</Link>;
}

export function When({ iso, full }: { iso: string | null | undefined; full?: boolean }) {
  if (!iso) return <span className="muted">—</span>;
  return <time className="num" dateTime={iso} title={dateTime(iso)}>{full ? dateTime(iso) : hhmmss(iso)}</time>;
}

export function KV({ rows }: { rows: [ReactNode, ReactNode][] }) {
  return (
    <dl className="kv">
      {rows.map(([k, v], i) => (
        <div key={i} style={{ display: "contents" }}>
          <dt>{k}</dt>
          <dd>{v ?? <span className="muted">—</span>}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Evidence is attacker-controlled text. It is only ever rendered as text, never as HTML or Markdown. */
export function Evidence({ value, label = "Stored evidence" }: { value: unknown; label?: string }) {
  return <pre className="evidence" aria-label={label}>{JSON.stringify(value, null, 2)}</pre>;
}

export function Pager({ total, limit, offset, onChange, noun }: { total: number; limit: number; offset: number; onChange: (o: number) => void; noun: string }) {
  if (total === 0) return null;
  const from = offset + 1;
  const to = Math.min(offset + limit, total);
  return (
    <nav className="pager" aria-label={`${noun} pages`}>
      <span className="num">{from.toLocaleString()}–{to.toLocaleString()} of {total.toLocaleString()} {noun}</span>
      <span className="spacer" />
      <button className="btn" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - limit))}>
        <ChevronLeft aria-hidden /> Previous
      </button>
      <button className="btn" disabled={to >= total} onClick={() => onChange(offset + limit)}>
        Next <ChevronRight aria-hidden />
      </button>
    </nav>
  );
}
