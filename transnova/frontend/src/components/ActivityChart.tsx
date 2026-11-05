import { useMemo, useState } from "react";
import { SERVICE_LABEL } from "../lib/format";

// Events per hour, stacked by decoy, drawn from /summary.activity_24h. Hours with no stored event are
// zero-height bars, so a quiet hour reads as quiet rather than missing.
const ORDER = ["web", "database", "ssh", "soc"];
const W = 720, H = 180, PAD_L = 32, PAD_B = 22, PAD_T = 8, GAP = 2;

export function ActivityChart({ rows }: { rows: { hour: string; service: string; count: number }[] }) {
  const [hover, setHover] = useState<{ x: number; y: number; hour: string; parts: [string, number][] } | null>(null);
  const { hours, max, present } = useMemo(() => {
    const now = new Date();
    now.setUTCMinutes(0, 0, 0);
    const keys = Array.from({ length: 24 }, (_, i) => new Date(now.getTime() - (23 - i) * 3600_000).toISOString().slice(0, 13) + ":00Z");
    const by = new Map(keys.map((k) => [k, new Map<string, number>()]));
    for (const r of rows) by.get(r.hour)?.set(r.service, (by.get(r.hour)?.get(r.service) ?? 0) + r.count);
    const hours = keys.map((k) => ({ hour: k, parts: ORDER.map((s) => [s, by.get(k)!.get(s) ?? 0] as [string, number]) }));
    const max = Math.max(1, ...hours.map((h) => h.parts.reduce((a, [, n]) => a + n, 0)));
    const present = ORDER.filter((s) => rows.some((r) => r.service === s));
    return { hours, max, present };
  }, [rows]);

  const plotW = W - PAD_L, plotH = H - PAD_B - PAD_T;
  const bw = plotW / 24;
  const ticks = [0, Math.ceil(max / 2), max];
  return (
    <figure>
      <svg className="chart" viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`Events per hour over the last 24 hours, highest hour ${max}.`} onMouseLeave={() => setHover(null)}>
        {ticks.map((t) => {
          const y = PAD_T + plotH - (t / max) * plotH;
          return (
            <g key={t}>
              <line className="grid" x1={PAD_L} x2={W} y1={y} y2={y} />
              <text className="axis" x={PAD_L - 6} y={y + 4} textAnchor="end">{t}</text>
            </g>
          );
        })}
        {hours.map((h, i) => {
          let y = PAD_T + plotH;
          const x = PAD_L + i * bw + 3;
          const segs = h.parts.filter(([, n]) => n > 0);
          return (
            <g key={h.hour} onMouseMove={(e) => setHover({ x: e.clientX, y: e.clientY, hour: h.hour, parts: h.parts })}>
              <rect x={PAD_L + i * bw} y={PAD_T} width={bw} height={plotH} fill="transparent" />
              {segs.map(([s, n], j) => {
                const hgt = Math.max(1, (n / max) * plotH - (j < segs.length - 1 ? GAP : 0));
                y -= hgt + (j > 0 ? GAP : 0);
                const top = j === segs.length - 1;
                return <rect key={s} x={x} y={y} width={bw - 6} height={hgt} rx={top ? 3 : 0} fill={`var(--series-${s})`} />;
              })}
              {i % 6 === 0 && <text className="axis" x={PAD_L + i * bw + bw / 2} y={H - 6} textAnchor="middle">{h.hour.slice(11, 13)}:00</text>}
            </g>
          );
        })}
      </svg>
      <figcaption className="legend" style={{ marginTop: 8 }}>
        {present.length > 1 && present.map((s) => <span key={s}><i style={{ ["--c" as string]: `var(--series-${s})` }} />{SERVICE_LABEL[s]}</span>)}
        <span className="muted">Hours in UTC</span>
      </figcaption>
      {hover && (
        <div className="tooltip" style={{ left: hover.x + 12, top: hover.y + 12 }} role="presentation">
          <div className="num">{hover.hour.slice(11, 16)} UTC</div>
          {hover.parts.filter(([, n]) => n > 0).map(([s, n]) => <div key={s}>{SERVICE_LABEL[s]}: <span className="num">{n}</span></div>)}
          {hover.parts.every(([, n]) => n === 0) && <div>No events</div>}
        </div>
      )}
    </figure>
  );
}
