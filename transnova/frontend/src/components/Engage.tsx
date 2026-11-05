import type { EngageRef } from "../api/types";

export const ENGAGE_URL = "https://engage.mitre.org/matrix/";

/** Which deception made a detection visible (MITRE Engage). Activity names only; no IDs we can't verify. */
export function EngageList({ items, rules }: { items: { rule?: string; engage: EngageRef[] }[]; rules?: boolean }) {
  const rows = items.flatMap((i) => i.engage.map((e) => ({ ...e, rule: i.rule })));
  const seen = new Set<string>();
  const unique = rows.filter((r) => {
    const k = `${r.rule ?? ""}|${r.activity}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  if (!unique.length) return <p className="small muted">No deception activity is recorded for these rules.</p>;
  return (
    <ul className="engage">
      {unique.map((r) => (
        <li key={`${r.rule}-${r.activity}`}>
          <div className="eg-head">
            <span className="eg-activity">{r.activity}</span>
            <span className="eg-goal">{r.goal} · {r.approach}</span>
            {rules && r.rule && <span className="mono small muted">{r.rule}</span>}
          </div>
          <div className="small muted">{r.description}</div>
        </li>
      ))}
    </ul>
  );
}
