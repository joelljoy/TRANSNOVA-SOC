// Formatting only. These never invent a value: a missing input renders as an em dash.

export const DASH = "—";

export function time(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(11, 19);
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return DASH;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${d.toISOString().slice(0, 10)} ${d.toISOString().slice(11, 19)} UTC`;
}

export function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return DASH;
  const s = Math.round((now - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(s)) return DASH;
  if (s < 5) return "just now";
  if (s < 60) return `${s} s ago`;
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

export function duration(seconds: number): string {
  if (seconds < 1) return "under 1 s";
  if (seconds < 60) return `${Math.round(seconds)} s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ${Math.round(seconds % 60)} s`;
  return `${Math.floor(seconds / 3600)} h ${Math.round((seconds % 3600) / 60)} min`;
}

export const count = (n: number | null | undefined) => (n === null || n === undefined ? DASH : n.toLocaleString("en-US"));

export const words = (s: string | null | undefined) => (s ? s.replace(/_/g, " ") : DASH);

export const SERVICE_LABEL: Record<string, string> = {
  web: "Web decoy", database: "Database decoy", ssh: "SSH decoy", soc: "SOC console", multi: "Several decoys",
};

export const STATUS_LABEL: Record<string, string> = {
  open: "Open", investigating: "Under investigation", confirmed_malicious: "Confirmed malicious",
  false_positive: "False positive", resolved: "Resolved",
};

export const DETECTION_LABEL: Record<string, string> = {
  observed: "Observed", matched: "Rule matched", alerted: "In an alert",
};

export const CLASS_LABEL: Record<string, string> = {
  benign: "Benign", suspicious: "Suspicious", confirmed_malicious: "Confirmed malicious", false_positive: "False positive",
  unclassified: "Unclassified / requires investigation",
};

/** What the event did, in one short line, from its own fields. */
export function describe(e: { action: string; request_path?: string | null; http_method?: string | null; command?: string | null; username?: string | null; event_type: string }): string {
  if (e.event_type === "http_request" && e.request_path) return `${e.http_method ?? ""} ${e.request_path}`.trim();
  if (e.command) return e.command;
  if (e.event_type === "authentication") return `${words(e.action)}${e.username ? ` as ${e.username}` : ""}`;
  if (e.request_path) return `${words(e.action)} ${e.request_path}`;
  return words(e.action);
}

export const plural = (n: number, word: string) => `${n.toLocaleString("en-US")} ${word}${n === 1 ? "" : "s"}`;
