// Shapes returned by the console backend (which relays the collector's /api/v2). Nothing here is
// filled in by the browser: a missing value stays missing.

export type Service = "web" | "database" | "ssh" | "soc";
export type Severity = "critical" | "high" | "medium" | "low";
export type AlertStatus = "open" | "investigating" | "confirmed_malicious" | "false_positive" | "resolved";
export type DetectionStatus = "observed" | "matched" | "alerted";
export type Classification = "benign" | "suspicious" | "confirmed_malicious" | "false_positive" | "unclassified";

export interface Page<T> { items: T[]; total: number; limit: number; offset: number }

export interface AttackRef {
  technique?: string; name?: string | null; tactic?: string; status?: string; confidence?: string; rationale?: string;
  tactics?: string[]; valid?: boolean; url?: string | null;
}

export interface Detection {
  rule: string; category?: string; label?: string; field?: string; owasp?: string; confidence?: string;
  severity?: string; rationale?: string; attack?: AttackRef[];
}

export interface SocEvent {
  event_id: string; timestamp: string; sensor_id: string; service: Service; source_ip: string; source_port: number | null;
  destination_service: string; event_type: string; action: string; outcome: string; username: string | null;
  session_id: string | null; campaign_id: string | null; request_path: string | null; http_method: string | null;
  http_status: number | null; command: string | null; query_type: string | null; database_name: string | null;
  table_names: string[]; rows_returned: number | null; file_name: string | null; file_direction: string | null;
  user_agent: string | null; raw_evidence_redacted: Record<string, unknown> & { detections?: Detection[] }; tags: string[];
  detection_status: DetectionStatus; alert_ids: string[]; rules: string[]; classification: Classification;
}

export interface EventPage extends Page<SocEvent> { span: { first: string; last: string } | null }

export interface EngageRef { activity: string; goal: "Expose" | "Affect" | "Elicit" | string; approach: string; description: string }

export interface ExplainedDetection {
  rule: string; name: string; field?: string | null; confidence?: string | null; severity?: string | null;
  rationale?: string | null; owasp_2021?: string | null; owasp_2025?: string | null; alerting: boolean; attack: AttackRef[];
  engage?: EngageRef[]; event_id?: string; timestamp?: string;
}

export interface Block {
  ip: string; created_at: string; expires_at: string; actor: string; rule: string | null; alert_id: string | null; reason: string;
}

export interface Blocklist {
  active: Block[]; history: (Omit<Block, "created_at" | "expires_at"> & { ts: string; action: "block" | "unblock" })[];
  auto_rules: string[]; ttl_s: number; engage: EngageRef[];
}

export interface Annotation { ts: string; actor: string; classification: Classification; previous: string | null; reason: string }

export interface AlertSummary {
  alert_id: string; rule: string; title: string; severity: Severity; confidence: string | null; status: AlertStatus;
  status_updated_at: string | null; status_updated_by: string | null; first_seen: string; last_seen: string;
  source_ip: string; service: string; event_count: number; attack_ids: string[]; kill_chain_stage: string | null;
  owasp_2025: string | null; activity_after_status: boolean;
}

export interface EventDetail {
  event: SocEvent; annotations: Annotation[]; alerts: AlertSummary[]; session_events: SocEvent[];
  source_recent: SocEvent[]; detections: ExplainedDetection[];
}

export interface RuleEntry {
  rule_id: string; name: string; service: string; description: string; logic: string; required_evidence: string;
  default_severity: Severity; confidence_model: string; false_positives: string; attack: string[];
  owasp_2021: string | null; owasp_2025: string | null; alerting: boolean; does_not_detect: string;
  tested_by: { path: string; needle: string; kind: string }[];
}

export interface HistoryEntry {
  ts: string; actor: string; action: string; from_status: string | null; to_status: string | null; note: string | null;
}

export interface Explanation {
  summary: string; observed_facts: { fact: string; event_ids: string[] }[]; rule_conclusion: string; interpretation: string;
  benign_explanations: string[]; supporting_evidence: string[]; weakening_evidence: string[]; missing_context: string[];
  next_steps: string[]; confidence_note: string;
}

export interface StoredExplanation { ts: string; actor: string; model: string; evidence_digest: string; explanation: Explanation }

export interface SourceBrief {
  source_ip: string; kind: string; first_seen: string; last_seen: string; event_count: number; services: string[];
  sessions: number; alerts_by_severity: Partial<Record<Severity, number>>; alert_count: number; attribution: string;
}

export interface AlertDetail {
  alert: AlertSummary; rationale: string | null; recommended_action: string | null; attack: AttackRef[];
  rule: RuleEntry | null; events: SocEvent[]; matched_detections: ExplainedDetection[];
  evidence_window: { first: string; last: string } | null; events_truncated: boolean; history: HistoryEntry[];
  explanations: StoredExplanation[]; source: SourceBrief | null;
  engage?: EngageRef[]; engage_matrix?: string; block?: Block | null;
}

export interface SourceRow {
  source_ip: string; first_seen: string; last_seen: string; event_count: number; services: string[]; sessions: number;
  alert_count: number; kind: string;
}

export interface Correlation {
  correlation_id: string; rule: string; title: string; related_event_ids: string[]; related_sources?: string[];
  window: { first: string; last: string } | null; confidence: string; reason: string; session_id?: string; campaign_id?: string;
}

export interface SourceProfile extends Omit<SourceBrief, "sessions"> {
  breakdown: { service: string; event_type: string; outcome: string; count: number }[];
  sessions: SessionRow[];
  commands: { event_id: string; timestamp: string; command: string; session_id: string | null }[];
  http_requests: { method: string | null; path: string | null; count: number; last_seen: string }[];
  sql_queries: { event_id: string; timestamp: string; command: string | null; outcome: string }[];
  authentication: { service: string; username: string; outcome: string; count: number }[];
  techniques: { technique: string; name: string | null; tactics: string[]; valid: boolean; statuses: Record<string, number>;
    rules: string[]; event_ids: string[]; basis: "evidence" | "rule_inferred" }[];
  alerts: AlertSummary[];
  correlations: Correlation[];
}

export interface SessionRow {
  session_id: string; service: string; first_seen: string; last_seen: string; event_count: number; duration_s: number;
  usernames: string[];
}

export interface Sensor {
  sensor_id: string; service: string | null; health: "healthy" | "degraded" | "stale" | "unknown" | "internal";
  health_reason: string; last_heartbeat_at: string | null; heartbeat_age_s: number | null; reported_status: string | null;
  last_event_at: string | null; events_total: number; events_5m: number; events_1h: number;
  details: Record<string, unknown>; sessions: Record<string, unknown>[] | null;
}

export interface Refusal { reason: string; kind: string; count: number; last_at: string }
export interface Ingestion { since: string; total: number; reasons: Refusal[]; other: Refusal[] }

export interface Summary {
  events_total: number; last_event_at: string | null; sources_observed: number;
  events_by_service: { service: string; count: number; last_event_at: string }[];
  activity_24h: { hour: string; service: string; count: number }[];
  alerts_needing_attention: Partial<Record<Severity, number>>; alert_status_counts: Partial<Record<AlertStatus, number>>;
  sensors: Sensor[]; ingestion: Ingestion; read_capped_at: string | null;
}

export interface MitreRow {
  technique: string; name: string | null; tactics: string[]; valid: boolean; url: string | null; subtechnique?: boolean;
  rules: string[]; rules_tested: string[]; evidence_observed: number; evidence_candidate: number; alerts: number;
  status: "evidence" | "rule_inferred" | "implemented_not_observed" | "gap"; gap_reason: string | null; services: string[];
}

export interface Mitre {
  attack_version: string; source: string; modified: string; total_techniques: number;
  tactics: { id: string; shortname: string; name: string }[]; techniques: MitreRow[];
}

export interface OwaspCategory {
  code: string; name: string; rules: string[]; observable: boolean; not_observable_reason: string | null; matches: number;
  last_seen: string | null; by_rule: { rule: string; label_2021: string; matches: number; sources: number }[];
}

export interface Owasp { edition: string; source: string; sensor_edition: string; web_events: number; categories: OwaspCategory[] }

export interface RulesResponse {
  owasp_edition: string; attack_version: string;
  rules: (RuleEntry & { matches: number; alerts: number; attack_detail: AttackRef[] })[];
}

export interface Facets { [k: string]: { value: string; count: number }[] }

export interface Me { username: string; role: "viewer" | "analyst" | "admin"; csrf: string; idle_timeout_min: number }

export interface SystemStatus {
  collector: string; collector_url: string; read_token_accepted: boolean | null; read_token_present: boolean;
  console_token_present: boolean; accounts: number; ai: { configured: boolean; model: string; provider: string };
  audit_backlog: number; audit_dropped: number; session: { idle_timeout_min: number; max_hours: number; cookie_secure: boolean };
}

export interface Adaptation {
  adaptation_id: string; timestamp: string; rule_id: string; stage: number; trigger_event_id: string; trigger_reason: string;
  asset_revealed: string; source_ip: string; status: string; statement: string | null; privilege_before: boolean | null;
  privilege_after: boolean | null; followup_event_ids: string[];
  followups: { event_id: string; timestamp: string; command: string | null; source_ip: string; session_id: string | null }[];
}
