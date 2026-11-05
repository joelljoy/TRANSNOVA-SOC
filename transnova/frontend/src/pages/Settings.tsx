import { useRules, useSystem } from "../api/hooks";
import { useAuth } from "../auth/AuthContext";
import { ErrorState, KV, Loading, PageHeader, Panel } from "../components/ui";

const yes = (v: boolean | null | undefined, ok = "Yes", no = "No") => (v === null || v === undefined ? "Not checked" : v ? ok : no);

export function Settings() {
  const sys = useSystem();
  const rules = useRules();
  const { me } = useAuth();
  return (
    <div className="page">
      <PageHeader title="Settings" lede="How this console is configured. Values come from the backend's environment and secret files; secrets are never shown, only whether they are present. Nothing here is edited from the browser." />
      <div className="grid-halves">
        <Panel title="Your account" id="acct">
          <KV rows={[["Signed in as", me?.username], ["Role", me?.role], ["Can change alerts", me && me.role !== "viewer" ? "Yes" : "No"],
            ["Idle sign-out after", me ? `${me.idle_timeout_min} minutes` : null]]} />
          <p className="small muted" style={{ marginTop: 12 }}>Accounts are managed on the server with <span className="mono">python -m console.users add</span>.</p>
        </Panel>
        <Panel title="Connections" id="conn">
          {sys.isLoading ? <Loading rows={4} /> : sys.isError ? <ErrorState error={sys.error} /> : (
            <KV rows={[
              ["Collector", `${sys.data!.collector} (${sys.data!.collector_url})`],
              ["Read token", `${yes(sys.data!.read_token_present, "Present", "Missing")} · accepted: ${yes(sys.data!.read_token_accepted)}`],
              ["Analyst-action token", yes(sys.data!.console_token_present, "Present", "Missing")],
              ["Console accounts", sys.data!.accounts],
              ["Sign-in audit backlog", `${sys.data!.audit_backlog} waiting, ${sys.data!.audit_dropped} refused by the collector`],
              ["Session cookie", `HttpOnly, SameSite=Strict, Secure: ${sys.data!.session.cookie_secure ? "on" : "off (plain HTTP on localhost)"}`],
              ["Session limit", `${sys.data!.session.idle_timeout_min} min idle, ${sys.data!.session.max_hours} h total`],
            ]} />
          )}
        </Panel>
        <Panel title="AI explanations" id="ai">
          {sys.data && (
            <KV rows={[["Provider", sys.data.ai.provider], ["Model", <span className="mono">{sys.data.ai.model}</span>],
              ["Status", sys.data.ai.configured ? "Configured (key held by the backend)" : "Not configured: explanations are unavailable"]]} />
          )}
          <p className="small muted" style={{ marginTop: 12 }}>The model sees only an alert's stored evidence. Its answer is saved as interpretation and never changes an alert or event.</p>
        </Panel>
        <Panel title="Detection content" id="det">
          {rules.data && (
            <KV rows={[["Rules catalogued", rules.data.rules.length], ["Rules that can alert", rules.data.rules.filter((r) => r.alerting).length],
              ["Signal-only rules", rules.data.rules.filter((r) => !r.alerting).map((r) => r.rule_id).join(", ")],
              ["ATT&CK dataset", `Enterprise v${rules.data.attack_version}`], ["OWASP edition", rules.data.owasp_edition]]} />
          )}
        </Panel>
      </div>
    </div>
  );
}
