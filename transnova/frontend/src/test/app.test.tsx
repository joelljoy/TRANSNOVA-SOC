// UI tests. fetch is stubbed here and only here: these fixtures exist for tests, never for the app.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { AuthProvider } from "../auth/AuthContext";
import { App } from "../App";

type Handler = (url: URL, init?: RequestInit) => [number, unknown];
let routes: Record<string, Handler>;
let calls: { url: string; init?: RequestInit }[];

const me = { username: "analyst", role: "analyst", csrf: "csrf-1", idle_timeout_min: 30 };
const emptySummary = {
  events_total: 0, last_event_at: null, sources_observed: 0, events_by_service: [], activity_24h: [],
  alerts_needing_attention: {}, alert_status_counts: {}, sensors: [], ingestion: { since: "2026-11-01T00:00:00Z", total: 0, reasons: [], other: [] },
  read_capped_at: null,
};
const page = (items: unknown[] = []) => ({ items, total: items.length, limit: 50, offset: 0, span: null });
const xssEvent = {
  event_id: "e1111111-0000-4000-8000-000000000001", timestamp: "2026-11-01T10:00:00.000Z", sensor_id: "web-01", service: "web",
  source_ip: "172.28.0.50", source_port: 4000, destination_service: "web-decoy", event_type: "http_request", action: "route_probe",
  outcome: "observed", username: null, session_id: null, campaign_id: null, request_path: "/search?q=<img src=x onerror=alert(1)>",
  http_method: "GET", http_status: 200, command: null, query_type: null, database_name: null, table_names: [], rows_returned: null,
  file_name: null, file_direction: null, user_agent: "<script>alert(1)</script>", raw_evidence_redacted: { detections: [] }, tags: [],
  detection_status: "matched", alert_ids: [], rules: ["W-XSS-01"], classification: "unclassified",
};

function stub() {
  calls = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string, init?: RequestInit) => {
    const url = new URL(input, "http://localhost");
    calls.push({ url: url.pathname + url.search, init });
    const key = Object.keys(routes).find((k) => url.pathname === k || (k.endsWith("*") && url.pathname.startsWith(k.slice(0, -1))));
    const [status, body] = key ? routes[key](url, init) : [404, { detail: "unknown route" }];
    return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
  }));
  vi.stubGlobal("EventSource", undefined);
}

function renderAt(path: string) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}><MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}><AuthProvider><App /></AuthProvider></MemoryRouter></QueryClientProvider>,
  );
}

beforeEach(() => {
  routes = {
    "/api/auth/me": () => [200, me],
    "/api/data/summary": () => [200, emptySummary],
    "/api/data/events": () => [200, page()],
    "/api/data/alerts": () => [200, page()],
    "/api/data/events/facets": () => [200, { service: [], event_type: [], outcome: [], rule: [] }],
    "/api/data/rules": () => [200, { owasp_edition: "OWASP Top 10:2025", attack_version: "20.0", rules: [] }],
  };
  stub();
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

describe("sign-in", () => {
  it("shows the login form when there is no session, and reports a wrong password", async () => {
    routes["/api/auth/me"] = () => [200, { authenticated: false }];
    routes["/api/auth/login"] = () => [401, { detail: "username or password is incorrect" }];
    renderAt("/");
    await userEvent.type(await screen.findByLabelText("Username"), "analyst");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("username or password is incorrect");
    expect(screen.getByLabelText("Password")).toHaveValue("");
    const body = JSON.parse(String(calls.find((c) => c.url === "/api/auth/login")!.init!.body));
    expect(body).toEqual({ username: "analyst", password: "wrong" });
  });

  it("enters the console after a successful sign-in", async () => {
    routes["/api/auth/me"] = () => [200, { authenticated: false }];
    routes["/api/auth/login"] = () => [200, me];
    renderAt("/");
    await userEvent.type(await screen.findByLabelText("Username"), "analyst");
    await userEvent.type(screen.getByLabelText("Password"), "correct horse battery");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });
});

describe("honest states", () => {
  it("overview shows empty states, not invented numbers, when nothing is stored", async () => {
    renderAt("/");
    expect(await screen.findByText("No events received yet")).toBeInTheDocument();
    expect(screen.getByText("No sensor has sent an event or heartbeat yet.")).toBeInTheDocument();
    expect(screen.getByText("No open alerts")).toBeInTheDocument();
  });

  it("shows a clear error when the collector is unavailable", async () => {
    routes["/api/data/summary"] = () => [502, { detail: "collector unavailable" }];
    renderAt("/");
    expect(await screen.findByText("Data unavailable")).toBeInTheDocument();
    expect(screen.getByText(/collector unavailable/)).toBeInTheDocument();
  });

  it("sensors are never shown healthy without a heartbeat", async () => {
    routes["/api/data/sensors"] = () => [200, [{ sensor_id: "web-01", service: "web", health: "unknown",
      health_reason: "This sensor sends no heartbeat, so only its last event is known.", last_heartbeat_at: null,
      heartbeat_age_s: null, reported_status: null, last_event_at: "2026-11-01T10:00:00.000Z", events_total: 3, events_5m: 0,
      events_1h: 0, details: {}, sessions: null }]];
    routes["/api/data/adaptations"] = () => [200, []];
    renderAt("/sensors");
    expect(await screen.findByText("Health unknown")).toBeInTheDocument();
    expect(screen.getByText("none sent")).toBeInTheDocument();
    expect(screen.queryByText("Healthy")).not.toBeInTheDocument();
  });
});

describe("events", () => {
  it("renders attacker-controlled strings as text only", async () => {
    routes["/api/data/events"] = () => [200, { ...page([xssEvent]), total: 1 }];
    const { container } = renderAt("/events");
    expect(await screen.findByText(/<img src=x onerror=alert\(1\)>/)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(screen.getByText("Rule matched")).toBeInTheDocument();
  });

  it("sends filters to the backend instead of filtering in the browser", async () => {
    renderAt("/events");
    await screen.findByText("No events received yet");
    await userEvent.selectOptions(screen.getByLabelText("Detection"), "alerted");
    await waitFor(() => expect(calls.some((c) => c.url.startsWith("/api/data/events?") && c.url.includes("detection=alerted"))).toBe(true));
    expect(await screen.findByText("No events match these filters")).toBeInTheDocument();
  });

  it("pages through results with offsets", async () => {
    routes["/api/data/events"] = (u) => [200, { items: [xssEvent], total: 120, limit: 50, offset: Number(u.searchParams.get("offset") ?? 0), span: null }];
    renderAt("/events");
    await userEvent.click(await screen.findByRole("button", { name: /Next/ }));
    await waitFor(() => expect(calls.some((c) => c.url.includes("offset=50"))).toBe(true));
  });
});

describe("alerts", () => {
  const alert = {
    alert_id: "a1", rule: "SOC-AUTH-01", title: "Repeated failed SOC console logins", severity: "medium", confidence: "medium",
    status: "open", status_updated_at: null, status_updated_by: null, first_seen: "2026-11-01T10:00:00.000Z",
    last_seen: "2026-11-01T10:05:00.000Z", source_ip: "127.0.0.1", service: "soc", event_count: 5, attack_ids: ["T1110"],
    kill_chain_stage: "credential_access", owasp_2025: null, activity_after_status: false,
  };
  const detail = {
    alert, rationale: "5 failed console logins", recommended_action: "Check with the account owner", attack: [{ technique: "T1110", name: "Brute Force", tactics: ["credential-access"], status: "candidate", valid: true }],
    rule: { rule_id: "SOC-AUTH-01", name: "Repeated failed console logins", logic: ">= 5 failures", required_evidence: "username", confidence_model: "medium", false_positives: "An analyst who forgot a password", does_not_detect: "", tested_by: [] },
    events: [], matched_detections: [], evidence_window: null, events_truncated: false, history: [], explanations: [], source: null,
  };

  it("explains why the alert exists and what could make it a false positive", async () => {
    routes["/api/data/alerts/a1"] = () => [200, detail];
    renderAt("/alerts/a1");
    expect(await screen.findByRole("heading", { name: alert.title })).toBeInTheDocument();
    expect(screen.getByText(/An analyst who forgot a password/)).toBeInTheDocument();
    expect(screen.getByText(/inferred by rule \(candidate\)/)).toBeInTheDocument();
  });

  it("requires a reason before marking a false positive, and persists through the backend", async () => {
    routes["/api/data/alerts/a1"] = () => [200, detail];
    routes["/api/alerts/a1/status"] = () => [200, { ok: true }];
    renderAt("/alerts/a1");
    const fp = await screen.findByRole("button", { name: "Mark false positive" });
    expect(fp).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Note or reason/), "Owner mistyped while testing");
    await userEvent.click(fp);
    await waitFor(() => expect(calls.some((c) => c.url === "/api/alerts/a1/status")).toBe(true));
    const call = calls.find((c) => c.url === "/api/alerts/a1/status")!;
    expect(JSON.parse(String(call.init!.body))).toEqual({ action: "false_positive", note: "Owner mistyped while testing" });
    expect((call.init!.headers as Record<string, string>)["X-CSRF-Token"]).toBe("csrf-1");
  });

  it("says the AI explanation is unavailable instead of inventing one", async () => {
    routes["/api/data/alerts/a1"] = () => [200, detail];
    routes["/api/alerts/a1/explain"] = () => [503, { detail: "AI explanations are not configured (no ANTHROPIC_API_KEY on the console backend).", available: false }];
    renderAt("/alerts/a1");
    await userEvent.click(await screen.findByRole("button", { name: /Explain this alert/ }));
    const xai = (await screen.findByRole("heading", { name: "Explainable AI" })).closest("section")!;
    expect(await within(xai).findByRole("alert")).toHaveTextContent("not configured");
    expect(within(xai).getByText(/No AI explanation has been requested/)).toBeInTheDocument();
  });

  it("hides write actions from viewers", async () => {
    routes["/api/auth/me"] = () => [200, { ...me, role: "viewer" }];
    routes["/api/data/alerts/a1"] = () => [200, detail];
    renderAt("/alerts/a1");
    expect(await screen.findByText("Your role can view alerts but not change them.")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Resolve" })).not.toBeInTheDocument();
  });
});

describe("navigation", () => {
  it("has every page in the rail and an honest not-found page", async () => {
    renderAt("/nowhere");
    for (const name of ["Overview", "All events", "Alerts", "Sources", "Sensors", "MITRE ATT&CK", "OWASP web", "Settings"]) {
      expect(await screen.findByRole("link", { name: new RegExp(`^${name.replace(/[&]/g, "&")}`) })).toBeInTheDocument();
    }
    expect(screen.getByRole("heading", { name: "Page not found" })).toBeInTheDocument();
  });
});
