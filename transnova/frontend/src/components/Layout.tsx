import { NavLink, Outlet } from "react-router-dom";
import { Activity, Ban, Bell, Cpu, Fingerprint, Globe2, LayoutGrid, Settings, Shield } from "lucide-react";
import { useAuth } from "../auth/AuthContext";
import { useLive } from "../live/LiveContext";
import { useSummary } from "../api/hooks";

const LIVE_LABEL = { live: "Live updates on", connecting: "Connecting…", down: "Live updates off, refreshing every 10 s" };

export function Layout() {
  const { me, signOut } = useAuth();
  const live = useLive();
  const summary = useSummary();
  const attention = summary.data
    ? Object.values(summary.data.alerts_needing_attention).reduce((a, b) => a + (b ?? 0), 0)
    : undefined;
  const nav = [
    { to: "/", label: "Overview", icon: LayoutGrid, end: true },
    { to: "/events", label: "All events", icon: Activity, count: summary.data?.events_total },
    { to: "/alerts", label: "Alerts", icon: Bell, count: attention },
    { to: "/sources", label: "Sources", icon: Fingerprint, count: summary.data?.sources_observed },
    { to: "/sensors", label: "Sensors", icon: Cpu },
    { to: "/mitre", label: "MITRE ATT&CK", icon: Shield },
    { to: "/owasp", label: "OWASP web", icon: Globe2 },
    { to: "/response", label: "Response", icon: Ban },
    { to: "/settings", label: "Settings", icon: Settings },
  ];
  return (
    <div className="shell">
      <nav className="rail" aria-label="Main">
        <div className="brand">
          <div className="brand-name">TransNova SOC</div>
          <div className="brand-sub">Web, database and SSH decoys</div>
        </div>
        <div className="nav">
          {nav.map(({ to, label, icon: Icon, end, count }) => (
            <NavLink key={to} to={to} end={end}>
              <Icon size={17} aria-hidden />
              {label}
              {count !== undefined && <span className="count" aria-label={`${count} ${label}`}>{count.toLocaleString()}</span>}
            </NavLink>
          ))}
        </div>
        <div className="rail-foot">
          <span className="live" data-state={live} role="status"><span className="live-dot" aria-hidden />{LIVE_LABEL[live]}</span>
          <span className="user">{me?.username} · {me?.role}</span>
          <button onClick={() => void signOut()}>Sign out</button>
        </div>
      </nav>
      <main className="main" id="main">
        <Outlet />
      </main>
    </div>
  );
}
