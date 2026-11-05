import { Link, Route, Routes } from "react-router-dom";
import { useAuth } from "./auth/AuthContext";
import { LiveProvider } from "./live/LiveContext";
import { Layout } from "./components/Layout";
import { Empty, Loading, PageHeader, Panel } from "./components/ui";
import { Overview } from "./pages/Overview";
import { Events } from "./pages/Events";
import { EventDetail } from "./pages/EventDetail";
import { Alerts } from "./pages/Alerts";
import { AlertDetail } from "./pages/AlertDetail";
import { SourceProfile, Sources } from "./pages/Sources";
import { Sensors } from "./pages/Sensors";
import { Mitre } from "./pages/Mitre";
import { Owasp } from "./pages/Owasp";
import { Settings } from "./pages/Settings";
import { Response } from "./pages/Response";
import { Login } from "./pages/Login";

function NotFound() {
  return <div className="page"><PageHeader title="Page not found" /><Panel><Empty title="Nothing lives at this address"><Link to="/">Go to the overview</Link></Empty></Panel></div>;
}

export function App() {
  const { me, checking } = useAuth();
  if (checking) return <div className="main"><Loading rows={3} label="Checking your session" /></div>;
  if (!me) return <Login />;
  return (
    <LiveProvider enabled>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="events" element={<Events />} />
          <Route path="events/:id" element={<EventDetail />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="alerts/:id" element={<AlertDetail />} />
          <Route path="sources" element={<Sources />} />
          <Route path="sources/:ip" element={<SourceProfile />} />
          <Route path="sensors" element={<Sensors />} />
          <Route path="mitre" element={<Mitre />} />
          <Route path="owasp" element={<Owasp />} />
          <Route path="response" element={<Response />} />
          <Route path="settings" element={<Settings />} />
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </LiveProvider>
  );
}
