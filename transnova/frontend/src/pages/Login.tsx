import { useState } from "react";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { signIn } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  return (
    <div className="login">
      <aside className="login-side">
        <div className="brand-name">TransNova SOC</div>
        <p>The defender's console for the web, database and SSH decoys. Every sign-in attempt here, including a mistyped password, is recorded as an event.</p>
      </aside>
      <main className="login-main">
        <form className="login-card" onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await signIn(username.trim(), password);
          } catch (err) {
            setError((err as Error).message);
            setPassword("");
          } finally {
            setBusy(false);
          }
        }}>
          <h1>Sign in</h1>
          <label className="field">Username
            <input className="input" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} maxLength={64} />
          </label>
          <label className="field">Password
            <input className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} maxLength={256} />
          </label>
          {error && <p className="notice bad" role="alert">{error}</p>}
          <button className="btn primary" disabled={busy || !username || !password}>{busy ? "Signing in…" : "Sign in"}</button>
        </form>
      </main>
    </div>
  );
}
