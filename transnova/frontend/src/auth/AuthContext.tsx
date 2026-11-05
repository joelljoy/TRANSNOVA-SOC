import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { ApiError, post, request, setCsrf } from "../api/client";
import type { Me } from "../api/types";

interface AuthState {
  me: Me | null;
  checking: boolean;
  signIn: (username: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
  canWrite: boolean;
}

const Ctx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [checking, setChecking] = useState(true);
  const qc = useQueryClient();

  useEffect(() => {
    request<Me & { authenticated?: boolean }>("GET", "/api/auth/me")
      .then((m) => { if (m.authenticated === false) { setMe(null); return; } setCsrf(m.csrf); setMe(m); })
      .catch(() => setMe(null))
      .finally(() => setChecking(false));
    const onUnauthorized = () => { setCsrf(null); setMe(null); qc.clear(); };
    window.addEventListener("soc:unauthorized", onUnauthorized);
    return () => window.removeEventListener("soc:unauthorized", onUnauthorized);
  }, [qc]);

  const signIn = useCallback(async (username: string, password: string) => {
    const m = await post<Me>("/api/auth/login", { username, password });
    setCsrf(m.csrf);
    setMe(m);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await post("/api/auth/logout");
    } catch (e) {
      if (!(e instanceof ApiError) || e.status !== 401) throw e;
    }
    setCsrf(null);
    setMe(null);
    qc.clear();
  }, [qc]);

  const value = useMemo(() => ({ me, checking, signIn, signOut, canWrite: !!me && me.role !== "viewer" }),
    [me, checking, signIn, signOut]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useAuth(): AuthState {
  const v = useContext(Ctx);
  if (!v) throw new Error("useAuth outside AuthProvider");
  return v;
}
