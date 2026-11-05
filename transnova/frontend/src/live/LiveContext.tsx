import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { useQueryClient } from "@tanstack/react-query";

// Live updates are change notices from the console backend, which watches the collector's cursor.
// A notice only means "something new was stored"; the data itself is always re-read from the API.
// Without a working stream the pages fall back to polling, and the rail says which mode is on.

export type LiveState = "live" | "connecting" | "down";
const Ctx = createContext<LiveState>("connecting");

export function LiveProvider({ children, enabled }: { children: ReactNode; enabled: boolean }) {
  const [state, setState] = useState<LiveState>("connecting");
  const qc = useQueryClient();

  useEffect(() => {
    if (!enabled || typeof EventSource === "undefined") return;
    let source: EventSource | null = null;
    let retry: number | undefined;
    const connect = () => {
      setState("connecting");
      source = new EventSource("/api/stream");
      source.addEventListener("hello", () => setState("live"));
      source.addEventListener("change", () => {
        setState("live");
        qc.invalidateQueries();
      });
      source.addEventListener("status", () => setState("down"));
      source.onerror = () => {
        setState("down");
        source?.close();
        retry = window.setTimeout(connect, 5000);
      };
    };
    connect();
    return () => { source?.close(); window.clearTimeout(retry); };
  }, [enabled, qc]);

  return <Ctx.Provider value={state}>{children}</Ctx.Provider>;
}

export const useLive = () => useContext(Ctx);
/** Poll interval for queries: off while the stream is live, 10 s otherwise. */
export const usePollInterval = () => (useLive() === "live" ? false : 10_000);
