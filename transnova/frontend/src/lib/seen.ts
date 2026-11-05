import { useEffect, useState } from "react";

// "New until seen": items stored after this viewer last looked at a list keep a brass mark. This is
// a per-browser convenience only; it never changes data and survives nothing important.
function read(key: string): string | null {
  try {
    return window.localStorage.getItem(`soc.seen.${key}`);
  } catch {
    return null;
  }
}

function write(key: string, value: string) {
  try {
    window.localStorage.setItem(`soc.seen.${key}`, value);
  } catch {
    /* storage unavailable: marks simply do not persist */
  }
}

export function useSeenSince(key: string): string | null {
  const [since] = useState(() => read(key));
  useEffect(() => {
    const stamp = () => write(key, new Date().toISOString());
    const t = window.setTimeout(stamp, 4000);
    return () => { window.clearTimeout(t); stamp(); };
  }, [key]);
  return since;
}

export const isNew = (iso: string, since: string | null) => since !== null && iso > since;
