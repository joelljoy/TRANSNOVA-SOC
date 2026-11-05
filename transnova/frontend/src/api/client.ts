// The only way the browser talks to anything: the console backend on the same origin. The session
// is an HttpOnly cookie; the CSRF token lives in memory only.

let csrf: string | null = null;
export const setCsrf = (value: string | null) => { csrf = value; };

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

type Params = Record<string, string | number | undefined | null>;

function query(params?: Params): string {
  if (!params) return "";
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
}

async function parse(resp: Response): Promise<unknown> {
  const text = await resp.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}

function detail(body: unknown, status: number): string {
  if (body && typeof body === "object" && "detail" in body) {
    const d = (body as { detail: unknown }).detail;
    if (typeof d === "string") return d;
    if (Array.isArray(d)) return "The request was not valid.";
  }
  if (status === 502) return "The collector is unavailable.";
  return `Request failed (${status}).`;
}

export async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && csrf) headers["X-CSRF-Token"] = csrf;
  let resp: Response;
  try {
    resp = await fetch(path, { method, headers, credentials: "same-origin", body: body === undefined ? undefined : JSON.stringify(body) });
  } catch {
    throw new ApiError(0, "The console backend could not be reached.");
  }
  const data = await parse(resp);
  if (!resp.ok) {
    if (resp.status === 401) window.dispatchEvent(new CustomEvent("soc:unauthorized"));
    throw new ApiError(resp.status, detail(data, resp.status));
  }
  return data as T;
}

export const getData = <T,>(route: string, params?: Params) => request<T>("GET", `/api/data/${route}${query(params)}`);
export const post = <T,>(path: string, body?: unknown) => request<T>("POST", path, body ?? {});
