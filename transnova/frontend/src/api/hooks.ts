import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { getData, post, request } from "./client";
import { usePollInterval } from "../live/LiveContext";
import type {
  Adaptation, AlertDetail, AlertSummary, Blocklist, EventDetail, EventPage, Facets, Mitre, Owasp, Page, RulesResponse, Sensor,
  SourceProfile, SourceRow, Summary, SystemStatus,
} from "./types";

type Params = Record<string, string | number | undefined>;

function useData<T>(route: string, params?: Params, opts: { enabled?: boolean; keep?: boolean } = {}) {
  const refetchInterval = usePollInterval();
  return useQuery<T>({
    queryKey: [route, params ?? {}],
    queryFn: () => getData<T>(route, params),
    refetchInterval,
    enabled: opts.enabled ?? true,
    placeholderData: opts.keep ? keepPreviousData : undefined,
  });
}

export const useSummary = () => useData<Summary>("summary");
export const useEvents = (p: Params) => useData<EventPage>("events", p, { keep: true });
export const useFacets = () => useData<Facets>("events/facets");
export const useEvent = (id: string | undefined) => useData<EventDetail>(`events/${id}`, undefined, { enabled: !!id });
export const useAlerts = (p: Params) => useData<Page<AlertSummary>>("alerts", p, { keep: true });
export const useAlert = (id: string | undefined) => useData<AlertDetail>(`alerts/${id}`, undefined, { enabled: !!id });
export const useSources = (p: Params) => useData<Page<SourceRow>>("sources", p, { keep: true });
export const useSource = (ip: string | undefined) =>
  useData<SourceProfile>(`sources/${encodeURIComponent(ip ?? "")}`, undefined, { enabled: !!ip });
export const useSensors = () => useData<Sensor[]>("sensors");
export const useMitre = () => useData<Mitre>("mitre");
export const useOwasp = () => useData<Owasp>("owasp");
export const useRules = () => useData<RulesResponse>("rules");
export const useAdaptations = () => useData<Adaptation[]>("adaptations");
export const useBlocklist = () => useData<Blocklist>("blocklist");
export const useSystem = () =>
  useQuery<SystemStatus>({ queryKey: ["system"], queryFn: () => request<SystemStatus>("GET", "/api/system"), refetchInterval: 30_000 });

function useAction<B>(path: (id: string) => string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, body }: { id: string; body: B }) => post(path(id), body),
    onSuccess: () => qc.invalidateQueries(),
  });
}

export const useAlertStatus = () => useAction<{ action: string; note?: string }>((id) => `/api/alerts/${id}/status`);
export const useAlertNote = () => useAction<{ note: string }>((id) => `/api/alerts/${id}/notes`);
export const useClassify = () => useAction<{ classification: string; reason: string }>((id) => `/api/events/${id}/classification`);
export const useExplain = () => useAction<Record<string, never>>((id) => `/api/alerts/${id}/explain`);
export const useBlock = () => useAction<{ ip: string; reason: string; alert_id?: string }>(() => "/api/blocks");
export const useUnblock = () => useAction<{ ip: string; reason: string }>(() => "/api/blocks/remove");
