import { useQuery } from "@tanstack/react-query";
import { fetchGlobalHealth, fetchTokenBurn, fetchArtifactEdits } from "@/services/api";
import { POLL_INTERVAL_MS } from "@/config";

export function useGlobalHealth(runId: string | null) {
  return useQuery({
    queryKey: ["globalHealth", runId],
    queryFn: () => fetchGlobalHealth(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useTokenBurn(runId: string | null) {
  return useQuery({
    queryKey: ["tokenBurn", runId],
    queryFn: () => fetchTokenBurn(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useArtifactEdits(runId: string | null) {
  return useQuery({
    queryKey: ["artifactEdits", runId],
    queryFn: () => fetchArtifactEdits(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}
