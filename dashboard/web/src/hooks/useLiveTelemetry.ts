import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";

/**
 * Invalidates React Query caches when SSE events arrive, giving
 * the dashboard near-instant updates instead of waiting for the
 * 10s poll interval.
 */
export function useLiveTelemetry(
  runId: string | null,
  lastPhaseUpdate: Record<string, unknown> | null,
  lastTaskUpdate: Record<string, unknown> | null,
  lastMetricsUpdate: Record<string, unknown> | null,
  lastPipelineStatus: Record<string, unknown> | null
) {
  const queryClient = useQueryClient();

  useEffect(() => {
    if (!runId || !lastPhaseUpdate) return;
    queryClient.invalidateQueries({ queryKey: ["phases", runId] });
  }, [queryClient, runId, lastPhaseUpdate]);

  useEffect(() => {
    if (!runId || !lastTaskUpdate) return;
    queryClient.invalidateQueries({ queryKey: ["tasks", runId] });
  }, [queryClient, runId, lastTaskUpdate]);

  useEffect(() => {
    if (!runId || !lastMetricsUpdate) return;
    queryClient.invalidateQueries({ queryKey: ["globalHealth", runId] });
    queryClient.invalidateQueries({ queryKey: ["tokenBurn", runId] });
  }, [queryClient, runId, lastMetricsUpdate]);

  useEffect(() => {
    if (!runId || !lastPipelineStatus) return;
    queryClient.invalidateQueries({ queryKey: ["run", runId] });
    queryClient.invalidateQueries({ queryKey: ["runs"] });
  }, [queryClient, runId, lastPipelineStatus]);
}
