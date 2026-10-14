import { useQuery } from "@tanstack/react-query";
import {
  fetchRuns,
  fetchRun,
  fetchPhases,
  fetchTasks,
  fetchEvents,
} from "@/services/api";
import { POLL_INTERVAL_MS } from "@/config";

export function useRuns() {
  return useQuery({
    queryKey: ["runs"],
    queryFn: fetchRuns,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useRun(runId: string | null) {
  return useQuery({
    queryKey: ["run", runId],
    queryFn: () => fetchRun(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function usePhases(runId: string | null) {
  return useQuery({
    queryKey: ["phases", runId],
    queryFn: () => fetchPhases(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useTasks(runId: string | null) {
  return useQuery({
    queryKey: ["tasks", runId],
    queryFn: () => fetchTasks(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}

export function useEvents(runId: string | null) {
  return useQuery({
    queryKey: ["events", runId],
    queryFn: () => fetchEvents(runId!),
    enabled: !!runId,
    refetchInterval: POLL_INTERVAL_MS,
  });
}
