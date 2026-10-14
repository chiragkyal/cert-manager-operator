import { useState, useMemo } from "react";
import DashboardLayout from "@/components/layout/DashboardLayout";
import DashboardHeader from "@/components/layout/DashboardHeader";
import PipelineStatusBanner from "@/components/pipeline/PipelineStatusBanner";
import GlobalHealthMetrics from "@/components/metrics/GlobalHealthMetrics";
import PhaseWaterfall from "@/components/phases/PhaseWaterfall";
import WorkerLogs from "@/components/logs/WorkerLogs";
import TokenBurnChart from "@/components/metrics/TokenBurnChart";

import { useRuns, useRun, usePhases, useTasks, useEvents } from "@/hooks/useRun";
import ArtifactEdits from "@/components/metrics/ArtifactEdits";
import { useGlobalHealth, useTokenBurn, useArtifactEdits } from "@/hooks/useMetrics";
import { useSSE } from "@/hooks/useSSE";
import { useLiveTelemetry } from "@/hooks/useLiveTelemetry";
import type { AgentEvent } from "@/types";

export default function App() {
  const { data: runsData } = useRuns();
  const latestRunId = runsData?.runs?.[0]?.id ?? null;
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);

  const activeRunId = selectedRunId ?? latestRunId;

  const { data: run } = useRun(activeRunId);
  const { data: phases } = usePhases(activeRunId);
  const { data: tasks } = useTasks(activeRunId);
  const { data: metrics } = useGlobalHealth(activeRunId);
  const { data: tokenBurn } = useTokenBurn(activeRunId);
  const { data: artifactEdits } = useArtifactEdits(activeRunId);
  const { data: historicalEvents } = useEvents(activeRunId);
  const { logs: streamLogs, lastPhaseUpdate, lastTaskUpdate, lastMetricsUpdate, lastPipelineStatus } = useSSE(activeRunId);

  useLiveTelemetry(activeRunId, lastPhaseUpdate, lastTaskUpdate, lastMetricsUpdate, lastPipelineStatus);

  const allLogs: AgentEvent[] = useMemo(() => {
    const seen = new Set<string>();
    const merged: AgentEvent[] = [];
    for (const log of streamLogs) {
      if (!seen.has(log.id)) {
        seen.add(log.id);
        merged.push(log);
      }
    }
    if (historicalEvents) {
      for (const log of historicalEvents) {
        if (!seen.has(log.id)) {
          seen.add(log.id);
          merged.push(log);
        }
      }
    }
    return merged;
  }, [streamLogs, historicalEvents]);

  return (
    <DashboardLayout>
      <DashboardHeader branch={run?.branch ?? ""} runId={activeRunId} />

      {runsData && runsData.runs.length > 1 && (
        <div className="bg-terminal-surface border-b border-terminal-border px-6 py-2 flex items-center gap-2">
          <label className="text-terminal-muted text-xs">Run:</label>
          <select
            value={activeRunId ?? ""}
            onChange={(e) => setSelectedRunId(e.target.value || null)}
            className="bg-terminal-bg border border-terminal-border rounded px-2 py-1 text-xs text-terminal-text"
          >
            {runsData.runs.map((r) => (
              <option key={r.id} value={r.id}>
                {r.jira_key} — {r.change_name}
              </option>
            ))}
          </select>
        </div>
      )}

      <PipelineStatusBanner run={run ?? null} />

      <GlobalHealthMetrics metrics={metrics ?? null} />

      <PhaseWaterfall phases={phases ?? []} tasks={tasks ?? []} />

      <ArtifactEdits data={artifactEdits ?? null} />

      <WorkerLogs logs={allLogs} />

      <TokenBurnChart data={tokenBurn ?? null} />
    </DashboardLayout>
  );
}
