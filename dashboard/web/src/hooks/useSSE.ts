import { useEffect, useRef, useCallback, useState } from "react";
import { createSSEConnection, type SSEHandler } from "@/services/sse";
import { MAX_LOG_ENTRIES } from "@/config";
import type { AgentEvent } from "@/types";

export function useSSE(runId: string | null) {
  const [logs, setLogs] = useState<AgentEvent[]>([]);
  const [lastPhaseUpdate, setLastPhaseUpdate] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [lastMetricsUpdate, setLastMetricsUpdate] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [lastPipelineStatus, setLastPipelineStatus] = useState<Record<
    string,
    unknown
  > | null>(null);
  const [lastTaskUpdate, setLastTaskUpdate] = useState<Record<
    string,
    unknown
  > | null>(null);

  const connectionRef = useRef<{ close: () => void } | null>(null);

  const handleEvent: SSEHandler = useCallback((event, data) => {
    switch (event) {
      case "agent_log":
        setLogs((prev) => {
          const entry: AgentEvent = {
            id: (data.id as string) || crypto.randomUUID(),
            run_id: data.run_id as string,
            task_id: (data.task_id as string) || null,
            timestamp: (data.timestamp as string) || new Date().toISOString(),
            agent_id: data.agent_id as string,
            event_type: data.event_type as AgentEvent["event_type"],
            message: data.message as string,
            metadata_json: null,
          };
          const next = [entry, ...prev];
          return next.length > MAX_LOG_ENTRIES
            ? next.slice(0, MAX_LOG_ENTRIES)
            : next;
        });
        break;
      case "phase_update":
        setLastPhaseUpdate(data);
        break;
      case "task_update":
        setLastTaskUpdate(data);
        break;
      case "metrics_update":
        setLastMetricsUpdate(data);
        break;
      case "pipeline_status":
        setLastPipelineStatus(data);
        break;
    }
  }, []);

  useEffect(() => {
    connectionRef.current?.close();
    if (runId) {
      connectionRef.current = createSSEConnection(runId, handleEvent);
    }
    return () => {
      connectionRef.current?.close();
    };
  }, [runId, handleEvent]);

  return { logs, lastPhaseUpdate, lastTaskUpdate, lastMetricsUpdate, lastPipelineStatus };
}
