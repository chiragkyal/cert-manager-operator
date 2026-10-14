import { API_BASE_URL, SSE_RECONNECT_MS } from "@/config";

export type SSEHandler = (event: string, data: Record<string, unknown>) => void;

export function createSSEConnection(
  runId: string | null,
  onEvent: SSEHandler
): { close: () => void } {
  const params = runId ? `?run_id=${runId}` : "";
  const url = `${API_BASE_URL}/events/stream${params}`;

  let eventSource: EventSource | null = null;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let closed = false;

  function connect() {
    if (closed) return;
    eventSource = new EventSource(url);

    const eventTypes = [
      "agent_log",
      "phase_update",
      "task_update",
      "metrics_update",
      "pipeline_status",
      "heartbeat",
    ];

    for (const type of eventTypes) {
      eventSource.addEventListener(type, (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          onEvent(type, data);
        } catch {
          // skip malformed events
        }
      });
    }

    eventSource.onerror = () => {
      eventSource?.close();
      if (!closed) {
        reconnectTimer = setTimeout(connect, SSE_RECONNECT_MS);
      }
    };
  }

  connect();

  return {
    close() {
      closed = true;
      eventSource?.close();
      if (reconnectTimer) clearTimeout(reconnectTimer);
    },
  };
}
