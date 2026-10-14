import { useRef, useEffect } from "react";
import type { AgentEvent } from "@/types";
import LogEntry from "./LogEntry";

interface WorkerLogsProps {
  logs: AgentEvent[];
}

export default function WorkerLogs({ logs }: WorkerLogsProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [logs.length]);

  return (
    <section className="px-6 py-4 border-b border-terminal-border">
      <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
        Active Target Worker Logs &amp; Self-Reflection Loop Monitor
      </div>
      <div
        ref={containerRef}
        className="bg-terminal-bg border border-terminal-border rounded max-h-64 overflow-y-auto"
      >
        {logs.length === 0 ? (
          <div className="px-4 py-8 text-center text-terminal-muted text-sm">
            Waiting for agent events...
          </div>
        ) : (
          logs.map((event) => <LogEntry key={event.id} event={event} />)
        )}
      </div>
    </section>
  );
}
