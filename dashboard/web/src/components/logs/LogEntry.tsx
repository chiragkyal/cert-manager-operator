import type { AgentEvent, EventType } from "@/types";

const EVENT_STYLES: Record<EventType, { prefix: string; color: string }> = {
  tool_call: { prefix: "[Tool Call]", color: "text-terminal-accent" },
  harness_alert: { prefix: "[Harness Alert]", color: "text-terminal-red" },
  self_correction: { prefix: "[Self-Correction]", color: "text-terminal-yellow" },
  state_machine: { prefix: "[State Machine]", color: "text-terminal-muted" },
};

interface LogEntryProps {
  event: AgentEvent;
}

export default function LogEntry({ event }: LogEntryProps) {
  const style = EVENT_STYLES[event.event_type];
  const time = new Date(event.timestamp).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });

  return (
    <div className="flex gap-2 px-4 py-1 text-xs font-mono hover:bg-terminal-surface/40 transition-colors">
      <span className="text-terminal-muted shrink-0">[{time}]</span>
      <span className="text-terminal-muted shrink-0">-&gt;</span>
      <span className="text-terminal-accent shrink-0">[{event.agent_id || "Unknown"}]</span>
      <span className={`${style.color} shrink-0`}>{style.prefix}</span>
      <span className="text-terminal-text break-all">{event.message}</span>
    </div>
  );
}
