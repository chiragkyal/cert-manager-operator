import type { PhaseExecution, TaskExecution } from "@/types";
import { STATUS_ICONS } from "@/types";
import TaskRow from "./TaskRow";

interface SubPhaseRowProps {
  phase: PhaseExecution;
  tasks: TaskExecution[];
  isExpanded: boolean;
  hasTasks: boolean;
  onToggle: () => void;
}

function formatTokens(n: number): string {
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

function formatDuration(seconds: number): string {
  if (seconds === 60) return "~1m (est.)";
  if (seconds === 0) return "\u2014";
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

export default function SubPhaseRow({
  phase,
  tasks,
  isExpanded,
  hasTasks,
  onToggle,
}: SubPhaseRowProps) {
  const icon = STATUS_ICONS[phase.status];

  return (
    <>
      <tr
        className="border-b border-terminal-border/50 hover:bg-terminal-surface/30 transition-colors cursor-pointer"
        onClick={hasTasks ? onToggle : undefined}
      >
        <td className="px-4 py-2 text-sm pl-10">
          <span className="text-terminal-muted mr-1">→</span>
          <span className="text-terminal-muted">Phase {phase.plan_phase}</span>
          {hasTasks && (
            <span className="text-terminal-muted ml-2 text-xs select-none">
              {isExpanded ? "▼" : "▶"}
            </span>
          )}
        </td>
        <td className="px-4 py-2 text-sm">
          {icon}{" "}
          <span
            className={
              phase.status === "passed"
                ? "text-terminal-green"
                : phase.status === "failed"
                ? "text-terminal-red"
                : phase.status === "waiting"
                ? "text-terminal-yellow"
                : "text-terminal-text"
            }
          >
            {phase.status.toUpperCase()}
          </span>
        </td>
        <td className="px-4 py-2 text-sm text-center">
          {phase.iteration_count} Iter.
          {phase.iteration_count > 3 && " 🔄"}
        </td>
        <td className="px-4 py-2 text-sm text-center">
          {formatDuration(phase.duration_s)}
        </td>
        <td className="px-4 py-2 text-sm text-center font-mono">
          {formatTokens(phase.tokens_in)} / {formatTokens(phase.tokens_out)}
        </td>
        <td className="px-4 py-2 text-sm">
          {phase.quality_label || `Score: ${phase.quality_score}/100`}
        </td>
      </tr>
      {isExpanded &&
        [...tasks]
          .sort((a, b) => a.task_id.localeCompare(b.task_id, undefined, { numeric: true }))
          .map((task) => <TaskRow key={task.id} task={task} />)}
    </>
  );
}
