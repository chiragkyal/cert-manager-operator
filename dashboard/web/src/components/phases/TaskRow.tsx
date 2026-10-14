import type { TaskExecution, TaskStatus } from "@/types";

const TASK_STATUS_ICONS: Record<TaskStatus, string> = {
  passed: "✅",
  failed: "❌",
  running: "🔄",
  pending: "⏳",
  waiting: "🟡",
  skipped: "⏭️",
};

interface TaskRowProps {
  task: TaskExecution;
}

type BadgeStatus = "passed" | "failed" | "skipped";

function resolveBadgeStatus(value: unknown): BadgeStatus | null {
  if (value === undefined) return null;
  if (value === "passed" || value === true) return "passed";
  if (value === "skipped") return "skipped";
  return "failed";
}

const BADGE_STYLES: Record<BadgeStatus, string> = {
  passed: "bg-green-900/40 text-green-400 border border-green-700/50",
  failed: "bg-red-900/40 text-red-400 border border-red-700/50",
  skipped: "bg-zinc-800/40 text-zinc-500 border border-zinc-700/50",
};

const BADGE_ICONS: Record<BadgeStatus, string> = {
  passed: "✓",
  failed: "✗",
  skipped: "–",
};

function VerificationBadge({ metadata }: { metadata?: Record<string, unknown> | null }) {
  if (!metadata) return null;

  const fields: { key: string; label: string }[] = [
    { key: "build_status", label: "Build" },
    { key: "test_status", label: "Test" },
    { key: "verify_status", label: "Verify" },
  ];

  const badges = fields
    .map(({ key, label }) => {
      const status = resolveBadgeStatus(metadata[key]);
      return status ? { label, status } : null;
    })
    .filter((b): b is { label: string; status: BadgeStatus } => b !== null);

  if (badges.length === 0) return null;

  const evalScore = typeof metadata.eval_score === "number" ? metadata.eval_score : null;

  return (
    <span className="ml-2 inline-flex gap-1 items-center">
      {badges.map((b) => (
        <span
          key={b.label}
          className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${BADGE_STYLES[b.status]}`}
        >
          {BADGE_ICONS[b.status]} {b.label}
        </span>
      ))}
      {evalScore !== null && (
        <span className="text-[10px] px-1.5 py-0.5 rounded font-medium bg-blue-900/40 text-blue-400 border border-blue-700/50">
          {evalScore}%
        </span>
      )}
    </span>
  );
}

export default function TaskRow({ task }: TaskRowProps) {
  const icon = TASK_STATUS_ICONS[task.status] ?? "⏳";

  return (
    <tr className="border-b border-terminal-border/30 hover:bg-terminal-surface/20 transition-colors">
      <td className="px-4 py-1.5 text-xs pl-16">
        <span className="text-terminal-muted mr-1">⤷</span>
        <span className="font-mono">{task.task_id}</span>
        {task.task_title && (
          <span className="text-terminal-muted ml-1 truncate max-w-[200px] inline-block align-bottom">
            — {task.task_title}
          </span>
        )}
      </td>
      <td className="px-4 py-1.5 text-xs">
        {icon}{" "}
        <span
          className={
            task.status === "passed"
              ? "text-terminal-green"
              : task.status === "failed"
              ? "text-terminal-red"
              : task.status === "waiting"
              ? "text-terminal-yellow"
              : "text-terminal-text"
          }
        >
          {task.status.toUpperCase()}
        </span>
        <VerificationBadge metadata={task.metadata_json} />
      </td>
      <td className="px-4 py-1.5 text-xs text-center">
        {task.self_correction_loops > 0
          ? `${task.self_correction_loops} fix${task.self_correction_loops > 1 ? "es" : ""}`
          : "—"}
      </td>
      <td className="px-4 py-1.5 text-xs text-center">
        {task.metadata_json && typeof task.metadata_json.eval_score === "number"
          ? <span className="text-blue-400 font-mono">{task.metadata_json.eval_score}%</span>
          : <span className="text-terminal-muted">—</span>}
      </td>
      <td className="px-4 py-1.5 text-xs text-center font-mono">
        {task.tokens_in > 0 || task.tokens_out > 0
          ? `${formatTokens(task.tokens_in)} / ${formatTokens(task.tokens_out)}`
          : "—"}
      </td>
      <td className="px-4 py-1.5 text-xs text-terminal-muted">
        {task.agent_id || "—"}
      </td>
    </tr>
  );
}

function formatTokens(n: number): string {
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}
