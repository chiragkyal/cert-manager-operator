import type { PipelineRun, RunStatus } from "@/types";

const STATUS_DISPLAY: Record<RunStatus, { label: string; icon: string; color: string }> = {
  running: { label: "RUNNING", icon: "🟢", color: "text-terminal-green" },
  waiting_for_human: { label: "WAITING FOR HUMAN REVIEW", icon: "🟡", color: "text-terminal-yellow" },
  completed: { label: "COMPLETED", icon: "✅", color: "text-terminal-green" },
  failed: { label: "FAILED", icon: "🔴", color: "text-terminal-red" },
};

interface PipelineStatusBannerProps {
  run: PipelineRun | null;
}

function formatStartDate(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const day = String(d.getDate()).padStart(2, "0");
  const month = d.toLocaleString("en-US", { month: "long" });
  const hours = String(d.getHours()).padStart(2, "0");
  const minutes = String(d.getMinutes()).padStart(2, "0");
  return `${day}-${month}-${d.getFullYear()} ${hours}:${minutes}`;
}

export default function PipelineStatusBanner({ run }: PipelineStatusBannerProps) {
  if (!run) {
    return (
      <div className="bg-terminal-surface border-b border-terminal-border px-6 py-3 text-terminal-muted text-sm">
        No active pipeline run selected.
      </div>
    );
  }

  const display = STATUS_DISPLAY[run.status];
  const startDate = formatStartDate(run.started_at);

  return (
    <div className="bg-terminal-surface border-b border-terminal-border px-6 py-3 flex flex-wrap items-center gap-x-8 gap-y-2">
      <div className="text-sm">
        <span className="text-terminal-muted">[ ACTIVE FEATURE ]:</span>{" "}
        <span className="text-terminal-text font-bold">
          {run.jira_key} - {run.change_name}
        </span>
        {startDate && (
          <>
            <span className="text-terminal-muted"> · Started: </span>
            <span className="text-terminal-text">{startDate}</span>
          </>
        )}
      </div>
      <div className="text-sm">
        <span className="text-terminal-muted">[ PIPELINE STATUS ]:</span>{" "}
        <span className={display.color}>
          {display.icon} {display.label}
        </span>
      </div>
    </div>
  );
}
