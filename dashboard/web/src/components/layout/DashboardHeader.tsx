interface DashboardHeaderProps {
  branch: string;
  runId?: string | null;
}

export default function DashboardHeader({ branch, runId }: DashboardHeaderProps) {
  async function exportReport() {
    if (!runId) return;
    const { fetchRunReport } = await import("@/services/api");
    const report = await fetchRunReport(runId);
    const blob = new Blob([JSON.stringify(report, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `run-report-${runId.slice(0, 8)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <header className="bg-terminal-surface border-b border-terminal-border px-6 py-3 flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="text-terminal-accent font-bold text-sm tracking-wider">
          [SDLC OBSERVABILITY]
        </span>
        <span className="text-terminal-text font-bold text-sm">
          AGENTIC AI DEVELOPMENT PIPELINE DASHBOARD
        </span>
      </div>
      <div className="flex items-center gap-4">
        {runId && (
          <button
            type="button"
            onClick={() => void exportReport()}
            className="text-xs border border-terminal-border rounded px-2 py-1 text-terminal-muted hover:text-terminal-accent hover:border-terminal-accent transition-colors"
          >
            Export JSON
          </button>
        )}
        {branch && (
          <div className="text-terminal-muted text-xs">
            Branch:{" "}
            <span className="text-terminal-accent font-medium">{branch}</span>
          </div>
        )}
      </div>
    </header>
  );
}
