import type { ArtifactEditsOut } from "@/types";
import { PHASE_DISPLAY_NAMES } from "@/types";
import type { PhaseName } from "@/types";

interface ArtifactEditsProps {
  data: ArtifactEditsOut | null;
}

const ARTIFACT_LABELS: Record<string, string> = {
  validation: "Validation",
  specs: "Specs",
  "repo-assessment": "Repo Assessment",
  plan: "Plan",
  tasks: "Tasks",
};

export default function ArtifactEdits({ data }: ArtifactEditsProps) {
  if (!data || data.artifacts.length === 0) {
    return (
      <section className="px-6 py-4 border-b border-terminal-border">
        <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
          Per-Artifact Edit Counts
        </div>
        <div className="text-terminal-muted text-sm text-center py-4">
          No artifact data available yet.
        </div>
      </section>
    );
  }

  return (
    <section className="px-6 py-4 border-b border-terminal-border">
      <div className="flex items-baseline gap-3 mb-3">
        <div className="text-terminal-muted text-xs uppercase tracking-wider font-bold">
          Per-Artifact Edit Counts
        </div>
        <span className="text-terminal-accent text-xs font-mono">
          Total: {data.total_edits}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left">
          <thead>
            <tr className="border-b-2 border-terminal-border text-terminal-muted text-xs uppercase">
              <th className="px-4 py-2">Artifact</th>
              <th className="px-4 py-2">Phase</th>
              <th className="px-4 py-2 text-center">Eval Refinements</th>
              <th className="px-4 py-2 text-center">User Feedback Rounds</th>
              <th className="px-4 py-2 text-center">Total Edits</th>
            </tr>
          </thead>
          <tbody>
            {data.artifacts.map((a) => (
              <tr
                key={a.artifact_id}
                className="border-b border-terminal-border hover:bg-terminal-surface/50 transition-colors"
              >
                <td className="px-4 py-2.5 text-sm font-mono">
                  {ARTIFACT_LABELS[a.artifact_id] ?? a.artifact_id}
                </td>
                <td className="px-4 py-2.5 text-sm text-terminal-muted">
                  {PHASE_DISPLAY_NAMES[a.phase_name as PhaseName] ?? a.phase_name}
                </td>
                <td className="px-4 py-2.5 text-sm text-center font-mono">
                  {a.eval_refinements}
                </td>
                <td className="px-4 py-2.5 text-sm text-center font-mono">
                  {a.feedback_rounds}
                </td>
                <td className="px-4 py-2.5 text-sm text-center font-bold">
                  <span
                    className={
                      a.total_edits > 3
                        ? "text-terminal-red"
                        : a.total_edits > 1
                        ? "text-terminal-yellow"
                        : "text-terminal-green"
                    }
                  >
                    {a.total_edits}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
