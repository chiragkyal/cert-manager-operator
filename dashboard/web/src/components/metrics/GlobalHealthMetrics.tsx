import type { GlobalHealthMetrics as Metrics } from "@/types";
import MetricCard from "./MetricCard";

interface GlobalHealthMetricsProps {
  metrics: Metrics | null;
}

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function formatTime(seconds: number): string {
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s.toString().padStart(2, "0")}s`;
}

function formatCost(usd: number): string {
  return `$${usd.toFixed(2)} USD`;
}

export default function GlobalHealthMetrics({ metrics }: GlobalHealthMetricsProps) {
  if (!metrics) {
    return (
      <section className="px-6 py-4">
        <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
          Global Health Metrics
        </div>
        <div className="flex gap-3 flex-wrap">
          <MetricCard label="Total Tokens Consumed" value="—" />
          <MetricCard label="Total Run Cost" value="—" />
          <MetricCard label="Cumulative Wall Time" value="—" />
          <MetricCard label="Avg Quality Score" value="—" />
          <MetricCard label="Gate Passing Rate" value="—" />
          <MetricCard label="Refinement Iterations" value="—" />
          <MetricCard label="Agent Success Rate" value="—" />
        </div>
      </section>
    );
  }

  return (
    <section className="px-6 py-4 border-b border-terminal-border">
      <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
        Global Health Metrics
      </div>
      <div className="flex gap-3 flex-wrap">
        <MetricCard
          label="Total Tokens Consumed"
          value={`${formatTokens(metrics.total_tokens_consumed)} Tokens`}
          subtext="Planning phases (1-4)"
        />
        <MetricCard
          label="Total Run Cost"
          value={formatCost(metrics.total_run_cost_usd)}
        />
        <MetricCard
          label="Cumulative Wall Time"
          value={formatTime(metrics.cumulative_wall_time_s)}
          subtext="Since run start"
        />
        <MetricCard
          label="Avg Quality Score"
          value={`${metrics.compliance_index}%`}
          subtext="Across eval gates"
        />
        <MetricCard
          label="Gate Passing Rate"
          value={`${metrics.gate_passing_rate}%`}
          subtext="First-pass phases"
        />
        <MetricCard
          label="Refinement Iterations"
          value={String(metrics.total_refinement_iterations)}
          subtext={`${metrics.human_rejection_rate}% rejection proxy`}
        />
        <MetricCard
          label="Agent Success Rate"
          value={`${metrics.agent_success_rate}%`}
          subtext={`(${metrics.tasks_passed}/${metrics.tasks_total} Tasks)`}
        />
      </div>
    </section>
  );
}
