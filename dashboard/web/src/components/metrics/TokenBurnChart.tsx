import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import type { TokenBurnOut } from "@/types";

interface TokenBurnChartProps {
  data: TokenBurnOut | null;
}

const AGENT_COLORS: Record<string, string> = {
  Backend_Agent: "#58a6ff",
  DB_Agent: "#3fb950",
  Frontend_Agent: "#d29922",
  Operator_Agent: "#f85149",
  API_Agent: "#58a6ff",
  OperatorController_Agent: "#3fb950",
  Testing_Agent: "#d29922",
  ManifestsBindata_Agent: "#f85149",
};

function formatTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${Math.round(n / 1_000)}k`;
  return String(n);
}

export default function TokenBurnChart({ data }: TokenBurnChartProps) {
  if (!data || data.entries.length === 0) {
    return (
      <section className="px-6 py-4 border-b border-terminal-border">
        <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
          Token Burn per Worker Role (agents.md Tracking)
        </div>
        <div className="text-terminal-muted text-sm text-center py-8">
          No token data available.
        </div>
      </section>
    );
  }

  const chartData = data.entries.map((e) => ({
    name: e.agent_id || "Unknown Agent",
    tokens: e.tokens,
    cost: e.cost_usd,
    label: `${formatTokens(e.tokens)} Tokens (Cost: $${e.cost_usd.toFixed(2)})`,
  }));

  return (
    <section className="px-6 py-4 border-b border-terminal-border">
      <div className="text-terminal-muted text-xs uppercase tracking-wider mb-3 font-bold">
        {`Token Burn — Implementation Tasks (${formatTokens(data.total_tokens)} total, $${data.total_cost_usd.toFixed(2)})`}
      </div>
      <div className="h-48">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={chartData} layout="vertical" margin={{ left: 140 }}>
            <XAxis
              type="number"
              tickFormatter={formatTokens}
              stroke="#8b949e"
              fontSize={10}
            />
            <YAxis
              type="category"
              dataKey="name"
              stroke="#8b949e"
              fontSize={11}
              width={130}
              tick={{ fill: "#c9d1d9" }}
            />
            <Tooltip
              contentStyle={{
                background: "#161b22",
                border: "1px solid #30363d",
                borderRadius: 4,
                fontSize: 12,
                color: "#c9d1d9",
              }}
              formatter={(value: number) => [formatTokens(value), "Tokens"]}
            />
            <Bar dataKey="tokens" radius={[0, 4, 4, 0]}>
              {chartData.map((entry, i) => (
                <Cell
                  key={i}
                  fill={AGENT_COLORS[entry.name] || "#58a6ff"}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
