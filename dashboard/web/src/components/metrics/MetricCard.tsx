interface MetricCardProps {
  label: string;
  value: string;
  subtext?: string;
}

export default function MetricCard({ label, value, subtext }: MetricCardProps) {
  return (
    <div className="bg-terminal-surface border border-terminal-border rounded px-4 py-3 flex flex-col items-center min-w-[160px]">
      <div className="text-terminal-muted text-xs uppercase tracking-wider mb-1">
        {label}
      </div>
      <div className="text-terminal-text text-lg font-bold">{value}</div>
      {subtext && (
        <div className="text-terminal-muted text-xs mt-0.5">{subtext}</div>
      )}
    </div>
  );
}
