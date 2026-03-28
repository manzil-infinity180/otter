interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ name: string; value: number; color: string }>;
  label?: string;
}

export function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;

  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900 px-3 py-2 text-xs shadow-lg">
      <p className="mb-1.5 font-medium text-ink-300">{label}</p>
      {payload.map((entry) => (
        <div key={entry.name} className="flex items-center gap-2 py-0.5">
          <span className="inline-block h-2.5 w-2.5 flex-shrink-0 rounded-full" style={{ backgroundColor: entry.color }} />
          <span className="text-ink-400">{entry.name}</span>
          <span className="ml-auto font-medium text-white">{entry.value}</span>
        </div>
      ))}
    </div>
  );
}
