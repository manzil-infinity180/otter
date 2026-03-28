import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import type { MultiCompareImageSnapshot, SeverityDataPoint } from "../../lib/api";

interface SeverityChartProps {
  data: SeverityDataPoint[];
  images: MultiCompareImageSnapshot[];
}

export function SeverityChart({ data, images }: SeverityChartProps) {
  const chartData = data
    .filter((d) => d.counts.some((c) => c > 0))
    .map((d) => {
      const point: Record<string, string | number> = { severity: d.severity };
      images.forEach((img, i) => {
        point[img.image_name] = d.counts[i] ?? 0;
      });
      return point;
    });

  if (chartData.length === 0) {
    return (
      <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h3 className="font-display text-lg text-ink-900 dark:text-white">CVEs by Severity</h3>
        <p className="mt-3 text-sm text-ink-500 dark:text-ink-400">No vulnerabilities to compare.</p>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900" id="severity-chart">
      <h3 className="font-display text-lg text-ink-900 dark:text-white">CVEs by Severity</h3>
      {/* Legend for export (always visible) */}
      <div className="mt-3 flex flex-wrap gap-4">
        {images.map((img) => (
          <span key={img.image_name} className="flex items-center gap-1.5 text-xs text-ink-600 dark:text-ink-300">
            <span className="inline-block h-3 w-3 rounded" style={{ backgroundColor: img.color }} />
            {img.image_name}
          </span>
        ))}
      </div>
      <div className="mt-3">
        <ResponsiveContainer width="100%" height={320}>
          <BarChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis dataKey="severity" tick={{ fontSize: 12 }} />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                border: "1px solid #3f3f46",
                borderRadius: "8px",
                color: "#fff",
                fontSize: "12px",
              }}
            />
            {images.map((img) => (
              <Bar
                key={img.image_name}
                dataKey={img.image_name}
                fill={img.color}
                radius={[4, 4, 0, 0]}
                maxBarSize={48}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
