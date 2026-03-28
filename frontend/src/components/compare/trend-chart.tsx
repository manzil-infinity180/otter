import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from "recharts";
import type { MultiCompareImageSnapshot } from "../../lib/api";

interface TrendChartProps {
  images: MultiCompareImageSnapshot[];
}

export function TrendChart({ images }: TrendChartProps) {
  // Merge all trend points onto a unified timeline
  const hasTrend = images.some((img) => (img.trend?.length ?? 0) > 1);
  if (!hasTrend) {
    return (
      <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h3 className="font-display text-lg text-ink-900 dark:text-white">Vulnerability Trend</h3>
        <p className="mt-3 text-sm text-ink-500 dark:text-ink-400">
          Trend data requires multiple scans over time. Scan these images again later to see trend lines.
        </p>
      </div>
    );
  }

  // Build unified timeline
  const timeMap = new Map<string, { ts: number;[key: string]: number }>();
  images.forEach((img) => {
    (img.trend ?? []).forEach((point) => {
      const date = point.observed_at.split("T")[0];
      if (!timeMap.has(date)) {
        timeMap.set(date, { ts: new Date(point.observed_at).getTime() });
      }
      timeMap.get(date)![img.image_name] = point.total;
    });
  });

  const chartData = Array.from(timeMap.entries())
    .map(([date, values]) => ({ date, ...values }))
    .sort((a, b) => a.ts - b.ts);

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <h3 className="font-display text-lg text-ink-900 dark:text-white">Vulnerability Trend</h3>
      <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">Total CVE count over time — like star-history, but for security</p>
      <div className="mt-4" id="trend-chart">
        <ResponsiveContainer width="100%" height={320}>
          <LineChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis dataKey="date" tick={{ fontSize: 11 }} />
            <YAxis tick={{ fontSize: 12 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                border: "1px solid #3f3f46",
                borderRadius: "8px",
                color: "#fff",
                fontSize: "12px",
              }}
              labelStyle={{ color: "#d4d4d8" }}
              itemStyle={{ color: "#fff" }}
            />
            <Legend wrapperStyle={{ fontSize: "12px" }} />
            {images.map((img) => (
              <Line
                key={img.image_name}
                type="monotone"
                dataKey={img.image_name}
                stroke={img.color}
                strokeWidth={2.5}
                dot={{ r: 4 }}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
