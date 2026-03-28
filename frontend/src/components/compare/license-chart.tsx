import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer, Cell } from "recharts";
import type { MultiCompareImageSnapshot, LicenseDataPoint } from "../../lib/api";

interface LicenseChartProps {
  data: LicenseDataPoint[];
  images: MultiCompareImageSnapshot[];
}

export function LicenseChart({ data, images }: LicenseChartProps) {
  if (!data.length) return null;

  const chartData = data.slice(0, 15).map((d) => {
    const point: Record<string, string | number | boolean> = {
      license: d.license.length > 18 ? d.license.slice(0, 18) + "..." : d.license,
      fullLicense: d.license,
      isCopyleft: d.is_copyleft,
    };
    images.forEach((img, i) => {
      point[img.image_name] = d.counts[i] ?? 0;
    });
    return point;
  });

  const hasCopyleft = data.some((d) => d.is_copyleft);

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <div className="flex items-center gap-3">
        <h3 className="font-display text-lg text-ink-900 dark:text-white">License Distribution</h3>
        {hasCopyleft ? (
          <span className="rounded-full bg-rose-100 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-700 dark:bg-rose-950 dark:text-rose-300">
            Copyleft detected
          </span>
        ) : null}
      </div>
      <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">
        Package count by license type — copyleft licenses (GPL, AGPL, LGPL) are flagged
      </p>
      <div className="mt-4" id="license-chart">
        <ResponsiveContainer width="100%" height={Math.max(320, chartData.length * 28 + 40)}>
          <BarChart data={chartData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis type="number" tick={{ fontSize: 12 }} />
            <YAxis
              dataKey="license"
              type="category"
              tick={{ fontSize: 11 }}
              width={160}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: "#18181b",
                border: "1px solid #3f3f46",
                borderRadius: "8px",
                color: "#fff",
                fontSize: "12px",
              }}
            />
            <Legend wrapperStyle={{ fontSize: "12px" }} />
            {images.map((img) => (
              <Bar key={img.image_name} dataKey={img.image_name} fill={img.color} radius={[0, 4, 4, 0]} maxBarSize={20} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
