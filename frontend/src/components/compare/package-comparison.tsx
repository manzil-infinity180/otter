import { useMemo, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import type { MultiCompareImageSnapshot, PackageOverlapEntry } from "../../lib/api";

interface PackageComparisonProps {
  images: MultiCompareImageSnapshot[];
  packages: PackageOverlapEntry[];
}

export function PackageComparison({ images, packages }: PackageComparisonProps) {
  const [search, setSearch] = useState("");
  const [filter, setFilter] = useState<"all" | "shared" | "unique">("all");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 30;

  // Package count bar chart data
  const countData = images.map((img) => ({
    name: img.image_name.length > 30 ? img.image_name.slice(0, 30) + "..." : img.image_name,
    packages: img.package_count,
    fill: img.color,
  }));

  const filtered = useMemo(() => {
    let result = packages;
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((p) => p.name.toLowerCase().includes(q));
    }
    if (filter === "shared") {
      result = result.filter((p) => p.in_images.length === images.length);
    } else if (filter === "unique") {
      result = result.filter((p) => p.in_images.length === 1);
    }
    return result;
  }, [packages, search, filter, images.length]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paginated = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="space-y-6">
      {/* Package count chart */}
      <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h3 className="font-display text-lg text-ink-900 dark:text-white">Package Count</h3>
        <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">Fewer packages = smaller attack surface</p>
        <div className="mt-4" id="package-chart">
          <ResponsiveContainer width="100%" height={images.length * 60 + 40}>
            <BarChart data={countData} layout="vertical" margin={{ top: 5, right: 20, left: 10, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis type="number" tick={{ fontSize: 12 }} />
              <YAxis dataKey="name" type="category" tick={{ fontSize: 11 }} width={180} />
              <Tooltip contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", borderRadius: "8px", color: "#fff", fontSize: "12px" }} labelStyle={{ color: "#d4d4d8" }} itemStyle={{ color: "#fff" }} />
              <Bar dataKey="packages" radius={[0, 4, 4, 0]} maxBarSize={32}>
                {countData.map((entry, index) => (
                  <Cell key={index} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Package overlap table */}
      <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h3 className="font-display text-lg text-ink-900 dark:text-white">Package Comparison</h3>
            <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">{filtered.length} packages</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              type="text"
              placeholder="Search packages..."
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(1); }}
              className="rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 placeholder:text-ink-400 dark:border-ink-700 dark:bg-ink-800 dark:text-white"
            />
            <select
              value={filter}
              onChange={(e) => { setFilter(e.target.value as "all" | "shared" | "unique"); setPage(1); }}
              className="rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-800 dark:text-white"
            >
              <option value="all">All packages</option>
              <option value="shared">Shared only</option>
              <option value="unique">Unique only</option>
            </select>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead className="text-ink-500 dark:text-ink-400">
              <tr>
                <th className="pb-3 pr-4">Package</th>
                <th className="pb-3 pr-4">Type</th>
                {images.map((img, i) => (
                  <th key={i} className="pb-3 pr-4">
                    <span className="flex items-center gap-1.5">
                      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: img.color }} />
                      {img.image_name.length > 20 ? img.image_name.slice(0, 20) + "..." : img.image_name}
                    </span>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
              {paginated.map((pkg) => (
                <tr key={pkg.name}>
                  <td className="py-2 pr-4 font-medium text-ink-900 dark:text-white">{pkg.name}</td>
                  <td className="py-2 pr-4 text-ink-500 dark:text-ink-400">{pkg.type || "-"}</td>
                  {images.map((_, i) => (
                    <td key={i} className="py-2 pr-4 text-ink-600 dark:text-ink-300">
                      {pkg.versions[i] || <span className="text-ink-300 dark:text-ink-600">-</span>}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {totalPages > 1 ? (
          <div className="mt-4 flex items-center justify-between text-sm text-ink-600 dark:text-ink-300">
            <p>Showing {(safePage - 1) * PAGE_SIZE + 1}-{Math.min(safePage * PAGE_SIZE, filtered.length)} of {filtered.length}</p>
            <div className="flex gap-2">
              <button type="button" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={safePage === 1} className="rounded border border-ink-200 px-3 py-1 text-xs disabled:opacity-50 dark:border-ink-700">Previous</button>
              <button type="button" onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={safePage >= totalPages} className="rounded border border-ink-200 px-3 py-1 text-xs disabled:opacity-50 dark:border-ink-700">Next</button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}
