import { useMemo, useState } from "react";
import type { MultiCompareImageSnapshot, VulnOverlapEntry } from "../../lib/api";
import type { Severity } from "../../lib/types";
import { SeverityPill } from "../severity-pill";

interface VulnOverlapProps {
  images: MultiCompareImageSnapshot[];
  vulns: VulnOverlapEntry[];
}

export function VulnOverlap({ images, vulns }: VulnOverlapProps) {
  const [filter, setFilter] = useState<"all" | "shared" | "unique">("all");
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const PAGE_SIZE = 25;

  const totalShared = useMemo(() => vulns.filter((v) => v.in_images.length === images.length).length, [vulns, images.length]);
  const totalUnique = useMemo(() => vulns.filter((v) => v.in_images.length === 1).length, [vulns]);

  const filtered = useMemo(() => {
    let result = vulns;
    if (filter === "shared") result = result.filter((v) => v.in_images.length === images.length);
    else if (filter === "unique") result = result.filter((v) => v.in_images.length === 1);
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((v) => v.id.toLowerCase().includes(q) || v.package_name.toLowerCase().includes(q));
    }
    return result;
  }, [vulns, filter, search, images.length]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const paginated = filtered.slice((safePage - 1) * PAGE_SIZE, safePage * PAGE_SIZE);

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="font-display text-lg text-ink-900 dark:text-white">Vulnerability Overlap</h3>
          <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">
            {vulns.length} total CVEs — {totalShared} shared across all images, {totalUnique} unique to one image
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <input
            type="text"
            placeholder="Search CVE or package..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setPage(1); }}
            className="rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 placeholder:text-ink-400 dark:border-ink-700 dark:bg-ink-800 dark:text-white"
          />
          <select
            value={filter}
            onChange={(e) => { setFilter(e.target.value as "all" | "shared" | "unique"); setPage(1); }}
            className="rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-800 dark:text-white"
          >
            <option value="all">All CVEs ({vulns.length})</option>
            <option value="shared">Shared ({totalShared})</option>
            <option value="unique">Unique ({totalUnique})</option>
          </select>
        </div>
      </div>

      {/* Summary bar */}
      {vulns.length > 0 ? (
        <div className="mt-4 flex h-4 overflow-hidden rounded-full bg-ink-100 dark:bg-ink-800">
          <div
            className="bg-amber-400 transition-all"
            style={{ width: `${(totalShared / vulns.length) * 100}%` }}
            title={`Shared: ${totalShared}`}
          />
          <div
            className="bg-sky-400 transition-all"
            style={{ width: `${(totalUnique / vulns.length) * 100}%` }}
            title={`Unique: ${totalUnique}`}
          />
          <div
            className="bg-ink-300 dark:bg-ink-600 transition-all"
            style={{ width: `${((vulns.length - totalShared - totalUnique) / vulns.length) * 100}%` }}
            title={`Partial overlap: ${vulns.length - totalShared - totalUnique}`}
          />
        </div>
      ) : null}
      <div className="mt-1 flex gap-4 text-[10px] text-ink-500 dark:text-ink-400">
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-amber-400" /> Shared</span>
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-sky-400" /> Unique</span>
        <span className="flex items-center gap-1"><span className="inline-block h-2 w-2 rounded-full bg-ink-300 dark:bg-ink-600" /> Partial</span>
      </div>

      {/* Table */}
      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="text-ink-500 dark:text-ink-400">
            <tr>
              <th className="pb-3 pr-4">Severity</th>
              <th className="pb-3 pr-4">CVE ID</th>
              <th className="pb-3 pr-4">Package</th>
              {images.map((img, i) => (
                <th key={i} className="pb-3 pr-4 text-center">
                  <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: img.color }} />
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
            {paginated.map((vuln) => (
              <tr key={vuln.id}>
                <td className="py-2 pr-4"><SeverityPill severity={vuln.severity as Severity} /></td>
                <td className="py-2 pr-4 font-medium text-ink-900 dark:text-white">{vuln.id}</td>
                <td className="py-2 pr-4 text-ink-600 dark:text-ink-300">{vuln.package_name}</td>
                {images.map((_, i) => (
                  <td key={i} className="py-2 pr-4 text-center text-lg">
                    {vuln.in_images.includes(i)
                      ? <span className="text-rose-500">&#x25CF;</span>
                      : <span className="text-emerald-500">&#x25CB;</span>
                    }
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
  );
}
