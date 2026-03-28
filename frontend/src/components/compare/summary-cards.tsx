import clsx from "clsx";
import type { MultiCompareImageSnapshot } from "../../lib/api";
import { formatBytes, formatTimestamp } from "../../lib/format";

interface SummaryCardsProps {
  images: MultiCompareImageSnapshot[];
  winner: number;
}

export function SummaryCards({ images, winner }: SummaryCardsProps) {
  return (
    <>
    <div className={clsx("grid gap-4", images.length === 3 ? "lg:grid-cols-3" : "lg:grid-cols-2")}>
      {images.map((img, i) => {
        const isWinner = i === winner;
        const critical = img.vulnerability_summary.by_severity["CRITICAL"] ?? 0;
        const high = img.vulnerability_summary.by_severity["HIGH"] ?? 0;

        return (
          <div
            key={img.image_id}
            className={clsx(
              "relative rounded-xl border p-5 transition",
              isWinner
                ? "border-emerald-300 bg-emerald-50/50 dark:border-emerald-700 dark:bg-emerald-950/20"
                : "border-ink-200 bg-white dark:border-ink-800 dark:bg-ink-900"
            )}
          >
            {isWinner ? (
              <span className="absolute -top-2.5 right-3 rounded-full bg-emerald-500 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-white">
                Fewest CVEs
              </span>
            ) : null}

            <div className="flex items-center gap-2">
              <div className="h-3 w-3 flex-shrink-0 rounded-full" style={{ backgroundColor: img.color }} />
              <h3 className="truncate text-sm font-medium text-ink-900 dark:text-white" title={img.image_name}>
                {img.image_name}
              </h3>
            </div>

            {/* Main metric - Total CVEs */}
            <div className="mt-4">
              <p className="font-display text-4xl tracking-tight text-ink-900 dark:text-white">
                {img.vulnerability_summary.total}
              </p>
              <p className="text-xs uppercase tracking-wider text-ink-500 dark:text-ink-400">Total CVEs</p>
            </div>

            {/* Secondary metrics */}
            <div className="mt-4 grid grid-cols-2 gap-3">
              <div>
                <p className={clsx("font-display text-xl", critical > 0 ? "text-rose-600 dark:text-rose-400" : "text-ink-900 dark:text-white")}>
                  {critical}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-ink-500 dark:text-ink-400">Critical</p>
              </div>
              <div>
                <p className={clsx("font-display text-xl", high > 0 ? "text-amber-600 dark:text-amber-400" : "text-ink-900 dark:text-white")}>
                  {high}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-ink-500 dark:text-ink-400">High</p>
              </div>
              <div>
                <p className="font-display text-xl text-ink-900 dark:text-white">{img.package_count}</p>
                <p className="text-[10px] uppercase tracking-wider text-ink-500 dark:text-ink-400">Packages</p>
              </div>
              <div>
                <p className="font-display text-xl text-ink-900 dark:text-white">
                  {img.estimated_size > 0 ? formatBytes(img.estimated_size) : "N/A"}
                </p>
                <p className="text-[10px] uppercase tracking-wider text-ink-500 dark:text-ink-400">Image Size</p>
              </div>
            </div>

            {/* Scanners & freshness */}
            <div className="mt-4 flex flex-wrap items-center gap-1.5 border-t border-ink-200 pt-3 dark:border-ink-800">
              {(img.scanners ?? []).map((s) => (
                <span key={s} className="rounded bg-sky-100 px-1.5 py-0.5 text-[10px] font-medium text-sky-700 dark:bg-sky-950/70 dark:text-sky-200">
                  {s}
                </span>
              ))}
              <span className="ml-auto text-[10px] text-ink-400 dark:text-ink-500">{formatTimestamp(img.updated_at)}</span>
            </div>
          </div>
        );
      })}
    </div>
    <p className="mt-2 text-[11px] leading-relaxed text-ink-400 dark:text-ink-500">
      Results reflect raw scanner output. Vendor-specific VEX documents may adjust reported counts.
      Enable Trivy for additional coverage. Import VEX via the image detail page to suppress resolved advisories.
    </p>
    </>
  );
}
