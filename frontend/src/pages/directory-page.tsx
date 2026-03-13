import { useQuery } from "@tanstack/react-query";
import { startTransition, useDeferredValue, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { EmptyState } from "../components/empty-state";
import { SeverityPill } from "../components/severity-pill";
import { StatCard } from "../components/stat-card";
import { formatCompactNumber, formatTimestamp, vulnerabilityChips } from "../lib/format";
import { listCatalog } from "../lib/api";

const severityOptions = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const sortOptions = [
  { value: "recent", label: "Most recent" },
  { value: "critical", label: "Critical exposure" },
  { value: "packages", label: "Package count" },
  { value: "name", label: "Repository" }
];

export function DirectoryPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [draftQuery, setDraftQuery] = useState(searchParams.get("query") ?? "");
  const deferredQuery = useDeferredValue(draftQuery.trim());
  const severity = searchParams.get("severity") ?? "";
  const sort = searchParams.get("sort") ?? "recent";

  useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (deferredQuery) {
      next.set("query", deferredQuery);
    } else {
      next.delete("query");
    }
    if (next.toString() === searchParams.toString()) {
      return;
    }
    startTransition(() => {
      setSearchParams(next, { replace: true });
    });
  }, [deferredQuery, searchParams, setSearchParams]);

  const catalogQuery = useQuery({
    queryKey: ["catalog", deferredQuery, severity, sort],
    queryFn: () =>
      listCatalog({
        query: deferredQuery || undefined,
        severity: severity || undefined,
        sort
      })
  });

  const totals = useMemo(() => {
    const items = catalogQuery.data?.items ?? [];
    return items.reduce(
      (accumulator, item) => {
        accumulator.images += 1;
        accumulator.packages += item.package_count;
        accumulator.vulnerabilities += item.vulnerability_summary.total;
        accumulator.critical += item.vulnerability_summary.by_severity.CRITICAL ?? 0;
        return accumulator;
      },
      { images: 0, packages: 0, vulnerabilities: 0, critical: 0 }
    );
  }, [catalogQuery.data?.items]);

  return (
    <div className="space-y-8">
      <section className="overflow-hidden rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze backdrop-blur-xl dark:border-white/10 dark:bg-ink-900/80 sm:p-8">
        <div className="grid gap-8 lg:grid-cols-[1.3fr_0.9fr]">
          <div className="space-y-4">
            <p className="text-sm uppercase tracking-[0.26em] text-tide">Local-first image directory</p>
            <h1 className="max-w-2xl font-display text-4xl tracking-tight text-ink-900 dark:text-white sm:text-5xl">
              Audit tags, compare drift, and read SBOM and attestation data without leaving one screen.
            </h1>
            <p className="max-w-2xl text-base text-ink-600 dark:text-ink-300 sm:text-lg">
              Otter’s catalog is designed around dense scan intelligence: packages, vulnerability posture, attestation metadata, and tag-level history.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <StatCard label="Images" value={formatCompactNumber(totals.images)} detail="Stored in the local index" />
            <StatCard label="Packages" value={formatCompactNumber(totals.packages)} detail="Across visible results" />
            <StatCard label="Vulnerabilities" value={formatCompactNumber(totals.vulnerabilities)} detail="Merged scanner findings" />
            <StatCard label="Critical" value={formatCompactNumber(totals.critical)} detail="Immediate review candidates" />
          </div>
        </div>
      </section>

      <section className="grid gap-4 rounded-[2rem] border border-white/60 bg-white/70 p-5 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80 lg:grid-cols-[minmax(0,1fr)_220px_220px]">
        <label className="space-y-2">
          <span className="text-sm font-medium text-ink-600 dark:text-ink-300">Search repository, tag, digest, or image ID</span>
          <input
            aria-label="Search images"
            value={draftQuery}
            onChange={(event) => setDraftQuery(event.target.value)}
            className="w-full rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 outline-none transition focus:border-tide focus:ring-2 focus:ring-sky-200 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white dark:focus:ring-sky-900"
            placeholder="alpine, chainguard/static, latest"
          />
        </label>
        <label className="space-y-2">
          <span className="text-sm font-medium text-ink-600 dark:text-ink-300">Minimum severity</span>
          <select
            aria-label="Filter by severity"
            value={severity}
            onChange={(event) => {
              const next = new URLSearchParams(searchParams);
              if (event.target.value) {
                next.set("severity", event.target.value);
              } else {
                next.delete("severity");
              }
              setSearchParams(next, { replace: true });
            }}
            className="w-full rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 outline-none transition focus:border-tide dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
          >
            {severityOptions.map((option) => (
              <option key={option || "all"} value={option}>
                {option || "All severities"}
              </option>
            ))}
          </select>
        </label>
        <label className="space-y-2">
          <span className="text-sm font-medium text-ink-600 dark:text-ink-300">Sort results</span>
          <select
            aria-label="Sort images"
            value={sort}
            onChange={(event) => {
              const next = new URLSearchParams(searchParams);
              next.set("sort", event.target.value);
              setSearchParams(next, { replace: true });
            }}
            className="w-full rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 outline-none transition focus:border-tide dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
          >
            {sortOptions.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
      </section>

      {catalogQuery.isLoading ? (
        <section className="rounded-[2rem] border border-white/60 bg-white/75 p-8 text-sm text-ink-600 shadow-haze dark:border-white/10 dark:bg-ink-900/80 dark:text-ink-300">
          Loading the image directory…
        </section>
      ) : null}

      {catalogQuery.isError ? (
        <EmptyState
          title="Catalog request failed"
          description={catalogQuery.error instanceof Error ? catalogQuery.error.message : "The catalog could not be loaded."}
        />
      ) : null}

      {!catalogQuery.isLoading && !catalogQuery.isError && (catalogQuery.data?.items.length ?? 0) === 0 ? (
        <EmptyState title="No images matched the current filters" description="Try widening the severity filter or clearing the search term." />
      ) : null}

      <section className="grid gap-4 xl:grid-cols-2">
        {catalogQuery.data?.items.map((item) => (
          <Link
            key={`${item.org_id}/${item.image_id}`}
            to={`/images/${item.org_id}/${item.image_id}`}
            className="group rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze transition hover:-translate-y-0.5 hover:border-tide dark:border-white/10 dark:bg-ink-900/80"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="space-y-2">
                <p className="text-sm uppercase tracking-[0.22em] text-ink-500 dark:text-ink-400">{item.registry}</p>
                <h2 className="font-display text-2xl tracking-tight text-ink-900 transition group-hover:text-tide dark:text-white">
                  {item.repository_path || item.image_name}
                </h2>
                <p className="text-sm text-ink-600 dark:text-ink-300">{item.image_name}</p>
              </div>
              <div className="rounded-2xl bg-ink-900 px-3 py-2 text-right text-white dark:bg-white dark:text-ink-900">
                <p className="text-xs uppercase tracking-[0.22em]">Updated</p>
                <p className="text-sm font-medium">{formatTimestamp(item.updated_at)}</p>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {item.tag ? <span className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">tag {item.tag}</span> : null}
              {item.scanners.map((scanner) => (
                <span key={scanner} className="rounded-full bg-sky-100 px-3 py-1 text-xs font-medium text-sky-700 dark:bg-sky-950/70 dark:text-sky-200">
                  {scanner}
                </span>
              ))}
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              <StatCard label="Packages" value={item.package_count} />
              <StatCard label="Vulnerabilities" value={item.vulnerability_summary.total} />
              <StatCard label="Org / ID" value={item.org_id} detail={item.image_id} />
            </div>

            <div className="mt-6 flex flex-wrap gap-2">
              {vulnerabilityChips(item.vulnerability_summary).map((chip) => (
                <SeverityPill key={chip.severity} severity={chip.severity} count={chip.count} />
              ))}
            </div>
          </Link>
        ))}
      </section>
    </div>
  );
}
