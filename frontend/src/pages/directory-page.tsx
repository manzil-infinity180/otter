import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { startTransition, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";

import { EmptyState } from "../components/empty-state";
import { SeverityPill } from "../components/severity-pill";
import { StatCard } from "../components/stat-card";
import { formatCompactNumber, formatTimestamp, vulnerabilityChips } from "../lib/format";
import { getScanJob, listCatalog, startScan } from "../lib/api";
import type { ScanJob, ScanJobStatus } from "../lib/types";

const severityOptions = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW"];
const sortOptions = [
  { value: "recent", label: "Most recent" },
  { value: "critical", label: "Critical exposure" },
  { value: "packages", label: "Package count" },
  { value: "name", label: "Repository" }
];

export function DirectoryPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [draftQuery, setDraftQuery] = useState(searchParams.get("query") ?? "");
  const [scanInput, setScanInput] = useState("");
  const [scanJobs, setScanJobs] = useState<ScanJob[]>([]);
  const completedJobs = useRef(new Set<string>());
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

  const scanMutation = useMutation({
    mutationFn: (imageName: string) => startScan(imageName),
    onSuccess: ({ job }) => {
      setScanJobs((current) => [job, ...current.filter((candidate) => candidate.id !== job.id)]);
      setScanInput("");
    }
  });

  const totals = useMemo(() => {
    const items = catalogQuery.data?.items ?? [];
    return items.reduce(
      (accumulator, item) => {
        accumulator.images += 1;
        accumulator.packages += item.package_count;
        accumulator.vulnerabilities += item.vulnerability_summary?.total ?? 0;
        accumulator.critical += item.vulnerability_summary?.by_severity?.CRITICAL ?? 0;
        return accumulator;
      },
      { images: 0, packages: 0, vulnerabilities: 0, critical: 0 }
    );
  }, [catalogQuery.data?.items]);

  const hasFilters = Boolean(deferredQuery || severity);

  return (
    <div className="space-y-8">
      <section className="overflow-hidden rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze backdrop-blur-xl dark:border-white/10 dark:bg-ink-900/80 sm:p-8">
        <div className="grid gap-8 xl:grid-cols-[1.15fr_0.85fr]">
          <div className="space-y-4">
            <p className="text-sm uppercase tracking-[0.26em] text-tide">Universal container image scanning</p>
            <h1 className="max-w-2xl font-display text-4xl tracking-tight text-ink-900 dark:text-white sm:text-5xl">
              Scan any public image, then inspect SBOMs, vulnerabilities, and attestations in one place.
            </h1>
            <p className="max-w-2xl text-base text-ink-600 dark:text-ink-300 sm:text-lg">
              Otter keeps the catalog for browsing, but manual scans are now first-class. Queue a new image, follow job status, and jump straight into the detail view when it finishes.
            </p>
          </div>
          <div className="space-y-4 rounded-[1.75rem] border border-ink-200/80 bg-white/80 p-5 shadow-haze dark:border-ink-800 dark:bg-ink-950/50">
            <div>
              <p className="text-sm uppercase tracking-[0.22em] text-ink-500 dark:text-ink-400">Scan a new image</p>
              <h2 className="mt-2 font-display text-2xl text-ink-900 dark:text-white">Start a public image scan</h2>
              <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">
                Try <span className="font-medium">nginx:latest</span>, <span className="font-medium">ghcr.io/owner/repo:tag</span>, or <span className="font-medium">cgr.dev/chainguard/static:latest</span>.
              </p>
            </div>
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                const imageName = scanInput.trim();
                if (!imageName) {
                  return;
                }
                scanMutation.mutate(imageName);
              }}
            >
              <label className="space-y-2">
                <span className="text-sm font-medium text-ink-600 dark:text-ink-300">Image reference</span>
                <input
                  aria-label="Scan image"
                  value={scanInput}
                  onChange={(event) => setScanInput(event.target.value)}
                  className="w-full rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 outline-none transition focus:border-tide focus:ring-2 focus:ring-sky-200 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white dark:focus:ring-sky-900"
                  placeholder="nginx:latest"
                />
              </label>
              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="submit"
                  disabled={scanMutation.isPending || !scanInput.trim()}
                  className="rounded-2xl bg-ink-900 px-5 py-3 text-sm font-medium text-white transition hover:bg-ink-800 disabled:cursor-not-allowed disabled:opacity-60 dark:bg-white dark:text-ink-900 dark:hover:bg-ink-100"
                >
                  {scanMutation.isPending ? "Queueing scan…" : "Scan image"}
                </button>
                <p className="text-xs text-ink-500 dark:text-ink-400">Scans run asynchronously and land in the default org.</p>
              </div>
            </form>
            {scanMutation.isError ? (
              <div className="rounded-2xl border border-rose/30 bg-rose/8 px-4 py-3 text-sm text-rose dark:text-rose/90">
                {formatScanError(scanMutation.error instanceof Error ? scanMutation.error.message : "The scan could not be queued.")}
              </div>
            ) : null}
          </div>
        </div>

        <div className="mt-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Images" value={formatCompactNumber(totals.images)} detail="Stored in the local index" />
          <StatCard label="Packages" value={formatCompactNumber(totals.packages)} detail="Across visible results" />
          <StatCard label="Vulnerabilities" value={formatCompactNumber(totals.vulnerabilities)} detail="Merged scanner findings" />
          <StatCard label="Critical" value={formatCompactNumber(totals.critical)} detail="Immediate review candidates" />
        </div>
      </section>

      {scanJobs.length ? (
        <section className="rounded-[2rem] border border-white/60 bg-white/75 p-5 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <h2 className="font-display text-2xl text-ink-900 dark:text-white">Active scan jobs</h2>
              <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Job status refreshes automatically until each scan succeeds or fails.</p>
            </div>
            <button
              type="button"
              onClick={() => setScanJobs((current) => current.filter((job) => job.status === "pending" || job.status === "running"))}
              className="text-sm text-ink-500 transition hover:text-ink-900 dark:text-ink-400 dark:hover:text-white"
            >
              Clear completed
            </button>
          </div>
          <div className="mt-5 grid gap-4 lg:grid-cols-2">
            {scanJobs.map((job) => (
              <ScanJobCard
                key={job.id}
                job={job}
                onUpdate={(updatedJob) => {
                  setScanJobs((current) => current.map((candidate) => (candidate.id === updatedJob.id ? updatedJob : candidate)));
                  if (updatedJob.status === "succeeded" && updatedJob.result && !completedJobs.current.has(updatedJob.id)) {
                    completedJobs.current.add(updatedJob.id);
                    void queryClient.invalidateQueries({ queryKey: ["catalog"] });
                    navigate(`/images/${updatedJob.result.org_id}/${updatedJob.result.image_id}`);
                  }
                }}
              />
            ))}
          </div>
        </section>
      ) : null}

      <section className="grid gap-4 rounded-[2rem] border border-white/60 bg-white/70 p-5 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80 lg:grid-cols-[minmax(0,1fr)_220px_220px]">
        <label className="space-y-2">
          <span className="text-sm font-medium text-ink-600 dark:text-ink-300">Filter catalog</span>
          <input
            aria-label="Filter catalog"
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
        hasFilters ? (
          <EmptyState title="No images matched the current filters" description="Try widening the severity filter or clearing the catalog filter." />
        ) : (
          <EmptyState
            title="No scanned images yet"
            description="Start with a public image scan above. Once a job succeeds, the image will appear here with SBOM, vulnerability, and attestation data."
          />
        )
      ) : null}

      <section className="grid gap-4 xl:grid-cols-2">
        {catalogQuery.data?.items.map((item) => (
          <Link
            key={`${item.org_id}/${item.image_id}`}
            to={`/images/${item.org_id}/${item.image_id}`}
            className="group rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze transition hover:-translate-y-0.5 hover:border-tide dark:border-white/10 dark:bg-ink-900/80"
          >
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="min-w-0 space-y-2">
                <p className="truncate text-sm uppercase tracking-[0.22em] text-ink-500 dark:text-ink-400" title={item.registry}>
                  {item.registry}
                </p>
                <h2 className="truncate font-display text-2xl tracking-tight text-ink-900 transition group-hover:text-tide dark:text-white">
                  {item.repository_path || item.image_name}
                </h2>
                <p className="truncate text-sm text-ink-600 dark:text-ink-300" title={item.image_name}>
                  {item.image_name}
                </p>
              </div>
              <div className="rounded-2xl bg-ink-900 px-3 py-2 text-right text-white dark:bg-white dark:text-ink-900">
                <p className="text-xs uppercase tracking-[0.22em]">Updated</p>
                <p className="text-sm font-medium">{formatTimestamp(item.updated_at)}</p>
              </div>
            </div>

            <div className="mt-5 flex flex-wrap gap-2">
              {item.tag ? <span className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">tag {item.tag}</span> : null}
              {(item.scanners ?? []).map((scanner) => (
                <span key={scanner} className="rounded-full bg-sky-100 px-3 py-1 text-xs font-medium text-sky-700 dark:bg-sky-950/70 dark:text-sky-200">
                  {scanner}
                </span>
              ))}
            </div>

            <div className="mt-6 grid gap-4 sm:grid-cols-3">
              <StatCard label="Packages" value={item.package_count} />
              <StatCard label="Vulnerabilities" value={item.vulnerability_summary?.total ?? 0} />
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

function ScanJobCard({
  job,
  onUpdate
}: {
  job: ScanJob;
  onUpdate: (job: ScanJob) => void;
}) {
  const lastSnapshot = useRef("");
  const jobQuery = useQuery({
    queryKey: ["scan-job", job.id],
    queryFn: () => getScanJob(job.id),
    initialData: { job, storage_backend: "local" },
    refetchInterval: (query) => {
      const status = query.state.data?.job.status;
      return status === "pending" || status === "running" ? 2000 : false;
    }
  });

  const currentJob = jobQuery.data?.job ?? job;

  useEffect(() => {
    const snapshot = JSON.stringify({
      id: currentJob.id,
      status: currentJob.status,
      error: currentJob.error,
      result: currentJob.result
    });
    if (snapshot === lastSnapshot.current) {
      return;
    }
    lastSnapshot.current = snapshot;
    onUpdate(currentJob);
  }, [currentJob, onUpdate]);

  const statusTone = statusClasses(currentJob.status);

  return (
    <article className="rounded-[1.75rem] border border-ink-200 bg-white/80 p-5 shadow-haze dark:border-ink-800 dark:bg-ink-950/50">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate font-display text-xl text-ink-900 dark:text-white" title={currentJob.request.image_name}>
            {currentJob.request.image_name}
          </p>
          <p className="mt-1 text-sm text-ink-500 dark:text-ink-400">{currentJob.request.org_id} / {currentJob.request.image_id}</p>
        </div>
        <span className={`rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.18em] ${statusTone}`}>
          {currentJob.status}
        </span>
      </div>

      <div className="mt-4 h-2 overflow-hidden rounded-full bg-ink-100 dark:bg-ink-800">
        <div className={`h-full rounded-full transition-all ${progressBarClasses(currentJob.status)}`} style={{ width: progressWidth(currentJob.status) }} />
      </div>

      <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{jobStatusMessage(currentJob)}</p>

      {currentJob.error ? (
        <p className="mt-3 rounded-2xl border border-rose/30 bg-rose/8 px-3 py-2 text-sm text-rose dark:text-rose/90">
          {formatScanError(currentJob.error)}
        </p>
      ) : null}
    </article>
  );
}

function statusClasses(status: ScanJobStatus) {
  switch (status) {
    case "succeeded":
      return "bg-mint/10 text-emerald-700 dark:text-emerald-300";
    case "failed":
      return "bg-rose/10 text-rose dark:text-rose/90";
    case "running":
      return "bg-sky-100 text-sky-700 dark:bg-sky-950/70 dark:text-sky-200";
    default:
      return "bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-200";
  }
}

function progressBarClasses(status: ScanJobStatus) {
  switch (status) {
    case "succeeded":
      return "bg-emerald-500";
    case "failed":
      return "bg-rose-500";
    default:
      return "bg-sky-500";
  }
}

function progressWidth(status: ScanJobStatus) {
  switch (status) {
    case "pending":
      return "28%";
    case "running":
      return "72%";
    default:
      return "100%";
  }
}

function jobStatusMessage(job: ScanJob) {
  switch (job.status) {
    case "pending":
      return "Queued and waiting for a scanner worker.";
    case "running":
      return "Scanning image layers, generating the SBOM, and merging vulnerability findings.";
    case "succeeded":
      return `Completed ${job.result?.completed_at ? formatTimestamp(job.result.completed_at) : "just now"}. Redirecting to the image detail view.`;
    case "failed":
      return "The scan did not complete.";
    default:
      return "Waiting for status.";
  }
}

function formatScanError(message: string) {
  const normalized = message.toLowerCase();
  if (normalized.includes("manifest_unknown") || normalized.includes("not found")) {
    return `Image not found. ${message}`;
  }
  if (normalized.includes("unauthorized") || normalized.includes("denied") || normalized.includes("auth")) {
    return `Registry authentication failed. ${message}`;
  }
  if (normalized.includes("deadline exceeded") || normalized.includes("timeout")) {
    return `Scanner timeout. ${message}`;
  }
  return message;
}
