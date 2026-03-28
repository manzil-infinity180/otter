import { useMutation, useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";

import { ComplianceComparison } from "../components/compare/compliance-comparison";
import { ExportToolbar } from "../components/compare/export-toolbar";
import { ImageSelector } from "../components/compare/image-selector";
import { LicenseChart } from "../components/compare/license-chart";
import { PackageComparison } from "../components/compare/package-comparison";
import { SeverityChart } from "../components/compare/severity-chart";
import { SummaryCards } from "../components/compare/summary-cards";
import { TrendChart } from "../components/compare/trend-chart";
import { VulnOverlap } from "../components/compare/vuln-overlap";
import { getMultiComparePresets, getScanJob, multiCompare, startScan } from "../lib/api";
import type { MultiCompareImage } from "../lib/api";

interface ScanProgress {
  imageName: string;
  jobId: string;
  status: "pending" | "running" | "succeeded" | "failed";
}

export function ComparePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [images, setImages] = useState<MultiCompareImage[]>(() => {
    const restored: MultiCompareImage[] = [];
    for (let i = 1; i <= 3; i++) {
      const name = searchParams.get(`image${i}`);
      if (name) restored.push({ name });
    }
    return restored;
  });
  const [scanProgress, setScanProgress] = useState<ScanProgress[]>([]);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const presetsQuery = useQuery({
    queryKey: ["multi-compare-presets"],
    queryFn: getMultiComparePresets,
    staleTime: 60 * 60 * 1000,
  });

  const compareMutation = useMutation({
    mutationFn: (imgs: MultiCompareImage[]) => multiCompare(imgs),
    onSuccess: (_, imgs) => {
      // Sync URL params
      const next = new URLSearchParams();
      imgs.forEach((img, i) => next.set(`image${i + 1}`, img.name));
      setSearchParams(next, { replace: true });
    },
  });

  // Auto-compare if URL has images on first load
  useEffect(() => {
    if (images.length >= 2 && images.every((img) => img.name.trim()) && !compareMutation.data) {
      compareMutation.mutate(images);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Auto-scan missing images, then retry comparison
  const handleAutoScan = useCallback(async (missingImageNames: string[]) => {
    const progress: ScanProgress[] = [];
    for (const name of missingImageNames) {
      try {
        const result = await startScan(name);
        progress.push({ imageName: name, jobId: result.job.id, status: "pending" });
      } catch {
        progress.push({ imageName: name, jobId: "", status: "failed" });
      }
    }
    setScanProgress(progress);

    // Poll scan jobs
    if (pollRef.current) clearInterval(pollRef.current);
    pollRef.current = setInterval(async () => {
      const updated = await Promise.all(
        progress.map(async (sp) => {
          if (sp.status === "succeeded" || sp.status === "failed" || !sp.jobId) return sp;
          try {
            const job = await getScanJob(sp.jobId);
            return { ...sp, status: job.job.status as ScanProgress["status"] };
          } catch {
            return sp;
          }
        })
      );
      setScanProgress(updated);

      const allDone = updated.every((sp) => sp.status === "succeeded" || sp.status === "failed");
      if (allDone) {
        if (pollRef.current) clearInterval(pollRef.current);
        pollRef.current = null;
        const allSucceeded = updated.every((sp) => sp.status === "succeeded");
        if (allSucceeded) {
          // Retry comparison
          setTimeout(() => {
            setScanProgress([]);
            compareMutation.mutate(images);
          }, 1000);
        }
      }
    }, 3000);
  }, [images, compareMutation]);

  // Cleanup poll on unmount
  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  // Update document title
  useEffect(() => {
    const report = compareMutation.data?.report;
    if (report) {
      document.title = `Compare: ${report.images.map((img) => img.image_name).join(" vs ")} - Otter`;
    } else {
      document.title = "Compare Images - Otter";
    }
    return () => { document.title = "Otter"; };
  }, [compareMutation.data]);

  const report = compareMutation.data?.report;

  return (
    <div className="space-y-6">
      {/* Hero header */}
      <section className="rounded-xl border border-ink-200 bg-gradient-to-br from-ink-900 to-ink-800 p-6 text-white sm:p-8 dark:from-ink-950 dark:to-ink-900">
        <p className="text-sm font-medium uppercase tracking-wider text-sky-300">Multi-Image Comparison</p>
        <h1 className="mt-2 font-display text-3xl tracking-tight sm:text-4xl">
          Compare container images side by side
        </h1>
        <p className="mt-2 max-w-2xl text-base text-ink-300">
          Evaluate the security posture of 2-3 images simultaneously. Compare vulnerabilities, packages, and supply chain attestations with visual charts you can download and share.
        </p>
      </section>

      {/* Image selector */}
      <ImageSelector
        images={images}
        presets={presetsQuery.data?.presets ?? []}
        onImagesChange={setImages}
        onCompare={() => compareMutation.mutate(images)}
        isComparing={compareMutation.isPending}
      />

      {/* Auto-scan progress */}
      {scanProgress.length > 0 ? (
        <div className="rounded-xl border border-sky-300 bg-sky-50 p-5 dark:border-sky-800 dark:bg-sky-950/30">
          <p className="text-sm font-medium text-sky-900 dark:text-sky-200">Scanning missing images...</p>
          <p className="mt-1 text-xs text-sky-700 dark:text-sky-300">The comparison will start automatically when all scans complete.</p>
          <div className="mt-3 space-y-2">
            {scanProgress.map((sp) => (
              <div key={sp.jobId} className="flex items-center gap-2 text-sm">
                <span className={`inline-block h-2 w-2 rounded-full ${sp.status === "succeeded" ? "bg-emerald-500" : sp.status === "failed" ? "bg-rose-500" : "animate-pulse bg-amber-500"}`} />
                <span className="text-sky-800 dark:text-sky-200">{sp.imageName}</span>
                <span className="text-xs text-sky-600 dark:text-sky-400">({sp.status})</span>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {/* Error state with auto-scan option */}
      {compareMutation.isError ? (
        <AutoScanError
          error={compareMutation.error}
          allImages={images}
          onScanAndRetry={(missingImages) => {
            handleAutoScan(missingImages);
          }}
        />
      ) : null}

      {/* Loading skeleton */}
      {compareMutation.isPending ? (
        <div className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-2">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="h-48 animate-pulse rounded-xl border border-ink-200 bg-ink-50 dark:border-ink-800 dark:bg-ink-950" />
            ))}
          </div>
          <div className="h-80 animate-pulse rounded-xl border border-ink-200 bg-ink-50 dark:border-ink-800 dark:bg-ink-950" />
        </div>
      ) : null}

      {/* Results */}
      {report ? (
        <>
          {/* Export toolbar */}
          <ExportToolbar report={report} />

          {/* Summary cards */}
          <SummaryCards images={report.images} winner={report.winner} />

          {/* Pairwise deltas */}
          <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
            <h3 className="font-display text-lg text-ink-900 dark:text-white">Pairwise Differences</h3>
            <div className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {report.pairwise_diffs.map((diff, i) => {
                const img1 = report.images[diff.image1_index];
                const img2 = report.images[diff.image2_index];
                return (
                  <div key={i} className="rounded-lg border border-ink-200 p-4 dark:border-ink-800">
                    <div className="flex items-center gap-2 text-xs font-medium text-ink-600 dark:text-ink-300">
                      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: img1.color }} />
                      <span className="truncate">{img1.image_name}</span>
                      <span className="text-ink-400">vs</span>
                      <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: img2.color }} />
                      <span className="truncate">{img2.image_name}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                      <div>
                        <p className="font-display text-lg text-emerald-600 dark:text-emerald-400">+{diff.vulns_fixed}</p>
                        <p className="text-[10px] uppercase text-ink-500">Fixed</p>
                      </div>
                      <div>
                        <p className="font-display text-lg text-rose-600 dark:text-rose-400">+{diff.vulns_new}</p>
                        <p className="text-[10px] uppercase text-ink-500">New</p>
                      </div>
                      <div>
                        <p className="font-display text-lg text-ink-600 dark:text-ink-300">{diff.packages_changed}</p>
                        <p className="text-[10px] uppercase text-ink-500">Pkg changes</p>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Severity chart */}
          <SeverityChart data={report.chart_data.severity_breakdown} images={report.images} />

          {/* Trend chart */}
          <TrendChart images={report.images} />

          {/* Vulnerability overlap */}
          {report.chart_data.vuln_overlap?.length ? (
            <VulnOverlap images={report.images} vulns={report.chart_data.vuln_overlap} />
          ) : null}

          {/* Package comparison */}
          <PackageComparison images={report.images} packages={report.chart_data.package_overlap} />

          {/* License comparison */}
          {report.chart_data.license_breakdown?.length ? (
            <LicenseChart data={report.chart_data.license_breakdown} images={report.images} />
          ) : null}

          {/* Compliance comparison */}
          <ComplianceComparison images={report.images} />
        </>
      ) : null}
    </div>
  );
}

// Auto-scan error component with "Scan and Retry" button
function AutoScanError({ error, allImages, onScanAndRetry }: {
  error: unknown;
  allImages: MultiCompareImage[];
  onScanAndRetry: (images: string[]) => void;
}) {
  const errorMsg = error instanceof Error ? error.message : "An error occurred";
  const isNotFound = errorMsg.includes("not found");

  return (
    <div className="rounded-xl border border-rose-300 bg-rose-50 p-5 dark:border-rose-800 dark:bg-rose-950/30">
      <p className="text-sm font-medium text-rose-900 dark:text-rose-200">Comparison failed</p>
      <p className="mt-1 text-sm text-rose-700 dark:text-rose-300">{errorMsg}</p>
      {isNotFound ? (
        <p className="mt-1 text-xs text-rose-600 dark:text-rose-400">
          Some images haven't been scanned yet. Click below to scan them — the comparison will start automatically when done.
        </p>
      ) : null}
      <div className="mt-3 flex flex-wrap gap-2">
        {isNotFound ? (
          <button
            type="button"
            onClick={() => onScanAndRetry(allImages.map((img) => img.name))}
            className="rounded-md bg-tide px-4 py-2 text-sm font-medium text-white transition hover:bg-sky-600"
          >
            Scan all images and retry
          </button>
        ) : null}
        <Link
          to="/directory"
          className="rounded-md border border-rose-300 px-4 py-2 text-sm font-medium text-rose-700 transition hover:bg-rose-100 dark:border-rose-700 dark:text-rose-300 dark:hover:bg-rose-950"
        >
          Go to Directory to scan images
        </Link>
      </div>
    </div>
  );
}
