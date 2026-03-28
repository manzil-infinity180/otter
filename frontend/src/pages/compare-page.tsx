import { useMutation, useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";

import { ComplianceComparison } from "../components/compare/compliance-comparison";
import { ExportToolbar } from "../components/compare/export-toolbar";
import { ImageSelector } from "../components/compare/image-selector";
import { PackageComparison } from "../components/compare/package-comparison";
import { SeverityChart } from "../components/compare/severity-chart";
import { SummaryCards } from "../components/compare/summary-cards";
import { TrendChart } from "../components/compare/trend-chart";
import { getMultiComparePresets, multiCompare } from "../lib/api";
import type { MultiCompareImage, MultiCompareResponse } from "../lib/api";

export function ComparePage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [images, setImages] = useState<MultiCompareImage[]>(() => {
    // Restore from URL params
    const restored: MultiCompareImage[] = [];
    for (let i = 1; i <= 3; i++) {
      const name = searchParams.get(`image${i}`);
      if (name) restored.push({ name });
    }
    return restored;
  });

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

      {/* Error state */}
      {compareMutation.isError ? (
        <div className="rounded-xl border border-rose-300 bg-rose-50 p-5 dark:border-rose-800 dark:bg-rose-950/30">
          <p className="text-sm font-medium text-rose-900 dark:text-rose-200">Comparison failed</p>
          <p className="mt-1 text-sm text-rose-700 dark:text-rose-300">
            {compareMutation.error instanceof Error ? compareMutation.error.message : "An error occurred"}
          </p>
          <p className="mt-2 text-xs text-rose-600 dark:text-rose-400">
            Make sure all images have been scanned first. You can scan them at the directory page.
          </p>
        </div>
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

          {/* Package comparison */}
          <PackageComparison images={report.images} packages={report.chart_data.package_overlap} />

          {/* Compliance comparison */}
          <ComplianceComparison images={report.images} />
        </>
      ) : null}
    </div>
  );
}
