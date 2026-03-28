import { toPng, toSvg } from "html-to-image";
import { useState } from "react";
import type { MultiCompareReport } from "../../lib/api";

interface ExportToolbarProps {
  report: MultiCompareReport;
}

export function ExportToolbar({ report }: ExportToolbarProps) {
  const [copied, setCopied] = useState(false);

  const copyShareURL = () => {
    const params = new URLSearchParams();
    report.images.forEach((img, i) => params.set(`image${i + 1}`, img.image_name));
    const url = `${window.location.origin}/compare?${params.toString()}`;
    navigator.clipboard.writeText(url);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const exportPNG = async (elementId: string, filename: string) => {
    const node = document.getElementById(elementId);
    if (!node) return;
    try {
      const dataUrl = await toPng(node, { backgroundColor: "#ffffff", pixelRatio: 2 });
      downloadDataURL(dataUrl, `${filename}.png`);
    } catch (err) {
      console.error("PNG export failed:", err);
    }
  };

  const exportSVG = async (elementId: string, filename: string) => {
    const node = document.getElementById(elementId);
    if (!node) return;
    try {
      const dataUrl = await toSvg(node, { backgroundColor: "#ffffff" });
      downloadDataURL(dataUrl, `${filename}.svg`);
    } catch (err) {
      console.error("SVG export failed:", err);
    }
  };

  const exportCSV = () => {
    const rows = [["Image", "Total CVEs", "Critical", "High", "Medium", "Low", "Packages", "Fixable", "Unfixable"]];
    report.images.forEach((img) => {
      rows.push([
        img.image_name,
        String(img.vulnerability_summary.total),
        String(img.vulnerability_summary.by_severity["CRITICAL"] ?? 0),
        String(img.vulnerability_summary.by_severity["HIGH"] ?? 0),
        String(img.vulnerability_summary.by_severity["MEDIUM"] ?? 0),
        String(img.vulnerability_summary.by_severity["LOW"] ?? 0),
        String(img.package_count),
        String(img.vulnerability_summary.fixable),
        String(img.vulnerability_summary.unfixable),
      ]);
    });
    const csv = rows.map((r) => r.map((c) => `"${c}"`).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    downloadBlob(blob, `comparison-${report.id}.csv`);
  };

  const exportJSON = () => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    downloadBlob(blob, `comparison-${report.id}.json`);
  };

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-4 dark:border-ink-800 dark:bg-ink-900">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium uppercase tracking-wider text-ink-500 dark:text-ink-400">Export</span>

        <button type="button" onClick={() => exportPNG("severity-chart", `severity-${report.id}`)} className={btnClass}>
          Severity PNG
        </button>
        <button type="button" onClick={() => exportSVG("severity-chart", `severity-${report.id}`)} className={btnClass}>
          Severity SVG
        </button>
        <button type="button" onClick={() => exportPNG("trend-chart", `trend-${report.id}`)} className={btnClass}>
          Trend PNG
        </button>
        <button type="button" onClick={() => exportPNG("package-chart", `packages-${report.id}`)} className={btnClass}>
          Packages PNG
        </button>

        <div className="mx-1 h-5 w-px bg-ink-200 dark:bg-ink-700" />

        <button type="button" onClick={exportCSV} className={btnClass}>
          CSV
        </button>
        <button type="button" onClick={exportJSON} className={btnClass}>
          JSON
        </button>

        <div className="mx-1 h-5 w-px bg-ink-200 dark:bg-ink-700" />

        <button type="button" onClick={copyShareURL} className={btnClass}>
          {copied ? "\u2713 Copied!" : "Copy share URL"}
        </button>
      </div>
    </div>
  );
}

const btnClass =
  "rounded-md border border-ink-200 px-3 py-1.5 text-xs font-medium text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-300 dark:hover:border-white dark:hover:text-white";

function downloadDataURL(dataUrl: string, filename: string) {
  const link = document.createElement("a");
  link.download = filename;
  link.href = dataUrl;
  link.click();
}

function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.download = filename;
  link.href = url;
  link.click();
  URL.revokeObjectURL(url);
}
