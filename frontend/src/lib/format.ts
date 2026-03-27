import type { ComplianceStatus, DependencyNode, Severity, VulnerabilitySummary } from "./types";

const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "UNKNOWN"];

export function formatTimestamp(value?: string) {
  if (!value) {
    return "Unavailable";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

export function formatCompactNumber(value: number) {
  return new Intl.NumberFormat(undefined, { notation: "compact" }).format(value);
}

export function formatBytes(value: number) {
  if (value === 0) {
    return "0 B";
  }
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

export function severityTone(severity: Severity) {
  switch (severity) {
    case "CRITICAL":
      return "bg-rose/15 text-rose ring-1 ring-inset ring-rose/30";
    case "HIGH":
      return "bg-amber-100 text-amber-800 ring-1 ring-inset ring-amber-300/50 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-500/30";
    case "MEDIUM":
      return "bg-sky-100 text-sky-800 ring-1 ring-inset ring-sky-300/50 dark:bg-sky-950/40 dark:text-sky-300 dark:ring-sky-500/30";
    case "LOW":
      return "bg-emerald-100 text-emerald-800 ring-1 ring-inset ring-emerald-300/50 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-500/30";
    default:
      return "bg-ink-100 text-ink-700 ring-1 ring-inset ring-ink-300 dark:bg-ink-800 dark:text-ink-200 dark:ring-ink-700";
  }
}

export function complianceTone(status: ComplianceStatus) {
  switch (status) {
    case "pass":
      return "bg-emerald-100 text-emerald-800 ring-1 ring-inset ring-emerald-300/50 dark:bg-emerald-950/40 dark:text-emerald-300 dark:ring-emerald-500/30";
    case "partial":
      return "bg-amber-100 text-amber-800 ring-1 ring-inset ring-amber-300/50 dark:bg-amber-950/40 dark:text-amber-300 dark:ring-amber-500/30";
    case "fail":
      return "bg-rose/15 text-rose ring-1 ring-inset ring-rose/30";
    default:
      return "bg-ink-100 text-ink-700 ring-1 ring-inset ring-ink-300 dark:bg-ink-800 dark:text-ink-200 dark:ring-ink-700";
  }
}

export function vulnerabilityChips(summary?: VulnerabilitySummary) {
  if (!summary) {
    return [];
  }
  return severityOrder
    .map((severity) => ({ severity, count: summary.by_severity?.[severity] ?? 0 }))
    .filter((entry) => entry.count > 0);
}

export function buildDependencyChildren(tree: DependencyNode[]) {
  const nodes = new Map(tree.map((node) => [node.id, node]));
  return tree.map((node) => ({
    ...node,
    children: (node.depends_on ?? []).map((dependencyId) => nodes.get(dependencyId)).filter(Boolean) as DependencyNode[]
  }));
}
