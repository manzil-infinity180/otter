import { useDeferredValue, useMemo, useState } from "react";

interface JsonMatch {
  path: string;
  preview: string;
  segments: string[];
}

export function JSONViewer({
  document,
  filename
}: {
  document: unknown;
  filename?: string;
}) {
  const [search, setSearch] = useState("");
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(() => new Set(["$"]));
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");
  const deferredSearch = useDeferredValue(search.trim().toLowerCase());
  const expandablePaths = useMemo(() => collectExpandablePaths(document), [document]);

  const searchMatches = useMemo(() => {
    if (!deferredSearch) {
      return [];
    }
    return findMatches(document, deferredSearch);
  }, [document, deferredSearch]);

  const onToggle = (path: string) => {
    setExpandedPaths((current) => {
      const next = new Set(current);
      if (next.has(path)) {
        next.delete(path);
      } else {
        next.add(path);
      }
      return next;
    });
  };

  const onRevealPath = (segments: string[]) => {
    setExpandedPaths((current) => {
      const next = new Set(current);
      let path = "$";
      next.add(path);
      for (const segment of segments) {
        path = pathSegment(path, segment);
        next.add(path);
      }
      return next;
    });
  };

  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(document, null, 2));
      setCopyState("copied");
      window.setTimeout(() => setCopyState("idle"), 1500);
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden rounded-lg border border-ink-200 bg-white dark:border-ink-800 dark:bg-ink-950">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-ink-200 px-4 py-3 dark:border-ink-800">
        <div className="min-w-0">
          <p className="truncate font-medium text-ink-900 dark:text-white" title={filename}>
            {filename || "artifact.json"}
          </p>
          <p className="text-xs text-ink-500 dark:text-ink-400">Lazy tree viewer for large JSON artifacts</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => setExpandedPaths(new Set(expandablePaths))}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
          >
            Expand all
          </button>
          <button
            type="button"
            onClick={() => setExpandedPaths(new Set(["$"]))}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
          >
            Collapse all
          </button>
          <input
            aria-label="Search JSON"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search keys or values"
            className="w-56 rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 outline-none transition focus:border-tide dark:border-ink-700 dark:bg-ink-900 dark:text-white"
          />
          <button
            type="button"
            onClick={() => void onCopy()}
            className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
          >
            {copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy failed" : "Copy JSON"}
          </button>
        </div>
      </div>

      {deferredSearch ? (
        <div className="border-b border-ink-200 px-4 py-3 dark:border-ink-800">
          <p className="text-xs font-medium uppercase tracking-wide text-ink-500 dark:text-ink-400">Search results</p>
          <div className="mt-3 max-h-32 space-y-2 overflow-y-auto">
            {searchMatches.map((match) => (
              <button
                key={match.path}
                type="button"
                onClick={() => onRevealPath(match.segments)}
                className="block w-full rounded-md border border-ink-200 px-3 py-2 text-left transition hover:border-tide dark:border-ink-800 dark:hover:border-sky-600"
              >
                <p className="truncate text-sm font-medium text-ink-900 dark:text-white">{match.path}</p>
                <p className="truncate text-xs text-ink-500 dark:text-ink-400">{match.preview}</p>
              </button>
            ))}
            {!searchMatches.length ? <p className="text-sm text-ink-500 dark:text-ink-400">No matches in this document.</p> : null}
          </div>
        </div>
      ) : null}

      <div className="min-h-0 flex-1 overflow-auto px-4 py-4 font-mono text-sm">
        <JsonTreeNode
          label="$"
          value={document}
          path="$"
          depth={0}
          expandedPaths={expandedPaths}
          onToggle={onToggle}
        />
      </div>
    </div>
  );
}

function JsonTreeNode({
  label,
  value,
  path,
  depth,
  expandedPaths,
  onToggle
}: {
  label: string;
  value: unknown;
  path: string;
  depth: number;
  expandedPaths: Set<string>;
  onToggle: (path: string) => void;
}) {
  const [visibleChildren, setVisibleChildren] = useState(50);
  const compound = toEntries(value);
  const isExpanded = expandedPaths.has(path);
  const indent = { paddingLeft: `${depth * 1}rem` };

  if (!compound) {
    return (
      <div className="leading-7" style={indent}>
        {label !== "$" ? <span className="mr-2 text-rose-700 dark:text-rose-300">{label}:</span> : null}
        <ValueToken value={value} />
      </div>
    );
  }

  const entries = compound.entries.slice(0, visibleChildren);

  return (
    <div>
      <button
        type="button"
        onClick={() => onToggle(path)}
        className="flex w-full items-center gap-2 rounded py-1 text-left leading-7 transition hover:bg-ink-100 dark:hover:bg-ink-900"
        style={indent}
      >
        <span className="w-4 text-center text-ink-500 dark:text-ink-400">{isExpanded ? "-" : "+"}</span>
        {label !== "$" ? <span className="text-rose-700 dark:text-rose-300">{label}:</span> : null}
        <span className="text-ink-500 dark:text-ink-400">
          {compound.kind === "array" ? `Array(${compound.entries.length})` : `Object(${compound.entries.length})`}
        </span>
      </button>

      {isExpanded ? (
        <div>
          {entries.map(([key, child]) => (
            <JsonTreeNode
              key={pathSegment(path, key)}
              label={compound.kind === "array" ? `[${key}]` : key}
              value={child}
              path={pathSegment(path, key)}
              depth={depth + 1}
              expandedPaths={expandedPaths}
              onToggle={onToggle}
            />
          ))}
          {compound.entries.length > visibleChildren ? (
            <button
              type="button"
              onClick={() => setVisibleChildren((current) => current + 50)}
              className="ml-4 mt-1 rounded px-3 py-1 text-xs text-tide transition hover:text-sky-600 dark:hover:text-sky-300"
            >
              Show 50 more
            </button>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function ValueToken({ value }: { value: unknown }) {
  if (typeof value === "string") {
    return <span className="break-all text-emerald-700 dark:text-emerald-300">"{value}"</span>;
  }
  if (typeof value === "number") {
    return <span className="text-sky-700 dark:text-sky-300">{value}</span>;
  }
  if (typeof value === "boolean") {
    return <span className="text-fuchsia-700 dark:text-fuchsia-300">{String(value)}</span>;
  }
  if (value === null) {
    return <span className="text-ink-500 dark:text-ink-400">null</span>;
  }
  return <span className="text-amber-700 dark:text-amber-300">{String(value)}</span>;
}

function toEntries(value: unknown) {
  if (Array.isArray(value)) {
    return {
      kind: "array" as const,
      entries: value.map((item, index) => [String(index), item] as const)
    };
  }
  if (value && typeof value === "object") {
    return {
      kind: "object" as const,
      entries: Object.entries(value as Record<string, unknown>)
    };
  }
  return null;
}

function findMatches(value: unknown, query: string) {
  const matches: JsonMatch[] = [];
  visitNode(value, [], query, matches);
  return matches.slice(0, 100);
}

function visitNode(value: unknown, segments: string[], query: string, matches: JsonMatch[]) {
  if (matches.length >= 100) {
    return;
  }

  const path = segments.length ? `$.${segments.join(".")}` : "$";
  const preview = previewValue(value);
  if (path.toLowerCase().includes(query) || preview.toLowerCase().includes(query)) {
    matches.push({ path, preview, segments });
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => visitNode(item, [...segments, String(index)], query, matches));
    return;
  }

  if (value && typeof value === "object") {
    Object.entries(value as Record<string, unknown>).forEach(([key, child]) => {
      visitNode(child, [...segments, key], query, matches);
    });
  }
}

function previewValue(value: unknown) {
  if (typeof value === "string") {
    return value;
  }
  if (typeof value === "number" || typeof value === "boolean") {
    return String(value);
  }
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return `Array(${value.length})`;
  }
  if (value && typeof value === "object") {
    return `Object(${Object.keys(value as Record<string, unknown>).length})`;
  }
  return "";
}

function pathSegment(path: string, key: string) {
  return `${path}.${key}`;
}

function collectExpandablePaths(value: unknown) {
  const paths = new Set<string>(["$"]);
  walkExpandablePaths(value, "$", paths);
  return Array.from(paths);
}

function walkExpandablePaths(value: unknown, path: string, paths: Set<string>) {
  const compound = toEntries(value);
  if (!compound) {
    return;
  }
  paths.add(path);
  for (const [key, child] of compound.entries) {
    walkExpandablePaths(child, pathSegment(path, key), paths);
  }
}
