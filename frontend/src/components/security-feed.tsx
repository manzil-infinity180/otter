import { useQuery } from "@tanstack/react-query";
import { getSecurityFeed } from "../lib/api";
import type { Severity } from "../lib/types";
import { SeverityPill } from "./severity-pill";

export function SecurityFeed() {
  const feedQuery = useQuery({
    queryKey: ["security-feed"],
    queryFn: getSecurityFeed,
    staleTime: 60 * 60 * 1000, // 1 hour
    retry: 1,
  });

  if (feedQuery.isLoading) {
    return (
      <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h2 className="font-display text-lg text-ink-900 dark:text-white">Recent Critical CVEs</h2>
        <p className="mt-3 text-sm text-ink-500 dark:text-ink-400">Loading security feed...</p>
      </div>
    );
  }

  if (feedQuery.isError || !feedQuery.data?.entries?.length) {
    return null;
  }

  return (
    <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
      <div className="flex items-center justify-between">
        <h2 className="font-display text-lg text-ink-900 dark:text-white">Recent Critical CVEs</h2>
        <span className="text-xs text-ink-400 dark:text-ink-500">
          Updated {new Date(feedQuery.data.updated_at).toLocaleString()}
        </span>
      </div>
      <div className="mt-4 divide-y divide-ink-200 dark:divide-ink-800">
        {feedQuery.data.entries.slice(0, 8).map((entry) => (
          <div key={entry.id} className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
            <SeverityPill severity={entry.severity as Severity} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                {entry.reference ? (
                  <a
                    href={entry.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-sm font-medium text-ink-900 hover:text-brand-600 dark:text-white dark:hover:text-brand-400"
                  >
                    {entry.id}
                  </a>
                ) : (
                  <span className="text-sm font-medium text-ink-900 dark:text-white">{entry.id}</span>
                )}
                {entry.published ? (
                  <span className="text-xs text-ink-400 dark:text-ink-500">
                    {new Date(entry.published).toLocaleDateString()}
                  </span>
                ) : null}
              </div>
              {entry.summary ? (
                <p className="mt-0.5 text-xs text-ink-600 line-clamp-2 dark:text-ink-300">{entry.summary}</p>
              ) : null}
              {entry.packages?.length ? (
                <div className="mt-1 flex flex-wrap gap-1">
                  {entry.packages.slice(0, 3).map((pkg) => (
                    <span key={pkg} className="rounded bg-ink-100 px-1.5 py-0.5 text-[10px] font-medium text-ink-600 dark:bg-ink-800 dark:text-ink-300">
                      {pkg}
                    </span>
                  ))}
                  {entry.packages.length > 3 ? (
                    <span className="text-[10px] text-ink-400">+{entry.packages.length - 3} more</span>
                  ) : null}
                </div>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
