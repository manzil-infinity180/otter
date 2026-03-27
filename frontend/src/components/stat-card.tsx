export function StatCard({
  label,
  value,
  detail
}: {
  label: string;
  value: string | number;
  detail?: string;
}) {
  const valueText = String(value);
  return (
    <section className="min-w-0 rounded-lg border border-ink-200 bg-white p-4 dark:border-ink-800 dark:bg-ink-900">
      <p className="text-xs uppercase tracking-wide text-ink-500 dark:text-ink-400">{label}</p>
      <p className="mt-2 truncate font-display text-3xl text-ink-900 dark:text-white" title={valueText}>
        {valueText}
      </p>
      {detail ? (
        <p className="mt-1 truncate text-sm text-ink-600 dark:text-ink-300" title={detail}>
          {detail}
        </p>
      ) : null}
    </section>
  );
}
