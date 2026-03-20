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
    <section className="min-w-0 rounded-3xl border border-white/50 bg-white/75 p-4 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80">
      <p className="text-xs uppercase tracking-[0.24em] text-ink-500 dark:text-ink-400">{label}</p>
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
