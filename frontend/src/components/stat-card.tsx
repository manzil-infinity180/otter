export function StatCard({
  label,
  value,
  detail
}: {
  label: string;
  value: string | number;
  detail?: string;
}) {
  return (
    <section className="rounded-3xl border border-white/50 bg-white/75 p-4 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80">
      <p className="text-xs uppercase tracking-[0.24em] text-ink-500 dark:text-ink-400">{label}</p>
      <p className="mt-2 font-display text-3xl text-ink-900 dark:text-white">{value}</p>
      {detail ? <p className="mt-1 text-sm text-ink-600 dark:text-ink-300">{detail}</p> : null}
    </section>
  );
}
