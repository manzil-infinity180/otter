export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <section className="rounded-lg border border-dashed border-ink-300 bg-white px-6 py-10 text-center dark:border-ink-700 dark:bg-ink-900">
      <h3 className="font-display text-xl text-ink-900 dark:text-white">{title}</h3>
      <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">{description}</p>
    </section>
  );
}
