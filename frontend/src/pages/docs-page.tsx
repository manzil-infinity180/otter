const architectureSections = [
  {
    title: "Backend",
    items: [
      "`main.go` boots storage, indexes, analyzer services, registry manager, catalog worker, and the Gin router.",
      "`pkg/api` exposes scan, catalog, image detail, export, comparison, compliance, attestation, and registry endpoints.",
      "`pkg/scan` orchestrates Syft plus Grype and optional Trivy scanners, then writes structured artifacts and summaries.",
      "`pkg/storage`, `pkg/sbomindex`, and `pkg/vulnindex` separate artifact persistence from queryable indexes."
    ]
  },
  {
    title: "Frontend",
    items: [
      "React 18 + Vite + Tailwind CSS power the single-page UI.",
      "`DirectoryPage` handles scan intake, catalog filtering, and active job status.",
      "`ImageDetailPage` renders overview, tags, comparison, vulnerabilities, SBOM, attestations, and advisories.",
      "React Query keeps the page synchronized with REST endpoints without heavy client-side state."
    ]
  },
  {
    title: "Storage modes",
    items: [
      "Local mode stores scan artifacts in `./data` and index files on disk.",
      "PostgreSQL mode stores artifacts and indexes in the database with migrations from `db/migrations`.",
      "S3 mode remains available for artifact persistence while indexes continue through the configured repositories."
    ]
  }
];

const runSteps = [
  {
    title: "Backend",
    code: "OTTER_STORAGE=local go run .",
    note: "Starts Gin on `http://localhost:7789`."
  },
  {
    title: "Frontend",
    code: "cd frontend\nnpm install\nnpm run dev",
    note: "Starts Vite on `http://localhost:4173` with proxying to the backend."
  },
  {
    title: "Optional Trivy server",
    code: "trivy server --listen 0.0.0.0:4954",
    note: "Then set `OTTER_TRIVY_ENABLED=true` and `OTTER_TRIVY_SERVER_URL=http://localhost:4954`."
  },
  {
    title: "Docker Compose",
    code: "docker compose up --build",
    note: "Runs the full stack with PostgreSQL and the Otter service."
  }
];

const supportRows = [
  ["Scanning", "Manual scans from the UI or API, async jobs, seeded catalog worker, public image scanning."],
  ["Artifacts", "CycloneDX, SPDX, combined vulnerability report, per-scanner JSON, advisory overlays, VEX imports."],
  ["Evidence", "OCI signatures, attestations, provenance summaries, OpenSSF Scorecard, supply-chain checklist."],
  ["Exports", "CycloneDX, SPDX, CSV, SARIF, JSON, and comparison export endpoints."],
  ["Registries", "Public pulls, docker config auth, explicit credentials, throttled host-level preflight access."]
];

const tutorialRows = [
  ["End-to-end walkthrough", "Use `docs/tutorial-otter-supply-chain-walkthrough.md` with the sample app in `examples/supply-chain-demo`."],
  ["Broken then fixed", "Use `docs/tutorial-baseline-vs-hardened.md` to show why Scorecard, SLSA, and attestations are empty first, then how to make them appear."],
  ["GitHub issue filing", "Use `docs/issues/README.md` and `docs/issues/file-audit-issues.sh` after `gh auth login` is fixed."]
];

const productFlow = [
  "User enters an image ref in the UI or POSTs to `/api/v1/scans`.",
  "Otter resolves registry access, applies auth and pull throttling, then starts analysis.",
  "Syft creates SBOM documents and normalized package data.",
  "Grype and Trivy run in parallel when enabled and available.",
  "Artifacts and indexes are stored, scan job state is updated, and the image detail page becomes queryable."
];

export function DocsPage() {
  return (
    <div className="space-y-6">
      <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900 sm:p-8">
        <p className="text-xs font-medium uppercase tracking-wider text-ink-500 dark:text-ink-400">Otter docs</p>
        <h1 className="mt-3 font-display text-3xl tracking-tight text-ink-900 dark:text-white">Architecture, runbook, and supported capabilities</h1>
        <p className="mt-4 max-w-4xl text-base leading-7 text-ink-600 dark:text-ink-300">
          This page explains the current system shape, how to run it locally, how the main scan flow works, and what the product
          supports today. The same information is also captured in the repository docs for contributors.
        </p>
      </section>

      <section className="grid gap-4 xl:grid-cols-3">
        {architectureSections.map((section) => (
          <article key={section.title} className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
            <h2 className="font-display text-xl text-ink-900 dark:text-white">{section.title}</h2>
            <ul className="mt-4 space-y-3 text-sm leading-7 text-ink-600 dark:text-ink-300">
              {section.items.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
          </article>
        ))}
      </section>

      <section className="grid gap-4 lg:grid-cols-2">
        <article className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
          <h2 className="font-display text-xl text-ink-900 dark:text-white">Run locally</h2>
          <div className="mt-5 space-y-4">
            {runSteps.map((step) => (
              <div key={step.title} className="rounded-lg border border-ink-200 bg-ink-50 p-4 dark:border-ink-800 dark:bg-ink-950">
                <p className="text-sm font-medium text-ink-900 dark:text-white">{step.title}</p>
                <pre className="mt-3 overflow-x-auto rounded-lg bg-ink-950 px-4 py-3 text-sm text-ink-50">
                  <code>{step.code}</code>
                </pre>
                <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{step.note}</p>
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
          <h2 className="font-display text-xl text-ink-900 dark:text-white">Primary flow</h2>
          <div className="mt-5 space-y-3">
            {productFlow.map((step, index) => (
              <div key={step} className="rounded-lg border border-ink-200 bg-ink-50 px-4 py-3 dark:border-ink-800 dark:bg-ink-950">
                <p className="text-xs font-medium uppercase tracking-wide text-ink-500 dark:text-ink-400">Step {index + 1}</p>
                <p className="mt-1.5 text-sm leading-6 text-ink-700 dark:text-ink-200">{step}</p>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h2 className="font-display text-xl text-ink-900 dark:text-white">Supported capabilities</h2>
        <div className="mt-5 overflow-x-auto">
          <table className="min-w-[760px] text-left text-sm">
            <thead className="text-ink-500 dark:text-ink-400">
              <tr>
                <th className="pb-3 pr-6">Area</th>
                <th className="pb-3">Support</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
              {supportRows.map(([area, detail]) => (
                <tr key={area}>
                  <td className="py-4 pr-6 font-medium text-ink-900 dark:text-white">{area}</td>
                  <td className="py-4 text-ink-600 dark:text-ink-300">{detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
        <h2 className="font-display text-xl text-ink-900 dark:text-white">Tutorials and issue tracking</h2>
        <div className="mt-5 overflow-x-auto">
          <table className="min-w-[760px] text-left text-sm">
            <thead className="text-ink-500 dark:text-ink-400">
              <tr>
                <th className="pb-3 pr-6">Guide</th>
                <th className="pb-3">Purpose</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
              {tutorialRows.map(([guide, detail]) => (
                <tr key={guide}>
                  <td className="py-4 pr-6 font-medium text-ink-900 dark:text-white">{guide}</td>
                  <td className="py-4 text-ink-600 dark:text-ink-300">{detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
