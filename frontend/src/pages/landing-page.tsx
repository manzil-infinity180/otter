import { Link } from "react-router-dom";

const architectureLayers = [
  {
    title: "Scan orchestration",
    detail: "Gin handlers accept manual and async scan requests, preflight registry access, and hand image refs to the analyzer pipeline."
  },
  {
    title: "Evidence pipeline",
    detail: "Syft generates SBOMs, Grype and Trivy produce vulnerability findings, and Cosign-backed discovery adds signatures and attestations when available."
  },
  {
    title: "Indexed storage",
    detail: "Artifacts are persisted in local storage, PostgreSQL, or S3 while normalized SBOM and vulnerability indexes power the detail APIs and comparisons."
  }
];

const userFlows = [
  "Scan any public image from the directory with async status polling.",
  "Review the overview, vulnerabilities, SBOM, attestations, advisories, and comparison tabs for a stored scan.",
  "Export CycloneDX, SPDX, CSV, SARIF, and JSON artifacts from the image detail page or API.",
  "Browse the fallback HTML catalog when the React bundle is not built."
];

const supportAreas = [
  "Public and authenticated registry pulls",
  "Async catalog jobs plus seeded background scans",
  "CycloneDX and SPDX SBOM handling",
  "Merged Grype and Trivy vulnerability analysis",
  "OpenVEX and advisory overlays",
  "OCI signatures, referrers, and provenance discovery",
  "OpenSSF Scorecard and supply-chain posture checks",
  "Image-to-image comparison and export formats"
];

export function LandingPage() {
  return (
    <div className="space-y-8">
      <section className="overflow-hidden rounded-[2.5rem] border border-white/60 bg-white/75 px-6 py-10 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80 sm:px-8 lg:px-10">
        <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
          <div className="space-y-6">
            <div className="inline-flex rounded-full border border-tide/20 bg-tide/10 px-4 py-2 text-xs font-medium uppercase tracking-[0.24em] text-tide dark:border-tide/30 dark:bg-tide/10 dark:text-sky-200">
              Open-source SBOM and vulnerability analyzer
            </div>
            <div className="space-y-4">
              <h1 className="max-w-4xl font-display text-4xl tracking-tight text-ink-900 dark:text-white sm:text-5xl lg:text-6xl">
                Inspect container images with one scan pipeline and one detail view.
              </h1>
              <p className="max-w-3xl text-base leading-8 text-ink-600 dark:text-ink-300 sm:text-lg">
                Otter pulls an image, generates SBOMs, merges vulnerability findings, stores evidence artifacts, and exposes
                detail APIs and UI tabs for packages, compliance, attestations, advisories, and comparisons.
              </p>
            </div>
            <div className="flex flex-wrap gap-3">
              <Link
                to="/directory"
                className="inline-flex items-center rounded-full bg-ink-900 px-5 py-3 text-sm font-medium text-white transition hover:bg-ink-800 dark:bg-white dark:text-ink-900 dark:hover:bg-ink-100"
              >
                Get started
              </Link>
              <Link
                to="/docs"
                className="inline-flex items-center rounded-full border border-ink-200 px-5 py-3 text-sm font-medium text-ink-800 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-100 dark:hover:border-white dark:hover:text-white"
              >
                Read docs
              </Link>
              <a
                href="/browse"
                className="inline-flex items-center rounded-full border border-ink-200 px-5 py-3 text-sm font-medium text-ink-800 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-100 dark:hover:border-white dark:hover:text-white"
              >
                HTML fallback
              </a>
            </div>
          </div>

          <div className="grid gap-4">
            <div className="rounded-[2rem] border border-ink-200 bg-white/85 p-5 dark:border-ink-800 dark:bg-ink-950/55">
              <p className="text-xs uppercase tracking-[0.2em] text-ink-500 dark:text-ink-400">Default flow</p>
              <ol className="mt-4 space-y-3 text-sm text-ink-700 dark:text-ink-200">
                <li>1. Queue or run a scan for an image reference such as `nginx:latest`.</li>
                <li>2. Generate CycloneDX and SPDX SBOMs with Syft.</li>
                <li>3. Merge Grype and Trivy findings into one indexed vulnerability view.</li>
                <li>4. Persist artifacts, normalized package records, and trend snapshots.</li>
                <li>5. Open the image detail page for drilldown, exports, and comparisons.</li>
              </ol>
            </div>
            <div className="rounded-[2rem] border border-ink-200 bg-gradient-to-br from-amber-50/90 via-white to-sky-50/90 p-5 dark:border-ink-800 dark:bg-gradient-to-br dark:from-amber-950/10 dark:via-ink-950/50 dark:to-sky-950/10">
              <p className="text-xs uppercase tracking-[0.2em] text-ink-500 dark:text-ink-400">Built for</p>
              <p className="mt-3 text-lg font-medium text-ink-900 dark:text-white">
                local-first analysis, CI automation, seeded catalog scanning, and supply-chain evidence review.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="grid gap-4 lg:grid-cols-3">
        {architectureLayers.map((layer) => (
          <article key={layer.title} className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
            <p className="text-xs uppercase tracking-[0.22em] text-ink-500 dark:text-ink-400">Architecture</p>
            <h2 className="mt-3 font-display text-2xl text-ink-900 dark:text-white">{layer.title}</h2>
            <p className="mt-3 text-sm leading-7 text-ink-600 dark:text-ink-300">{layer.detail}</p>
          </article>
        ))}
      </section>

      <section className="grid gap-6 lg:grid-cols-[1fr_1fr]">
        <article className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
          <h2 className="font-display text-2xl text-ink-900 dark:text-white">How teams use Otter</h2>
          <div className="mt-4 space-y-3">
            {userFlows.map((flow) => (
              <div key={flow} className="rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-700 dark:border-ink-800 dark:bg-ink-950/50 dark:text-ink-200">
                {flow}
              </div>
            ))}
          </div>
        </article>

        <article className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
          <h2 className="font-display text-2xl text-ink-900 dark:text-white">What Otter supports today</h2>
          <div className="mt-4 flex flex-wrap gap-3">
            {supportAreas.map((item) => (
              <span key={item} className="rounded-full border border-ink-200 bg-white/85 px-4 py-2 text-sm text-ink-700 dark:border-ink-800 dark:bg-ink-950/60 dark:text-ink-200">
                {item}
              </span>
            ))}
          </div>
        </article>
      </section>
    </div>
  );
}
