import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { startTransition, useMemo, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";

import { compareImages, getAttestations, getComparisonExportURL, getCompliance, getImageExportURL, getOverview, getSbom, getVulnerabilities, listCatalog } from "../lib/api";
import { buildDependencyChildren, complianceTone, formatBytes, formatTimestamp, vulnerabilityChips } from "../lib/format";
import type { CatalogItem, DependencyNode, ImageExportFormat, OverviewResponse, Severity, VulnerabilityRecord } from "../lib/types";
import { EmptyState } from "../components/empty-state";
import { SeverityPill } from "../components/severity-pill";
import { StatCard } from "../components/stat-card";

const tabs = ["Overview", "Tags", "Comparison", "Vulnerabilities", "SBOM", "Attestations", "Advisories"] as const;
type TabKey = (typeof tabs)[number];

const severityFilterOptions: Array<"" | Severity> = ["", "CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"];
const statusFilterOptions = ["", "affected", "not_affected", "fixed", "under_investigation"];
const imageExportOptions: Array<{ format: ImageExportFormat; label: string; description: string }> = [
  { format: "cyclonedx", label: "Export CycloneDX", description: "Raw SBOM JSON" },
  { format: "spdx", label: "Export SPDX", description: "SPDX 2.3 JSON" },
  { format: "json", label: "Export Vulnerabilities JSON", description: "Structured report" },
  { format: "csv", label: "Export CSV", description: "Spreadsheet-friendly" },
  { format: "sarif", label: "Export SARIF", description: "GitHub code scanning" }
];

export function ImageDetailPage() {
  const { orgId = "", imageId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = (searchParams.get("tab") as TabKey | null) ?? "Overview";
  const [comparisonTargetId, setComparisonTargetId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"" | Severity>("");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchFilter, setSearchFilter] = useState("");

  const overviewQuery = useQuery({
    queryKey: ["overview", orgId, imageId],
    queryFn: () => getOverview(orgId, imageId)
  });

  const vulnerabilitiesQuery = useQuery({
    queryKey: ["vulnerabilities", orgId, imageId],
    queryFn: () => getVulnerabilities(orgId, imageId),
    enabled: Boolean(orgId && imageId)
  });

  const complianceQuery = useQuery({
    queryKey: ["compliance", orgId, imageId],
    queryFn: () => getCompliance(orgId, imageId),
    enabled: Boolean(orgId && imageId),
    retry: false
  });

  const sbomQuery = useQuery({
    queryKey: ["sbom", orgId, imageId],
    queryFn: () => getSbom(orgId, imageId),
    enabled: Boolean(orgId && imageId)
  });

  const attestationsQuery = useQuery({
    queryKey: ["attestations", orgId, imageId],
    queryFn: () => getAttestations(orgId, imageId),
    enabled: Boolean(orgId && imageId),
    retry: false
  });

  const catalogQuery = useQuery({
    queryKey: ["catalog", "comparison", overviewQuery.data?.repository],
    queryFn: () => listCatalog({ query: overviewQuery.data?.repository_path }),
    enabled: Boolean(overviewQuery.data?.repository_path)
  });

  const comparisonCandidates = useMemo(() => {
    return (catalogQuery.data?.items ?? []).filter(
      (item) => !(item.org_id === orgId && item.image_id === imageId)
    );
  }, [catalogQuery.data?.items, imageId, orgId]);

  const comparisonMutation = useMutation({
    mutationFn: (target: CatalogItem) =>
      compareImages({
        image1: overviewQuery.data!.image_name,
        image2: target.image_name,
        org1: overviewQuery.data!.org_id,
        org2: target.org_id
      })
  });

  const filteredVulnerabilities = useMemo(() => {
    const source = vulnerabilitiesQuery.data?.vulnerabilities ?? [];
    const search = searchFilter.trim().toLowerCase();
    return source.filter((vulnerability) => {
      if (severityFilter && vulnerability.severity !== severityFilter) {
        return false;
      }
      if (statusFilter && vulnerability.status !== statusFilter) {
        return false;
      }
      if (!search) {
        return true;
      }
      return [
        vulnerability.id,
        vulnerability.package_name,
        vulnerability.package_version,
        vulnerability.description,
        vulnerability.title
      ]
        .join(" ")
        .toLowerCase()
        .includes(search);
    });
  }, [searchFilter, severityFilter, statusFilter, vulnerabilitiesQuery.data?.vulnerabilities]);

  const dependencyTree = useMemo(() => buildDependencyChildren(sbomQuery.data?.dependency_tree ?? []), [sbomQuery.data?.dependency_tree]);
  const overview = overviewQuery.data;

  if (overviewQuery.isLoading) {
    return <div className="rounded-[2rem] border border-white/60 bg-white/75 p-8 shadow-haze dark:border-white/10 dark:bg-ink-900/80">Loading image detail…</div>;
  }

  if (overviewQuery.isError || !overview) {
    return (
      <EmptyState
        title="Image detail unavailable"
        description={overviewQuery.error instanceof Error ? overviewQuery.error.message : "The overview endpoint did not return data."}
      />
    );
  }

  const allTags = [
    {
      org_id: overview.org_id,
      image_id: overview.image_id,
      image_name: overview.image_name,
      tag: overview.tag,
      digest: overview.digest,
      package_count: overview.package_count,
      vulnerability_summary: overview.vulnerability_summary,
      updated_at: overview.updated_at
    },
    ...overview.tags
  ];

  return (
    <div className="space-y-8">
      <section className="overflow-hidden rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80 sm:p-8">
        <div className="flex flex-wrap items-start justify-between gap-6">
          <div className="space-y-3">
            <Link to="/" className="text-sm text-tide hover:text-sky-600 dark:hover:text-sky-300">
              Back to directory
            </Link>
            <p className="text-sm uppercase tracking-[0.24em] text-ink-500 dark:text-ink-400">{overview.registry}</p>
            <h1 className="font-display text-4xl tracking-tight text-ink-900 dark:text-white">{overview.repository_path || overview.image_name}</h1>
            <p className="max-w-3xl text-base text-ink-600 dark:text-ink-300">{overview.image_name}</p>
            <div className="flex flex-wrap gap-2">
              {overview.tag ? <span className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">tag {overview.tag}</span> : null}
              {overview.platform ? <span className="rounded-full bg-emerald-100 px-3 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-950/70 dark:text-emerald-200">platform {overview.platform}</span> : null}
              {overview.scanners.map((scanner) => (
                <span key={scanner} className="rounded-full bg-sky-100 px-3 py-1 text-xs font-medium text-sky-700 dark:bg-sky-950/70 dark:text-sky-200">
                  {scanner}
                </span>
              ))}
            </div>
          </div>
          <div className="rounded-[1.75rem] bg-ink-900 px-5 py-4 text-white shadow-haze dark:bg-white dark:text-ink-900">
            <p className="text-xs uppercase tracking-[0.24em]">Last indexed</p>
            <p className="mt-2 font-display text-2xl">{formatTimestamp(overview.updated_at)}</p>
            <p className="mt-1 text-sm opacity-75">{overview.org_id} / {overview.image_id}</p>
          </div>
        </div>

        <div className="mt-8 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Packages" value={overview.package_count} />
          <StatCard label="Vulnerabilities" value={overview.vulnerability_summary.total} detail={`${overview.vulnerability_summary.fixable} fixable`} />
          <StatCard label="Artifacts" value={overview.files.length} detail={overview.storage_backend} />
          <StatCard label="Related tags" value={allTags.length} detail="Same repository" />
        </div>

        <div className="mt-5 flex flex-wrap gap-2">
          {vulnerabilityChips(overview.vulnerability_summary).map((chip) => (
            <SeverityPill key={chip.severity} severity={chip.severity} count={chip.count} />
          ))}
        </div>
      </section>

      <section className="grid gap-6 lg:grid-cols-[240px_minmax(0,1fr)]">
        <aside className="rounded-[2rem] border border-white/60 bg-white/75 p-3 shadow-haze backdrop-blur dark:border-white/10 dark:bg-ink-900/80">
          <div role="tablist" aria-orientation="vertical" className="flex gap-2 overflow-x-auto lg:flex-col">
            {tabs.map((label) => {
              const active = tab === label;
              return (
                <button
                  key={label}
                  role="tab"
                  aria-selected={active}
                  type="button"
                  onClick={() => {
                    startTransition(() => {
                      const next = new URLSearchParams(searchParams);
                      next.set("tab", label);
                      setSearchParams(next, { replace: true });
                    });
                  }}
                  className={clsx(
                    "min-w-fit rounded-2xl px-4 py-3 text-left text-sm font-medium transition",
                    active
                      ? "bg-ink-900 text-white shadow-haze dark:bg-white dark:text-ink-900"
                      : "text-ink-600 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-white"
                  )}
                >
                  {label}
                </button>
              );
            })}
          </div>
        </aside>

        <div className="space-y-6">
          {tab === "Overview" ? (
            <section className="grid gap-6">
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Scan summary</h2>
                <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                  <StatCard label="Registry" value={overview.registry || "local"} />
                  <StatCard label="Platform" value={overview.platform || "default"} />
                  <StatCard label="Repository" value={overview.repository_path || overview.image_name} />
                  <StatCard label="Fixable" value={overview.vulnerability_summary.fixable} />
                  <StatCard label="Unfixable" value={overview.vulnerability_summary.unfixable} />
                </div>
              </div>
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <h2 className="font-display text-2xl text-ink-900 dark:text-white">Compliance posture</h2>
                    <p className="mt-2 max-w-3xl text-sm text-ink-600 dark:text-ink-300">
                      {complianceQuery.data?.scope_note ?? "Best-effort standards tracking based on provenance, signatures, vulnerabilities, and upstream project posture."}
                    </p>
                  </div>
                  {complianceQuery.data ? (
                    <span className={clsx("rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.18em]", complianceTone(complianceQuery.data.summary.overall_status))}>
                      {complianceQuery.data.summary.overall_status}
                    </span>
                  ) : null}
                </div>

                {complianceQuery.isLoading ? (
                  <p className="mt-5 text-sm text-ink-500 dark:text-ink-400">Loading compliance signals…</p>
                ) : complianceQuery.isError ? (
                  <p className="mt-5 text-sm text-rose dark:text-rose/90">
                    {complianceQuery.error instanceof Error ? complianceQuery.error.message : "The compliance endpoint returned an error."}
                  </p>
                ) : complianceQuery.data ? (
                  <div className="mt-5 grid gap-6">
                    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                      <StatCard label="SLSA level" value={`${complianceQuery.data.slsa.level}/${complianceQuery.data.slsa.target_level}`} detail={complianceQuery.data.slsa.verified ? "verified provenance" : "best effort"} />
                      <StatCard label="Scorecard" value={complianceQuery.data.scorecard.available ? complianceQuery.data.scorecard.score?.toFixed(1) ?? "0.0" : "n/a"} detail={complianceQuery.data.scorecard.risk_level ?? complianceQuery.data.scorecard.status} />
                      <StatCard label="Checklist pass" value={complianceQuery.data.summary.passed} detail={`${complianceQuery.data.summary.partial} partial`} />
                      <StatCard label="Checklist fail" value={complianceQuery.data.summary.failed} detail={`${complianceQuery.data.summary.unavailable} unavailable`} />
                    </div>

                    <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                      <div className="rounded-[1.5rem] border border-ink-200 bg-white/80 p-5 dark:border-ink-800 dark:bg-ink-950/50">
                        <div className="flex flex-wrap items-center gap-2">
                          <span className={clsx("rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.18em]", complianceTone(complianceQuery.data.slsa.status))}>
                            SLSA {complianceQuery.data.slsa.level}
                          </span>
                          {complianceQuery.data.source_repository ? (
                            <a href={complianceQuery.data.source_repository.url} className="text-sm text-tide hover:text-sky-600 dark:hover:text-sky-300">
                              {complianceQuery.data.source_repository.repository}
                            </a>
                          ) : null}
                        </div>
                        <dl className="mt-4 grid gap-3 text-sm text-ink-600 dark:text-ink-300">
                          <div><dt className="font-medium text-ink-900 dark:text-white">Builder</dt><dd>{complianceQuery.data.slsa.builder_id || "Unavailable"}</dd></div>
                          <div><dt className="font-medium text-ink-900 dark:text-white">Build type</dt><dd>{complianceQuery.data.slsa.build_type || "Unavailable"}</dd></div>
                          <div><dt className="font-medium text-ink-900 dark:text-white">Invocation</dt><dd>{complianceQuery.data.slsa.invocation_id || "Unavailable"}</dd></div>
                        </dl>
                        <div className="mt-4 flex flex-wrap gap-2">
                          {(complianceQuery.data.slsa.evidence ?? []).map((item) => (
                            <span key={item} className="rounded-full bg-mint/10 px-3 py-1 text-xs font-medium text-emerald-700 dark:text-emerald-300">
                              {item}
                            </span>
                          ))}
                          {(complianceQuery.data.slsa.missing ?? []).map((item) => (
                            <span key={item} className="rounded-full bg-rose/10 px-3 py-1 text-xs font-medium text-rose dark:text-rose/90">
                              missing {item}
                            </span>
                          ))}
                        </div>
                      </div>

                      <div className="rounded-[1.5rem] border border-ink-200 bg-white/80 p-5 dark:border-ink-800 dark:bg-ink-950/50">
                        <div className="flex items-center justify-between gap-3">
                          <h3 className="font-display text-xl text-ink-900 dark:text-white">OpenSSF Scorecard</h3>
                          <span className={clsx("rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.18em]", complianceTone(complianceQuery.data.scorecard.status))}>
                            {complianceQuery.data.scorecard.status}
                          </span>
                        </div>
                        <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">
                          {complianceQuery.data.scorecard.available
                            ? `${complianceQuery.data.scorecard.repository} scored ${complianceQuery.data.scorecard.score?.toFixed(1)}`
                            : complianceQuery.data.scorecard.error || "Scorecard data unavailable."}
                        </p>
                        {complianceQuery.data.scorecard.available ? (
                          <div className="mt-4 space-y-3">
                            {(complianceQuery.data.scorecard.checks ?? []).slice(0, 5).map((check) => (
                              <div key={check.name} className="rounded-2xl border border-ink-200 p-3 dark:border-ink-800">
                                <div className="flex items-center justify-between gap-3">
                                  <p className="font-medium text-ink-900 dark:text-white">{check.name}</p>
                                  <span className="text-sm text-ink-600 dark:text-ink-300">{check.score}/10</span>
                                </div>
                                {check.reason ? <p className="mt-2 text-xs text-ink-500 dark:text-ink-400">{check.reason}</p> : null}
                              </div>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </div>

                    <div className="rounded-[1.5rem] border border-ink-200 bg-white/80 p-5 dark:border-ink-800 dark:bg-ink-950/50">
                      <h3 className="font-display text-xl text-ink-900 dark:text-white">Standards checklist</h3>
                      <div className="mt-4 grid gap-4 xl:grid-cols-3">
                        {complianceQuery.data.standards.map((standard) => (
                          <article key={standard.name} className="rounded-2xl border border-ink-200 p-4 dark:border-ink-800">
                            <div className="flex items-center justify-between gap-3">
                              <h4 className="font-medium text-ink-900 dark:text-white">{standard.name}</h4>
                              <span className={clsx("rounded-full px-3 py-1 text-xs font-medium uppercase tracking-[0.18em]", complianceTone(standard.status))}>
                                {standard.status}
                              </span>
                            </div>
                            <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{standard.summary}</p>
                            <div className="mt-4 space-y-3">
                              {standard.checks.map((check) => (
                                <div key={check.id}>
                                  <div className="flex items-center gap-2">
                                    <span className={clsx("rounded-full px-2.5 py-1 text-[11px] font-medium uppercase tracking-[0.16em]", complianceTone(check.status))}>
                                      {check.status}
                                    </span>
                                    <p className="text-sm font-medium text-ink-900 dark:text-white">{check.title}</p>
                                  </div>
                                  <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">{check.detail}</p>
                                </div>
                              ))}
                            </div>
                          </article>
                        ))}
                      </div>
                      {complianceQuery.data.evidence_errors?.length ? (
                        <div className="mt-4 rounded-2xl border border-rose/30 bg-rose/8 p-4 text-sm text-rose dark:text-rose/90">
                          {complianceQuery.data.evidence_errors.join(" ")}
                        </div>
                      ) : null}
                    </div>
                  </div>
                ) : null}
              </div>
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Exports</h2>
                <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Download SBOMs and vulnerability reports in formats suited for archives, spreadsheets, and security tooling.</p>
                <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
                  {imageExportOptions.map((item) => (
                    <a
                      key={item.format}
                      href={getImageExportURL(overview.org_id, overview.image_id, item.format)}
                      className="rounded-[1.5rem] border border-ink-200 bg-white/80 px-4 py-4 text-sm transition hover:border-sky-400 hover:text-sky-700 dark:border-ink-800 dark:bg-ink-950/50 dark:hover:border-sky-600 dark:hover:text-sky-300"
                    >
                      <span className="block font-medium text-ink-900 dark:text-white">{item.label}</span>
                      <span className="mt-1 block text-xs text-ink-500 dark:text-ink-400">{item.description}</span>
                    </a>
                  ))}
                </div>
              </div>
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Artifacts</h2>
                <div className="mt-4 overflow-x-auto">
                  <table className="min-w-full text-left text-sm">
                    <thead className="text-ink-500 dark:text-ink-400">
                      <tr>
                        <th className="pb-3">Artifact</th>
                        <th className="pb-3">Created</th>
                        <th className="pb-3">Size</th>
                        <th className="pb-3">Download</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                      {overview.files.map((file) => {
                        const filename = file.key.split("/").pop() ?? file.key;
                        return (
                          <tr key={file.key}>
                            <td className="py-3 text-ink-900 dark:text-white">{filename}</td>
                            <td className="py-3 text-ink-600 dark:text-ink-300">{formatTimestamp(file.created_at)}</td>
                            <td className="py-3 text-ink-600 dark:text-ink-300">{formatBytes(file.size)}</td>
                            <td className="py-3">
                              <a
                                href={`/api/v1/scans/${overview.org_id}/${overview.image_id}/files/${filename}`}
                                className="text-tide hover:text-sky-600 dark:hover:text-sky-300"
                              >
                                Open
                              </a>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </section>
          ) : null}

          {tab === "Tags" ? (
            <section className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
              <h2 className="font-display text-2xl text-ink-900 dark:text-white">Repository tags</h2>
              <div className="mt-5 overflow-x-auto">
                <table className="min-w-full text-left text-sm">
                  <thead className="text-ink-500 dark:text-ink-400">
                    <tr>
                      <th className="pb-3">Tag / Digest</th>
                      <th className="pb-3">Image</th>
                      <th className="pb-3">Platform</th>
                      <th className="pb-3">Updated</th>
                      <th className="pb-3">Vulnerabilities</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                    {allTags.map((tagItem) => (
                      <tr key={`${tagItem.org_id}/${tagItem.image_id}`}>
                        <td className="py-3 font-medium text-ink-900 dark:text-white">{tagItem.tag || tagItem.digest || "unknown"}</td>
                        <td className="py-3">
                          <Link to={`/images/${tagItem.org_id}/${tagItem.image_id}`} className="text-tide hover:text-sky-600 dark:hover:text-sky-300">
                            {tagItem.image_name}
                          </Link>
                        </td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{tagItem.platform || "default"}</td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{formatTimestamp(tagItem.updated_at)}</td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{tagItem.vulnerability_summary.total}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          {tab === "Comparison" ? (
            <section className="grid gap-6">
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Compare this image</h2>
                <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Choose another stored image and Otter will request the persisted diff report from the backend.</p>
                <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                  <select
                    aria-label="Comparison target"
                    value={comparisonTargetId}
                    onChange={(event) => setComparisonTargetId(event.target.value)}
                    className="flex-1 rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
                  >
                    <option value="">Select a comparison target</option>
                    {comparisonCandidates.map((candidate) => (
                      <option key={`${candidate.org_id}/${candidate.image_id}`} value={`${candidate.org_id}/${candidate.image_id}`}>
                        {candidate.image_name}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    disabled={!comparisonTargetId}
                    onClick={() => {
                      const target = comparisonCandidates.find((candidate) => `${candidate.org_id}/${candidate.image_id}` === comparisonTargetId);
                      if (target) {
                        comparisonMutation.mutate(target);
                      }
                    }}
                    className="rounded-2xl bg-ink-900 px-5 py-3 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white dark:text-ink-900"
                  >
                    Run comparison
                  </button>
                </div>
              </div>

              {comparisonMutation.isPending ? <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">Building comparison…</div> : null}
              {comparisonMutation.isError ? (
                <EmptyState
                  title="Comparison failed"
                  description={comparisonMutation.error instanceof Error ? comparisonMutation.error.message : "The comparison endpoint returned an error."}
                />
              ) : null}
              {comparisonMutation.data ? (
                <div className="grid gap-6">
                  <section className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                    <h3 className="font-display text-2xl text-ink-900 dark:text-white">Summary</h3>
                    <p className="mt-3 text-base text-ink-700 dark:text-ink-200">{comparisonMutation.data.comparison.summary.message}</p>
                    <div className="mt-5 grid gap-3 sm:grid-cols-3">
                      <StatCard label="Package delta" value={comparisonMutation.data.comparison.summary.package_delta} />
                      <StatCard label="Vulnerability delta" value={comparisonMutation.data.comparison.summary.vulnerability_delta} />
                      <StatCard label="Changed layers" value={comparisonMutation.data.comparison.summary.changed_layer_delta} />
                    </div>
                    <div className="mt-5">
                      <a
                        href={getComparisonExportURL(comparisonMutation.data.comparison_id)}
                        className="inline-flex rounded-full bg-ink-900 px-4 py-2 text-sm font-medium text-white dark:bg-white dark:text-ink-900"
                      >
                        Download comparison JSON
                      </a>
                    </div>
                  </section>
                  <section className="grid gap-4 xl:grid-cols-3">
                    <StatCard label="New vulnerabilities" value={comparisonMutation.data.comparison.vulnerability_diff.new.length} />
                    <StatCard label="Fixed vulnerabilities" value={comparisonMutation.data.comparison.vulnerability_diff.fixed.length} />
                    <StatCard label="Changed packages" value={comparisonMutation.data.comparison.package_diff.changed.length} />
                  </section>
                </div>
              ) : null}
            </section>
          ) : null}

          {tab === "Vulnerabilities" ? (
            <section className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
              <div className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
                <div>
                  <h2 className="font-display text-2xl text-ink-900 dark:text-white">Vulnerabilities</h2>
                  <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Filter the merged Grype and Trivy findings by severity, advisory state, or package name.</p>
                </div>
                <div className="grid gap-3 sm:grid-cols-3">
                  <input
                    aria-label="Search vulnerabilities"
                    value={searchFilter}
                    onChange={(event) => setSearchFilter(event.target.value)}
                    placeholder="Search CVE or package"
                    className="rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
                  />
                  <select
                    aria-label="Filter vulnerability severity"
                    value={severityFilter}
                    onChange={(event) => setSeverityFilter(event.target.value as "" | Severity)}
                    className="rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
                  >
                    {severityFilterOptions.map((option) => (
                      <option key={option || "all"} value={option}>
                        {option || "All severities"}
                      </option>
                    ))}
                  </select>
                  <select
                    aria-label="Filter vulnerability status"
                    value={statusFilter}
                    onChange={(event) => setStatusFilter(event.target.value)}
                    className="rounded-2xl border border-ink-200 bg-white/80 px-4 py-3 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-950/60 dark:text-white"
                  >
                    {statusFilterOptions.map((option) => (
                      <option key={option || "all"} value={option}>
                        {option || "All statuses"}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="mt-6 overflow-x-auto">
                <table className="min-w-full text-left text-sm">
                  <thead className="text-ink-500 dark:text-ink-400">
                    <tr>
                      <th className="pb-3">Severity</th>
                      <th className="pb-3">Vulnerability</th>
                      <th className="pb-3">Package</th>
                      <th className="pb-3">Fix version</th>
                      <th className="pb-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                    {filteredVulnerabilities.map((vulnerability) => (
                      <tr key={`${vulnerability.id}-${vulnerability.package_name}-${vulnerability.package_version}`}>
                        <td className="py-3"><SeverityPill severity={vulnerability.severity} /></td>
                        <td className="py-3">
                          <div className="font-medium text-ink-900 dark:text-white">{vulnerability.id}</div>
                          <div className="mt-1 max-w-md text-xs text-ink-500 dark:text-ink-400">{vulnerability.title || vulnerability.description}</div>
                        </td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{vulnerability.package_name} {vulnerability.package_version}</td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{vulnerability.fix_version || "Unavailable"}</td>
                        <td className="py-3 text-ink-600 dark:text-ink-300">{vulnerability.status}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {!filteredVulnerabilities.length ? <p className="mt-6 text-sm text-ink-500 dark:text-ink-400">No vulnerabilities matched the current filters.</p> : null}
            </section>
          ) : null}

          {tab === "SBOM" ? (
            <section className="grid gap-6">
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">SBOM package inventory</h2>
                <div className="mt-5 grid gap-3 sm:grid-cols-3">
                  <StatCard label="Packages" value={sbomQuery.data?.package_count ?? 0} />
                  <StatCard label="Dependency roots" value={sbomQuery.data?.dependency_roots.length ?? 0} />
                  <StatCard label="Format" value={sbomQuery.data?.format ?? "cyclonedx"} />
                </div>
                <div className="mt-5 flex flex-wrap gap-2">
                  {sbomQuery.data?.license_summary.map((license) => (
                    <span key={license.license} className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">
                      {license.license} · {license.count}
                    </span>
                  ))}
                </div>
              </div>
              <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                  <h3 className="font-display text-xl text-ink-900 dark:text-white">Packages</h3>
                  <div className="mt-4 overflow-x-auto">
                    <table className="min-w-full text-left text-sm">
                      <thead className="text-ink-500 dark:text-ink-400">
                        <tr>
                          <th className="pb-3">Name</th>
                          <th className="pb-3">Version</th>
                          <th className="pb-3">Type</th>
                          <th className="pb-3">Licenses</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                        {sbomQuery.data?.packages.slice(0, 50).map((pkg) => (
                          <tr key={pkg.id}>
                            <td className="py-3 text-ink-900 dark:text-white">{pkg.name}</td>
                            <td className="py-3 text-ink-600 dark:text-ink-300">{pkg.version || "Unknown"}</td>
                            <td className="py-3 text-ink-600 dark:text-ink-300">{pkg.type || "Unknown"}</td>
                            <td className="py-3 text-ink-600 dark:text-ink-300">{pkg.licenses?.join(", ") || "Unknown"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                  <h3 className="font-display text-xl text-ink-900 dark:text-white">Dependency tree</h3>
                  <div className="mt-4 space-y-3">
                    {dependencyTree
                      .filter((node) => overview.dependency_roots.includes(node.id))
                      .map((node) => (
                        <DependencyTreeCard key={node.id} node={node} depth={0} tree={dependencyTree} />
                      ))}
                    {!dependencyTree.length ? <p className="text-sm text-ink-500 dark:text-ink-400">No dependency tree data was returned.</p> : null}
                  </div>
                </div>
              </div>
            </section>
          ) : null}

          {tab === "Attestations" ? (
            <section className="grid gap-6">
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Attestation coverage</h2>
                <div className="mt-5 grid gap-3 sm:grid-cols-4">
                  <StatCard label="Records" value={attestationsQuery.data?.summary.total ?? 0} />
                  <StatCard label="Signatures" value={attestationsQuery.data?.summary.signatures ?? 0} />
                  <StatCard label="Attestations" value={attestationsQuery.data?.summary.attestations ?? 0} />
                  <StatCard label="Provenance" value={attestationsQuery.data?.summary.provenance ?? 0} />
                </div>
              </div>
              {attestationsQuery.isError ? (
                <EmptyState
                  title="Attestations unavailable"
                  description={attestationsQuery.error instanceof Error ? attestationsQuery.error.message : "Registry discovery failed."}
                />
              ) : (
                <div className="grid gap-4 xl:grid-cols-2">
                  {[...(attestationsQuery.data?.signatures ?? []), ...(attestationsQuery.data?.attestations ?? [])].map((record) => (
                    <article key={`${record.kind}-${record.digest}`} className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                      <div className="flex items-start justify-between gap-4">
                        <div>
                          <p className="text-sm uppercase tracking-[0.22em] text-ink-500 dark:text-ink-400">{record.kind}</p>
                          <h3 className="mt-2 font-display text-xl text-ink-900 dark:text-white">{record.signer || record.predicate_type || record.source}</h3>
                        </div>
                        <span className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">{record.verification_status}</span>
                      </div>
                      <dl className="mt-4 grid gap-3 text-sm text-ink-600 dark:text-ink-300">
                        <div><dt className="font-medium text-ink-900 dark:text-white">Digest</dt><dd>{record.digest}</dd></div>
                        {record.timestamp ? <div><dt className="font-medium text-ink-900 dark:text-white">Timestamp</dt><dd>{formatTimestamp(record.timestamp)}</dd></div> : null}
                        {record.provenance?.builder_id ? <div><dt className="font-medium text-ink-900 dark:text-white">Builder</dt><dd>{record.provenance.builder_id}</dd></div> : null}
                      </dl>
                    </article>
                  ))}
                </div>
              )}
            </section>
          ) : null}

          {tab === "Advisories" ? (
            <section className="grid gap-6">
              <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                <h2 className="font-display text-2xl text-ink-900 dark:text-white">Advisories and VEX status</h2>
                <div className="mt-5 grid gap-3 sm:grid-cols-4">
                  <StatCard label="Affected" value={vulnerabilitiesQuery.data?.summary.by_status?.affected ?? 0} />
                  <StatCard label="Not affected" value={vulnerabilitiesQuery.data?.summary.by_status?.not_affected ?? 0} />
                  <StatCard label="Fixed" value={vulnerabilitiesQuery.data?.summary.by_status?.fixed ?? 0} />
                  <StatCard label="Investigating" value={vulnerabilitiesQuery.data?.summary.by_status?.under_investigation ?? 0} />
                </div>
              </div>
              <div className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                  <h3 className="font-display text-xl text-ink-900 dark:text-white">Advisory-backed vulnerabilities</h3>
                  <div className="mt-4 space-y-4">
                    {filteredAdvisories(vulnerabilitiesQuery.data?.vulnerabilities ?? []).map((vulnerability) => (
                      <article key={`${vulnerability.id}-${vulnerability.package_name}`} className="rounded-2xl border border-ink-200 p-4 dark:border-ink-800">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <p className="font-medium text-ink-900 dark:text-white">{vulnerability.id}</p>
                            <p className="text-sm text-ink-600 dark:text-ink-300">{vulnerability.package_name} {vulnerability.package_version}</p>
                          </div>
                          <div className="flex items-center gap-2">
                            <SeverityPill severity={vulnerability.severity} />
                            <span className="rounded-full bg-ink-100 px-3 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">{vulnerability.status}</span>
                          </div>
                        </div>
                        {vulnerability.advisory?.status_notes ? (
                          <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{vulnerability.advisory.status_notes}</p>
                        ) : null}
                      </article>
                    ))}
                    {!filteredAdvisories(vulnerabilitiesQuery.data?.vulnerabilities ?? []).length ? (
                      <p className="text-sm text-ink-500 dark:text-ink-400">No advisory overlays have been imported for this image.</p>
                    ) : null}
                  </div>
                </div>
                <div className="rounded-[2rem] border border-white/60 bg-white/75 p-6 shadow-haze dark:border-white/10 dark:bg-ink-900/80">
                  <h3 className="font-display text-xl text-ink-900 dark:text-white">VEX documents</h3>
                  <div className="mt-4 space-y-3">
                    {vulnerabilitiesQuery.data?.vex_documents.map((document) => (
                      <div key={document.document_id} className="rounded-2xl border border-ink-200 p-4 dark:border-ink-800">
                        <p className="font-medium text-ink-900 dark:text-white">{document.filename || document.document_id}</p>
                        <p className="mt-1 text-sm text-ink-600 dark:text-ink-300">{document.author || "Unknown author"} · version {document.version}</p>
                      </div>
                    ))}
                    {!vulnerabilitiesQuery.data?.vex_documents.length ? (
                      <p className="text-sm text-ink-500 dark:text-ink-400">No VEX documents are stored for this image.</p>
                    ) : null}
                  </div>
                </div>
              </div>
            </section>
          ) : null}
        </div>
      </section>
    </div>
  );
}

function DependencyTreeCard({
  node,
  depth,
  tree
}: {
  node: DependencyNode & { children?: DependencyNode[] };
  depth: number;
  tree: Array<DependencyNode & { children?: DependencyNode[] }>;
}) {
  if (depth > 2) {
    return null;
  }

  return (
    <div className={clsx("rounded-2xl border border-ink-200 p-4 dark:border-ink-800", depth > 0 ? "ml-4" : "")}>
      <p className="font-medium text-ink-900 dark:text-white">{node.name} {node.version}</p>
      {node.depends_on?.length ? (
        <div className="mt-3 space-y-3">
          {node.depends_on.map((dependencyId) => {
            const child = tree.find((candidate) => candidate.id === dependencyId);
            return child ? <DependencyTreeCard key={child.id} node={child} depth={depth + 1} tree={tree} /> : null;
          })}
        </div>
      ) : (
        <p className="mt-2 text-sm text-ink-500 dark:text-ink-400">No further dependencies.</p>
      )}
    </div>
  );
}

function filteredAdvisories(vulnerabilities: VulnerabilityRecord[]) {
  return vulnerabilities.filter((vulnerability) => vulnerability.status !== "affected" || vulnerability.advisory);
}
