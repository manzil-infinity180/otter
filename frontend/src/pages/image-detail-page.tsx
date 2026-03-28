import { useMutation, useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { startTransition, useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";

import { EmptyState } from "../components/empty-state";
import { JSONViewer } from "../components/json-viewer";
import { SeverityPill } from "../components/severity-pill";
import { StatCard } from "../components/stat-card";
import {
  compareImages,
  getAttestations,
  getComparisonExportURL,
  getCompliance,
  getImageExportURL,
  getImageTags,
  getOverview,
  getSbom,
  getScanArtifactJSON,
  getVulnerabilities,
  listCatalog,
  startScan
} from "../lib/api";
import { buildDependencyChildren, complianceTone, formatBytes, formatTimestamp, vulnerabilityChips } from "../lib/format";
import type {
  CatalogItem,
  DependencyNode,
  ImageExportFormat,
  ScanFile,
  Severity,
  VulnerabilityRecord
} from "../lib/types";

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
  const navigate = useNavigate();
  const { orgId = "", imageId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const tab = (searchParams.get("tab") as TabKey | null) ?? "Overview";
  const [comparisonTargetId, setComparisonTargetId] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"" | Severity>("");
  const [statusFilter, setStatusFilter] = useState("");
  const [searchFilter, setSearchFilter] = useState("");
  const [selectedArtifact, setSelectedArtifact] = useState<string | null>(null);
  const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityRecord | null>(null);
  const [queuedTags, setQueuedTags] = useState<Record<string, boolean>>({});
  const [tagSearch, setTagSearch] = useState("");
  const [tagPage, setTagPage] = useState(1);
  const [pkgSearch, setPkgSearch] = useState("");
  const [pkgPage, setPkgPage] = useState(1);

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

  const artifactQuery = useQuery({
    queryKey: ["artifact-json", orgId, imageId, selectedArtifact],
    queryFn: () => getScanArtifactJSON(orgId, imageId, selectedArtifact ?? ""),
    enabled: Boolean(selectedArtifact)
  });

  const tagsQuery = useQuery({
    queryKey: ["image-tags", orgId, imageId, tagSearch, tagPage],
    queryFn: () =>
      getImageTags(orgId, imageId, {
        query: tagSearch.trim() || undefined,
        page: tagPage,
        pageSize: 12
      }),
    enabled: Boolean(orgId && imageId && tab === "Tags")
  });

  const comparisonCandidates = useMemo(() => {
    return (catalogQuery.data?.items ?? [])
      .filter((item) => item.repository === overviewQuery.data?.repository)
      .filter((item) => !(item.org_id === orgId && item.image_id === imageId));
  }, [catalogQuery.data?.items, imageId, orgId, overviewQuery.data?.repository]);

  useEffect(() => {
    if (!comparisonCandidates.length) {
      if (comparisonTargetId) {
        setComparisonTargetId("");
      }
      return;
    }
    if (comparisonCandidates.some((candidate) => `${candidate.org_id}/${candidate.image_id}` === comparisonTargetId)) {
      return;
    }
    setComparisonTargetId(`${comparisonCandidates[0].org_id}/${comparisonCandidates[0].image_id}`);
  }, [comparisonCandidates, comparisonTargetId]);

  useEffect(() => {
    setTagPage(1);
  }, [imageId, orgId]);

  const comparisonMutation = useMutation({
    mutationFn: (target: CatalogItem) =>
      compareImages({
        image1: overviewQuery.data!.image_name,
        image2: target.image_name,
        org1: overviewQuery.data!.org_id,
        org2: target.org_id
      })
  });
  const tagScanMutation = useMutation({
    mutationFn: (imageName: string) => startScan(imageName, overviewQuery.data?.org_id || orgId),
    onSuccess: (_, imageName) => {
      setQueuedTags((current) => ({ ...current, [imageName]: true }));
    }
  });

  const vulnerabilityRecords = vulnerabilitiesQuery.data?.vulnerabilities ?? [];
  const hasVulnerabilityFilters = Boolean(searchFilter.trim() || severityFilter || statusFilter);
  const filteredVulnerabilities = useMemo(() => {
    const search = searchFilter.trim().toLowerCase();
    return vulnerabilityRecords.filter((vulnerability) => {
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
  }, [searchFilter, severityFilter, statusFilter, vulnerabilityRecords]);

  const dependencyTree = useMemo(() => buildDependencyChildren(sbomQuery.data?.dependency_tree ?? []), [sbomQuery.data?.dependency_tree]);
  const overview = overviewQuery.data;

  if (overviewQuery.isLoading) {
    return <div className="rounded-xl border border-ink-200 bg-white p-8 dark:border-ink-800 dark:bg-ink-900">Loading image detail...</div>;
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
  const scannerWarnings = collectScannerWarnings(overview.files);
  const storedTagCount = allTags.length;
  const tagItems = tagsQuery.data?.items ?? [];
  const totalTagPages = Math.max(1, Math.ceil((tagsQuery.data?.total ?? 0) / (tagsQuery.data?.page_size ?? 12)));

  return (
    <>
      <div className="space-y-6">
        <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900 sm:p-8">
          <div className="flex flex-wrap items-start justify-between gap-6">
            <div className="min-w-0 space-y-2">
              <Link to="/directory" className="text-sm text-tide hover:text-sky-600 dark:hover:text-sky-300">
                Back to directory
              </Link>
              <p className="truncate text-xs uppercase tracking-wider text-ink-500 dark:text-ink-400" title={overview.registry}>
                {overview.registry}
              </p>
              <h1 className="truncate font-display text-3xl tracking-tight text-ink-900 dark:text-white" title={overview.repository_path || overview.image_name}>
                {overview.repository_path || overview.image_name}
              </h1>
              <p className="max-w-3xl truncate text-base text-ink-600 dark:text-ink-300" title={overview.image_name}>
                {overview.image_name}
              </p>
              <div className="flex flex-wrap gap-2">
                {overview.tag ? <span className="rounded-md bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">tag {overview.tag}</span> : null}
                {(overview.scanners ?? []).map((scanner) => (
                  <span key={scanner} className="rounded-md bg-sky-100 px-2.5 py-1 text-xs font-medium text-sky-700 dark:bg-sky-950/70 dark:text-sky-200">
                    {scanner}
                  </span>
                ))}
              </div>
              {allTags.length > 1 ? (
                <label className="block max-w-xs space-y-1.5">
                  <span className="text-xs uppercase tracking-wide text-ink-500 dark:text-ink-400">Stored version</span>
                  <select
                    aria-label="Stored tag"
                    value={`${overview.org_id}/${overview.image_id}`}
                    onChange={(event) => {
                      const [nextOrgId, nextImageId] = event.target.value.split("/");
                      navigate(`/images/${nextOrgId}/${nextImageId}`);
                    }}
                    className="w-full rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-900 dark:text-white"
                  >
                    {allTags.map((tagItem) => (
                      <option key={`${tagItem.org_id}/${tagItem.image_id}`} value={`${tagItem.org_id}/${tagItem.image_id}`}>
                        {tagItem.tag || tagItem.digest || tagItem.image_name}
                      </option>
                    ))}
                  </select>
                </label>
              ) : null}
            </div>
            <div className="rounded-lg bg-ink-900 px-4 py-3 text-white dark:bg-white dark:text-ink-900">
              <p className="text-xs uppercase tracking-wider">Last indexed</p>
              <p className="mt-1 font-display text-xl">{formatTimestamp(overview.updated_at)}</p>
              <p className="mt-1 text-sm opacity-75">{overview.org_id} / {overview.image_id}</p>
            </div>
          </div>

          <div className="mt-6 grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
            <StatCard label="Packages" value={overview.package_count} />
            <StatCard label="Vulnerabilities" value={overview.vulnerability_summary.total} detail={`${overview.vulnerability_summary.fixable} fixable`} />
            <StatCard label="Artifacts" value={overview.files.length} detail={overview.storage_backend} />
            <StatCard label="Related tags" value={allTags.length} detail="Same repository" />
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            {vulnerabilityChips(overview.vulnerability_summary).map((chip) => (
              <SeverityPill key={chip.severity} severity={chip.severity} count={chip.count} />
            ))}
          </div>
        </section>

        <section className="grid gap-6 xl:grid-cols-[200px_minmax(0,1fr)]">
          <aside className="rounded-xl border border-ink-200 bg-white p-2 dark:border-ink-800 dark:bg-ink-900">
            <div role="tablist" aria-orientation="vertical" className="flex gap-1 overflow-x-auto xl:flex-col">
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
                      "min-w-fit rounded-md px-3 py-2 text-left text-sm font-medium transition",
                      active
                        ? "bg-ink-900 text-white dark:bg-white dark:text-ink-900"
                        : "text-ink-600 hover:bg-ink-100 hover:text-ink-900 dark:text-ink-300 dark:hover:bg-ink-800 dark:hover:text-white"
                    )}
                  >
                    {label}
                  </button>
                );
              })}
            </div>
          </aside>

          <div className="min-w-0 space-y-6">
            {tab === "Overview" ? (
              <section className="grid gap-6">
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Scan summary</h2>
                  <div className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
                    <StatCard label="Registry" value={overview.registry || "local"} />
                    <StatCard label="Repository" value={overview.repository_path || overview.image_name} />
                    <StatCard label="Fixable" value={overview.vulnerability_summary.fixable} />
                    <StatCard label="Unfixable" value={overview.vulnerability_summary.unfixable} />
                  </div>
                  <div className="mt-5 grid gap-3 lg:grid-cols-2">
                    <div className="rounded-lg border border-ink-200 bg-ink-50 p-4 dark:border-ink-800 dark:bg-ink-950">
                      <p className="text-xs font-medium uppercase tracking-wide text-ink-500 dark:text-ink-400">Full registry</p>
                      <p className="mt-2 break-all text-sm font-medium text-ink-900 dark:text-white">{overview.registry || "local"}</p>
                    </div>
                    <div className="rounded-lg border border-ink-200 bg-ink-50 p-4 dark:border-ink-800 dark:bg-ink-950">
                      <p className="text-xs font-medium uppercase tracking-wide text-ink-500 dark:text-ink-400">Full repository</p>
                      <p className="mt-2 break-all text-sm font-medium text-ink-900 dark:text-white">{overview.repository_path || overview.image_name}</p>
                    </div>
                  </div>
                  {scannerWarnings.length ? (
                    <div className="mt-5 space-y-3">
                      {scannerWarnings.map((warning) => (
                        <div key={warning.scanner} className="rounded-md border border-amber-300/40 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-500/20 dark:bg-amber-950/30 dark:text-amber-100">
                          <span className="font-medium">{warning.scanner} unavailable.</span> {warning.message}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <div className="flex flex-wrap items-start justify-between gap-4">
                    <div>
                      <h2 className="font-display text-xl text-ink-900 dark:text-white">Compliance posture</h2>
                      <p className="mt-2 max-w-3xl text-sm text-ink-600 dark:text-ink-300">
                        {complianceQuery.data?.scope_note ?? "Best-effort standards tracking based on provenance, signatures, vulnerabilities, and upstream project posture."}
                      </p>
                    </div>
                    {complianceQuery.data ? (
                      <span className={clsx("rounded-md px-2.5 py-1 text-xs font-medium uppercase tracking-wide", complianceTone(complianceQuery.data.summary.overall_status))}>
                        {complianceQuery.data.summary.overall_status}
                      </span>
                    ) : null}
                  </div>

                  {complianceQuery.isLoading ? (
                    <p className="mt-5 text-sm text-ink-500 dark:text-ink-400">Loading compliance signals...</p>
                  ) : complianceQuery.isError ? (
                    <p className="mt-5 text-sm text-rose">
                      {complianceQuery.error instanceof Error ? complianceQuery.error.message : "The compliance endpoint returned an error."}
                    </p>
                  ) : complianceQuery.data ? (
                    <div className="mt-5 grid gap-6">
                      <div className="grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
                        <StatCard label="SLSA level" value={`${complianceQuery.data.slsa.level}/${complianceQuery.data.slsa.target_level}`} detail={complianceQuery.data.slsa.verified ? "verified provenance" : "best effort"} />
                        <StatCard label="Scorecard" value={complianceQuery.data.scorecard.available ? complianceQuery.data.scorecard.score?.toFixed(1) ?? "0.0" : "n/a"} detail={complianceQuery.data.scorecard.risk_level ?? complianceQuery.data.scorecard.status} />
                        <StatCard label="Checklist pass" value={complianceQuery.data.summary.passed} detail={`${complianceQuery.data.summary.partial} partial`} />
                        <StatCard label="Checklist fail" value={complianceQuery.data.summary.failed} detail={`${complianceQuery.data.summary.unavailable} unavailable`} />
                      </div>

                      <div className="grid gap-6 2xl:grid-cols-[1.1fr_0.9fr]">
                        <div className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={clsx("rounded-md px-2.5 py-1 text-xs font-medium uppercase tracking-wide", complianceTone(complianceQuery.data.slsa.status))}>
                              SLSA {complianceQuery.data.slsa.level}
                            </span>
                            {complianceQuery.data.source_repository ? (
                              <a href={complianceQuery.data.source_repository.url} className="text-sm text-tide hover:text-sky-600 dark:hover:text-sky-300">
                                {complianceQuery.data.source_repository.repository}
                              </a>
                            ) : null}
                          </div>
                          <dl className="mt-4 grid gap-3 text-sm text-ink-600 dark:text-ink-300">
                            <div><dt className="font-medium text-ink-900 dark:text-white">Builder</dt><dd className="truncate" title={complianceQuery.data.slsa.builder_id}>{complianceQuery.data.slsa.builder_id || "Unavailable"}</dd></div>
                            <div><dt className="font-medium text-ink-900 dark:text-white">Build type</dt><dd className="truncate" title={complianceQuery.data.slsa.build_type}>{complianceQuery.data.slsa.build_type || "Unavailable"}</dd></div>
                            <div><dt className="font-medium text-ink-900 dark:text-white">Invocation</dt><dd className="truncate" title={complianceQuery.data.slsa.invocation_id}>{complianceQuery.data.slsa.invocation_id || "Unavailable"}</dd></div>
                          </dl>
                          <div className="mt-4 flex flex-wrap gap-2">
                            {(complianceQuery.data.slsa.evidence ?? []).map((item) => (
                              <span key={item} className="rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-700 dark:bg-emerald-950/40 dark:text-emerald-300">
                                {item}
                              </span>
                            ))}
                            {(complianceQuery.data.slsa.missing ?? []).map((item) => (
                              <span key={item} className="rounded-md bg-rose/10 px-2.5 py-1 text-xs font-medium text-rose">
                                missing {item}
                              </span>
                            ))}
                          </div>
                        </div>

                        <div className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                          <div className="flex items-center justify-between gap-3">
                            <h3 className="font-display text-lg text-ink-900 dark:text-white">OpenSSF Scorecard</h3>
                            <span className={clsx("rounded-md px-2.5 py-1 text-xs font-medium uppercase tracking-wide", complianceTone(complianceQuery.data.scorecard.status))}>
                              {complianceQuery.data.scorecard.status}
                            </span>
                          </div>
                          <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">
                            {complianceQuery.data.scorecard.available
                              ? `${complianceQuery.data.scorecard.repository} scored ${complianceQuery.data.scorecard.score?.toFixed(1)}`
                              : complianceQuery.data.scorecard.error || "Scorecard data unavailable."}
                          </p>
                          {!complianceQuery.data.scorecard.available ? (
                            <div className="mt-4 rounded-lg border border-ink-200 bg-white p-4 text-sm text-ink-600 dark:border-ink-800 dark:bg-ink-900 dark:text-ink-300">
                              Otter only shows OpenSSF Scorecard when it can infer a public GitHub repository from provenance or image metadata. For this image, no GitHub source evidence was discovered.
                            </div>
                          ) : null}
                          {complianceQuery.data.scorecard.available ? (
                            <div className="mt-4 space-y-3">
                              {(complianceQuery.data.scorecard.checks ?? []).slice(0, 5).map((check) => (
                                <div key={check.name} className="rounded-lg border border-ink-200 p-3 dark:border-ink-800">
                                  <div className="flex items-center justify-between gap-3">
                                    <p className="font-medium text-ink-900 dark:text-white">{check.name}</p>
                                    <span className="text-sm text-ink-600 dark:text-ink-300">{check.score}/10</span>
                                  </div>
                                  {check.reason ? <p className="mt-1 text-xs text-ink-500 dark:text-ink-400">{check.reason}</p> : null}
                                </div>
                              ))}
                            </div>
                          ) : null}
                        </div>
                      </div>

                      <div className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                        <h3 className="font-display text-lg text-ink-900 dark:text-white">Standards checklist</h3>
                        <div className="mt-4 grid gap-4 2xl:grid-cols-3">
                          {complianceQuery.data.standards.map((standard) => (
                            <article key={standard.name} className="rounded-lg border border-ink-200 p-4 dark:border-ink-800">
                              <div className="flex items-center justify-between gap-3">
                                <h4 className="font-medium text-ink-900 dark:text-white">{standard.name}</h4>
                                <span className={clsx("rounded-md px-2.5 py-1 text-xs font-medium uppercase tracking-wide", complianceTone(standard.status))}>
                                  {standard.status}
                                </span>
                              </div>
                              <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{standard.summary}</p>
                              <div className="mt-4 space-y-3">
                                {standard.checks.map((check) => (
                                  <div key={check.id}>
                                    <div className="flex items-center gap-2">
                                      <span className={clsx("rounded-md px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide", complianceTone(check.status))}>
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
                          <div className="mt-4 rounded-md border border-rose/30 bg-rose/10 p-4 text-sm text-rose">
                            {complianceQuery.data.evidence_errors.join(" ")}
                          </div>
                        ) : null}
                      </div>
                    </div>
                  ) : null}
                </div>
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Exports</h2>
                  <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Download SBOMs and vulnerability reports in formats suited for archives, spreadsheets, and security tooling.</p>
                  <div className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-5">
                    {imageExportOptions.map((item) => (
                      <a
                        key={item.format}
                        href={getImageExportURL(overview.org_id, overview.image_id, item.format)}
                        className="rounded-lg border border-ink-200 bg-ink-50 px-4 py-3 text-sm transition hover:border-tide hover:text-tide dark:border-ink-800 dark:bg-ink-950 dark:hover:border-sky-600 dark:hover:text-sky-300"
                      >
                        <span className="block font-medium text-ink-900 dark:text-white">{item.label}</span>
                        <span className="mt-1 block text-xs text-ink-500 dark:text-ink-400">{item.description}</span>
                      </a>
                    ))}
                  </div>
                </div>
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Artifacts</h2>
                  <div className="mt-4 overflow-x-auto">
                    <table className="min-w-[760px] text-left text-sm">
                      <thead className="text-ink-500 dark:text-ink-400">
                        <tr>
                          <th className="pb-3">Artifact</th>
                          <th className="pb-3">Created</th>
                          <th className="pb-3">Size</th>
                          <th className="pb-3">Open</th>
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
                                {filename.endsWith(".json") ? (
                                  <button
                                    type="button"
                                    onClick={() => setSelectedArtifact(filename)}
                                    className="text-tide hover:text-sky-600 dark:hover:text-sky-300"
                                  >
                                    Open
                                  </button>
                                ) : (
                                  <span className="text-ink-400 dark:text-ink-500">n/a</span>
                                )}
                              </td>
                              <td className="py-3">
                                <a
                                  href={`/api/v1/scans/${overview.org_id}/${overview.image_id}/files/${filename}`}
                                  className="text-tide hover:text-sky-600 dark:hover:text-sky-300"
                                >
                                  Download
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
              <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
                  <div>
                    <h2 className="font-display text-xl text-ink-900 dark:text-white">Repository tags</h2>
                    <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">
                      Browse stored versions and best-effort public registry tags for this repository. Stored tags open directly, and public tags can be queued for scanning.
                    </p>
                  </div>
                  <label className="block w-full max-w-sm">
                    <span className="sr-only">Filter repository tags</span>
                    <input
                      aria-label="Filter repository tags"
                      value={tagSearch}
                      onChange={(event) => {
                        setTagSearch(event.target.value);
                        setTagPage(1);
                      }}
                      placeholder="Filter tags or digests"
                      className="w-full rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-900 dark:text-white"
                    />
                  </label>
                </div>
                <p className="mt-4 text-sm text-ink-500 dark:text-ink-400">
                  Otter already has {storedTagCount} stored tag{storedTagCount === 1 ? "" : "s"} for this repository. This view adds public registry tags when they can be listed.
                </p>
                {tagsQuery.data?.remote_tag_error ? (
                  <div className="mt-5 rounded-md border border-amber-300/40 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-500/20 dark:bg-amber-950/30 dark:text-amber-100">
                    {tagsQuery.data.remote_tag_error}
                  </div>
                ) : null}
                {tagsQuery.isLoading ? (
                  <p className="mt-6 text-sm text-ink-500 dark:text-ink-400">Loading repository tags...</p>
                ) : tagsQuery.isError ? (
                  <EmptyState
                    title="Repository tags unavailable"
                    description={tagsQuery.error instanceof Error ? tagsQuery.error.message : "The tag listing endpoint returned an error."}
                  />
                ) : (
                  <>
                    <div className="mt-5 overflow-x-auto">
                      <table className="min-w-[940px] text-left text-sm">
                        <thead className="text-ink-500 dark:text-ink-400">
                          <tr>
                            <th className="pb-3 pr-6">Tag / Digest</th>
                            <th className="pb-3 pr-6">Status</th>
                            <th className="pb-3 pr-6">Image</th>
                            <th className="pb-3 pr-6">Updated</th>
                            <th className="pb-3 pr-6">Vulnerabilities</th>
                            <th className="pb-3">Action</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                          {tagItems.map((tagItem) => {
                            const tagLabel = tagItem.tag || tagItem.digest || "unknown";
                            const imageName = tagItem.image_name || buildTaggedImageName(overview.repository || overview.image_name, tagItem.tag || "");
                            return (
                              <tr key={`${tagItem.tag || tagItem.digest}-${tagItem.org_id || "remote"}`}>
                                <td className="py-4 pr-6 align-top">
                                  <div className="font-medium text-ink-900 dark:text-white">{tagLabel}</div>
                                  {tagItem.current ? (
                                    <span className="mt-1 inline-flex rounded-md bg-sky-100 px-2 py-0.5 text-[11px] uppercase tracking-wide text-sky-800 dark:bg-sky-950/40 dark:text-sky-200">
                                      current
                                    </span>
                                  ) : null}
                                </td>
                                <td className="py-4 pr-6 align-top">
                                  <span
                                    className={clsx(
                                      "inline-flex rounded-md px-2 py-0.5 text-[11px] uppercase tracking-wide",
                                      tagItem.scanned
                                        ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300"
                                        : "bg-ink-100 text-ink-700 dark:bg-ink-800 dark:text-ink-200"
                                    )}
                                  >
                                    {tagItem.scanned ? "scanned" : "public only"}
                                  </span>
                                </td>
                                <td className="py-4 pr-6 align-top text-ink-600 dark:text-ink-300">
                                  {tagItem.scanned && tagItem.org_id && tagItem.image_id ? (
                                    <Link to={`/images/${tagItem.org_id}/${tagItem.image_id}`} className="break-all text-tide hover:text-sky-600 dark:hover:text-sky-300">
                                      {tagItem.image_name || imageName}
                                    </Link>
                                  ) : (
                                    <span className="break-all">{imageName}</span>
                                  )}
                                </td>
                                <td className="py-4 pr-6 align-top text-ink-600 dark:text-ink-300">
                                  {tagItem.updated_at ? formatTimestamp(tagItem.updated_at) : "Not scanned yet"}
                                </td>
                                <td className="py-4 pr-6 align-top text-ink-600 dark:text-ink-300">
                                  {tagItem.scanned ? tagItem.vulnerability_summary?.total ?? 0 : "n/a"}
                                </td>
                                <td className="py-4 align-top">
                                  {tagItem.scanned && tagItem.org_id && tagItem.image_id ? (
                                    <Link to={`/images/${tagItem.org_id}/${tagItem.image_id}`} className="text-tide hover:text-sky-600 dark:hover:text-sky-300">
                                      Open
                                    </Link>
                                  ) : (
                                    <button
                                      type="button"
                                      onClick={() => tagScanMutation.mutate(imageName)}
                                      disabled={tagScanMutation.isPending || queuedTags[imageName]}
                                      className="rounded-md border border-ink-200 px-2.5 py-1 text-xs uppercase tracking-wide text-ink-700 transition hover:border-ink-900 hover:text-ink-900 disabled:opacity-50 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                                    >
                                      {queuedTags[imageName] ? "queued" : "scan"}
                                    </button>
                                  )}
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                    {!tagItems.length ? (
                      <p className="mt-6 text-sm text-ink-500 dark:text-ink-400">
                        No tags matched the current filter.
                      </p>
                    ) : null}
                    <div className="mt-5 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-600 dark:text-ink-300">
                      <p>
                        Showing {tagItems.length ? (tagsQuery.data!.page - 1) * tagsQuery.data!.page_size + 1 : 0}
                        {" - "}
                        {(tagsQuery.data!.page - 1) * tagsQuery.data!.page_size + tagItems.length}
                        {" of "}
                        {tagsQuery.data!.total} tags
                      </p>
                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => setTagPage((current) => Math.max(1, current - 1))}
                          disabled={tagPage === 1}
                          className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 disabled:opacity-50 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                        >
                          Previous
                        </button>
                        <span className="min-w-[6rem] text-center">
                          Page {tagsQuery.data!.page} of {totalTagPages}
                        </span>
                        <button
                          type="button"
                          onClick={() => setTagPage((current) => Math.min(totalTagPages, current + 1))}
                          disabled={tagPage >= totalTagPages}
                          className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 disabled:opacity-50 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                        >
                          Next
                        </button>
                      </div>
                    </div>
                  </>
                )}
              </section>
            ) : null}

            {tab === "Comparison" ? (
              <section className="grid gap-6">
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Compare this image</h2>
                  <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Otter prefers stored scans from the same repository so you can compare the current tag against the closest previous version.</p>
                  {comparisonCandidates.length ? (
                    <div className="mt-4 flex flex-col gap-3 lg:flex-row">
                      <select
                        aria-label="Comparison target"
                        value={comparisonTargetId}
                        onChange={(event) => setComparisonTargetId(event.target.value)}
                        className="flex-1 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 dark:border-ink-700 dark:bg-ink-900 dark:text-white"
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
                        className="rounded-md bg-ink-900 px-4 py-2 text-sm font-medium text-white disabled:cursor-not-allowed disabled:opacity-50 dark:bg-white dark:text-ink-900"
                      >
                        Run comparison
                      </button>
                    </div>
                  ) : (
                    <div className="mt-4 rounded-lg border border-ink-200 bg-ink-50 p-4 text-sm text-ink-600 dark:border-ink-800 dark:bg-ink-950 dark:text-ink-300">
                      No comparison candidates are stored for this repository yet. Scan another tag from the same repo first, then come back here.
                    </div>
                  )}
                </div>

                {comparisonMutation.isPending ? <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">Building comparison...</div> : null}
                {comparisonMutation.isError ? (
                  <EmptyState
                    title="Comparison failed"
                    description={comparisonMutation.error instanceof Error ? comparisonMutation.error.message : "The comparison endpoint returned an error."}
                  />
                ) : null}
                {comparisonMutation.data ? (
                  <div className="grid gap-6">
                    <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                      <h3 className="font-display text-xl text-ink-900 dark:text-white">Summary</h3>
                      <p className="mt-3 text-base text-ink-700 dark:text-ink-200">{comparisonMutation.data.comparison.summary.message}</p>
                      <div className="mt-5 grid gap-3 md:grid-cols-3">
                        <StatCard label="Package delta" value={comparisonMutation.data.comparison.summary.package_delta} />
                        <StatCard label="Vulnerability delta" value={comparisonMutation.data.comparison.summary.vulnerability_delta} />
                        <StatCard label="Changed layers" value={comparisonMutation.data.comparison.summary.changed_layer_delta} />
                      </div>
                      <div className="mt-5">
                        <a
                          href={getComparisonExportURL(comparisonMutation.data.comparison_id)}
                          className="inline-flex rounded-md bg-ink-900 px-4 py-2 text-sm font-medium text-white dark:bg-white dark:text-ink-900"
                        >
                          Download comparison JSON
                        </a>
                      </div>
                    </section>
                    <section className="grid gap-4 md:grid-cols-3">
                      <StatCard label="New vulnerabilities" value={comparisonMutation.data.comparison.vulnerability_diff.new.length} />
                      <StatCard label="Fixed vulnerabilities" value={comparisonMutation.data.comparison.vulnerability_diff.fixed.length} />
                      <StatCard label="Changed packages" value={comparisonMutation.data.comparison.package_diff.changed.length} />
                    </section>
                  </div>
                ) : null}
              </section>
            ) : null}

            {tab === "Vulnerabilities" ? (
              <section className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                <div className="flex flex-col gap-4 2xl:flex-row 2xl:items-end 2xl:justify-between">
                  <div>
                    <h2 className="font-display text-xl text-ink-900 dark:text-white">Vulnerabilities</h2>
                    <p className="mt-2 text-sm text-ink-600 dark:text-ink-300">Filter the merged Grype and Trivy findings by severity, advisory state, or package name.</p>
                  </div>
                  <div className="flex w-full flex-col gap-3 xl:w-auto xl:flex-row xl:flex-wrap xl:items-end xl:justify-end">
                    <input
                      aria-label="Search vulnerabilities"
                      value={searchFilter}
                      onChange={(event) => setSearchFilter(event.target.value)}
                      placeholder="Search CVE or package"
                      className="w-full min-w-0 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 xl:w-[min(22rem,40vw)] dark:border-ink-700 dark:bg-ink-900 dark:text-white"
                    />
                    <select
                      aria-label="Filter vulnerability severity"
                      value={severityFilter}
                      onChange={(event) => setSeverityFilter(event.target.value as "" | Severity)}
                      className="w-full min-w-0 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 sm:w-auto sm:min-w-[190px] dark:border-ink-700 dark:bg-ink-900 dark:text-white"
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
                      className="w-full min-w-0 rounded-md border border-ink-200 bg-white px-3 py-2 text-sm text-ink-900 sm:w-auto sm:min-w-[190px] dark:border-ink-700 dark:bg-ink-900 dark:text-white"
                    >
                      {statusFilterOptions.map((option) => (
                        <option key={option || "all"} value={option}>
                          {option || "All statuses"}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      onClick={() => {
                        setSearchFilter("");
                        setSeverityFilter("");
                        setStatusFilter("");
                      }}
                      className="w-full rounded-md border border-ink-200 px-3 py-2 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 sm:w-auto sm:min-w-[160px] dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                    >
                      Reset filters
                    </button>
                  </div>
                </div>

                {scannerWarnings.length ? (
                  <div className="mt-5 space-y-3">
                    {scannerWarnings.map((warning) => (
                      <div key={warning.scanner} className="rounded-md border border-amber-300/40 bg-amber-50 px-4 py-3 text-sm text-amber-900 dark:border-amber-500/20 dark:bg-amber-950/30 dark:text-amber-100">
                        <span className="font-medium">{warning.scanner} unavailable.</span> {warning.message}
                      </div>
                    ))}
                  </div>
                ) : null}

                {vulnerabilitiesQuery.isLoading ? (
                  <p className="mt-6 text-sm text-ink-500 dark:text-ink-400">Loading vulnerabilities...</p>
                ) : vulnerabilitiesQuery.isError ? (
                  <EmptyState
                    title="Vulnerabilities unavailable"
                    description={vulnerabilitiesQuery.error instanceof Error ? vulnerabilitiesQuery.error.message : "The vulnerability endpoint returned an error."}
                  />
                ) : (
                  <>
                    <div className="mt-6 overflow-x-auto">
                      <table className="min-w-[1120px] text-left text-sm">
                        <thead className="text-ink-500 dark:text-ink-400">
                          <tr>
                            <th className="pb-4 pr-6">Severity</th>
                            <th className="pb-4 pr-6">Vulnerability</th>
                            <th className="pb-4 pr-6">Package</th>
                            <th className="pb-4 pr-6">Fix version</th>
                            <th className="pb-4">Status</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                          {filteredVulnerabilities.map((vulnerability) => (
                            <tr key={`${vulnerability.id}-${vulnerability.package_name}-${vulnerability.package_version}`}>
                              <td className="py-4 pr-6 align-top"><SeverityPill severity={vulnerability.severity} /></td>
                              <td className="py-4 pr-6 align-top">
                                <div className="font-medium text-ink-900 dark:text-white">
                                  <button
                                    type="button"
                                    onClick={() => setSelectedVulnerability(vulnerability)}
                                    className="text-left transition hover:text-tide"
                                  >
                                    {vulnerability.id}
                                  </button>
                                </div>
                                <div className="mt-1 max-w-2xl text-sm leading-6 text-ink-500 dark:text-ink-400">{vulnerability.title || vulnerability.description}</div>
                                {vulnerabilityLink(vulnerability) ? (
                                  <a
                                    href={vulnerabilityLink(vulnerability)}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="mt-2 inline-flex text-xs uppercase tracking-wide text-tide hover:text-sky-600 dark:hover:text-sky-300"
                                  >
                                    Open external reference
                                  </a>
                                ) : null}
                              </td>
                              <td className="py-4 pr-6 align-top text-ink-600 dark:text-ink-300">
                                <div className="font-medium text-ink-900 dark:text-white">{vulnerability.package_name}</div>
                                <div className="mt-1">{vulnerability.package_version || "Unknown version"}</div>
                              </td>
                              <td className="py-4 pr-6 align-top text-ink-600 dark:text-ink-300">{vulnerability.fix_version || "Unavailable"}</td>
                              <td className="py-4 align-top text-ink-600 dark:text-ink-300">{vulnerability.status}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {!filteredVulnerabilities.length ? (
                      <p className="mt-6 text-sm text-ink-500 dark:text-ink-400">
                        {hasVulnerabilityFilters && vulnerabilityRecords.length
                          ? "No vulnerabilities matched the current filters. Reset the filters to see all findings."
                          : scannerWarnings.length
                            ? "No vulnerabilities were returned, and at least one scanner was unavailable for this scan."
                            : "No vulnerabilities were reported for this image."}
                      </p>
                    ) : null}
                  </>
                )}
              </section>
            ) : null}

            {tab === "SBOM" ? (
              <section className="grid gap-6">
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">SBOM package inventory</h2>
                  <div className="mt-5 grid gap-3 md:grid-cols-3">
                    <StatCard label="Packages" value={sbomQuery.data?.package_count ?? 0} />
                    <StatCard label="Dependency roots" value={sbomQuery.data?.dependency_roots.length ?? 0} />
                    <StatCard label="Format" value={sbomQuery.data?.format ?? "cyclonedx"} />
                  </div>
                  <div className="mt-5 flex flex-wrap gap-2">
                    {sbomQuery.data?.license_summary.map((license) => (
                      <span key={license.license} className="rounded-md bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">
                        {license.license} · {license.count}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="grid gap-6 3xl:grid-cols-[1.15fr_0.85fr]">
                  <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <h3 className="font-display text-lg text-ink-900 dark:text-white">Packages</h3>
                      <input
                        type="text"
                        placeholder="Search packages…"
                        value={pkgSearch}
                        onChange={(e) => { setPkgSearch(e.target.value); setPkgPage(1); }}
                        className="rounded-md border border-ink-200 bg-white px-3 py-1.5 text-sm text-ink-900 placeholder:text-ink-400 dark:border-ink-700 dark:bg-ink-800 dark:text-white dark:placeholder:text-ink-500"
                      />
                    </div>
                    {(() => {
                      const PAGE_SIZE = 50;
                      const allPackages = sbomQuery.data?.packages ?? [];
                      const filtered = pkgSearch
                        ? allPackages.filter((pkg) => pkg.name.toLowerCase().includes(pkgSearch.toLowerCase()))
                        : allPackages;
                      const totalPkgPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
                      const safePage = Math.min(pkgPage, totalPkgPages);
                      const startIdx = (safePage - 1) * PAGE_SIZE;
                      const pagePackages = filtered.slice(startIdx, startIdx + PAGE_SIZE);
                      return (
                        <>
                          <div className="mt-4 max-h-[720px] overflow-auto">
                            <table className="min-w-[780px] text-left text-sm">
                              <thead className="text-ink-500 dark:text-ink-400">
                                <tr>
                                  <th className="pb-3">Name</th>
                                  <th className="pb-3">Version</th>
                                  <th className="pb-3">Type</th>
                                  <th className="pb-3">Licenses</th>
                                </tr>
                              </thead>
                              <tbody className="divide-y divide-ink-200 dark:divide-ink-800">
                                {pagePackages.map((pkg) => {
                                  const licenses = pkg.licenses?.join(", ") || "Unknown";
                                  return (
                                    <tr key={pkg.id}>
                                      <td className="py-3 text-ink-900 dark:text-white">{pkg.name}</td>
                                      <td className="py-3 text-ink-600 dark:text-ink-300">{pkg.version || "Unknown"}</td>
                                      <td className="py-3 text-ink-600 dark:text-ink-300">{pkg.type || "Unknown"}</td>
                                      <td className="py-3 text-ink-600 dark:text-ink-300">
                                        <span className="block max-w-[16rem] truncate" title={licenses}>
                                          {licenses}
                                        </span>
                                      </td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </div>
                          <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-600 dark:text-ink-300">
                            <p>
                              Showing {filtered.length ? startIdx + 1 : 0} - {startIdx + pagePackages.length} of {filtered.length} packages
                            </p>
                            <div className="flex items-center gap-2">
                              <button
                                type="button"
                                onClick={() => setPkgPage((p) => Math.max(1, p - 1))}
                                disabled={safePage === 1}
                                className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 disabled:opacity-50 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                              >
                                Previous
                              </button>
                              <span className="min-w-[6rem] text-center">
                                Page {safePage} of {totalPkgPages}
                              </span>
                              <button
                                type="button"
                                onClick={() => setPkgPage((p) => Math.min(totalPkgPages, p + 1))}
                                disabled={safePage >= totalPkgPages}
                                className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 disabled:opacity-50 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
                              >
                                Next
                              </button>
                            </div>
                          </div>
                        </>
                      );
                    })()}
                  </div>
                  <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">Dependency tree</h3>
                    <div className="mt-4 max-h-[720px] overflow-auto">
                      <div className="min-w-[320px] space-y-3">
                        {dependencyTree
                          .filter((node) => overview.dependency_roots.includes(node.id))
                          .map((node) => (
                            <DependencyTreeCard key={node.id} node={node} depth={0} tree={dependencyTree} />
                          ))}
                        {!dependencyTree.length ? <p className="text-sm text-ink-500 dark:text-ink-400">No dependency tree data was returned.</p> : null}
                      </div>
                    </div>
                  </div>
                </div>
              </section>
            ) : null}

            {tab === "Attestations" ? (
              <section className="grid gap-6">
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Attestation coverage</h2>
                  <div className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
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
                  <>
                    {!attestationsQuery.data?.summary.total ? (
                      <div className="rounded-lg border border-ink-200 bg-ink-50 p-5 text-sm text-ink-600 dark:border-ink-800 dark:bg-ink-950 dark:text-ink-300">
                        No signatures or attestations were discovered for this image. That usually means the scanned image does not publish OCI referrers or cosign metadata, not that the viewer is broken.
                      </div>
                    ) : null}
                    <div className="grid gap-4 2xl:grid-cols-2">
                      {[...(attestationsQuery.data?.signatures ?? []), ...(attestationsQuery.data?.attestations ?? [])].map((record) => (
                        <article key={`${record.kind}-${record.digest}`} className="rounded-xl border border-ink-200 bg-white p-5 dark:border-ink-800 dark:bg-ink-900">
                          <div className="flex items-start justify-between gap-4">
                            <div className="min-w-0">
                              <p className="text-xs uppercase tracking-wider text-ink-500 dark:text-ink-400">{record.kind}</p>
                              <h3 className="mt-1 truncate font-display text-lg text-ink-900 dark:text-white" title={record.signer || record.predicate_type || record.source}>
                                {record.signer || record.predicate_type || record.source}
                              </h3>
                            </div>
                            <span className="rounded-md bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">{record.verification_status}</span>
                          </div>
                          <dl className="mt-4 grid gap-3 text-sm text-ink-600 dark:text-ink-300">
                            <div><dt className="font-medium text-ink-900 dark:text-white">Digest</dt><dd className="break-all">{record.digest}</dd></div>
                            {record.timestamp ? <div><dt className="font-medium text-ink-900 dark:text-white">Timestamp</dt><dd>{formatTimestamp(record.timestamp)}</dd></div> : null}
                            {record.provenance?.builder_id ? <div><dt className="font-medium text-ink-900 dark:text-white">Builder</dt><dd className="break-all">{record.provenance.builder_id}</dd></div> : null}
                          </dl>
                        </article>
                      ))}
                    </div>
                  </>
                )}
              </section>
            ) : null}

            {tab === "Advisories" ? (
              <section className="grid gap-6">
                <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                  <h2 className="font-display text-xl text-ink-900 dark:text-white">Advisories and VEX status</h2>
                  <div className="mt-5 grid gap-3 md:grid-cols-2 2xl:grid-cols-4">
                    <StatCard label="Affected" value={vulnerabilitiesQuery.data?.summary.by_status?.affected ?? 0} />
                    <StatCard label="Not affected" value={vulnerabilitiesQuery.data?.summary.by_status?.not_affected ?? 0} />
                    <StatCard label="Fixed" value={vulnerabilitiesQuery.data?.summary.by_status?.fixed ?? 0} />
                    <StatCard label="Investigating" value={vulnerabilitiesQuery.data?.summary.by_status?.under_investigation ?? 0} />
                  </div>
                </div>
                <div className="grid gap-6 2xl:grid-cols-[1.1fr_0.9fr]">
                  <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">Advisory-backed vulnerabilities</h3>
                    <div className="mt-4 space-y-3">
                      {filteredAdvisories(vulnerabilityRecords).map((vulnerability) => (
                        <article key={`${vulnerability.id}-${vulnerability.package_name}`} className="rounded-lg border border-ink-200 p-4 dark:border-ink-800">
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-ink-900 dark:text-white">{vulnerability.id}</p>
                              <p className="text-sm text-ink-600 dark:text-ink-300">{vulnerability.package_name} {vulnerability.package_version}</p>
                            </div>
                            <div className="flex items-center gap-2">
                              <SeverityPill severity={vulnerability.severity} />
                              <span className="rounded-md bg-ink-100 px-2.5 py-1 text-xs font-medium text-ink-700 dark:bg-ink-800 dark:text-ink-200">{vulnerability.status}</span>
                            </div>
                          </div>
                          {vulnerability.advisory?.status_notes ? (
                            <p className="mt-3 text-sm text-ink-600 dark:text-ink-300">{vulnerability.advisory.status_notes}</p>
                          ) : null}
                        </article>
                      ))}
                      {!filteredAdvisories(vulnerabilityRecords).length ? (
                        <p className="text-sm text-ink-500 dark:text-ink-400">No advisory overlays have been imported for this image.</p>
                      ) : null}
                    </div>
                  </div>
                  <div className="rounded-xl border border-ink-200 bg-white p-6 dark:border-ink-800 dark:bg-ink-900">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">VEX documents</h3>
                    <div className="mt-4 space-y-3">
                      {(vulnerabilitiesQuery.data?.vex_documents ?? []).map((document) => (
                        <div key={document.document_id} className="rounded-lg border border-ink-200 p-4 dark:border-ink-800">
                          <p className="font-medium text-ink-900 dark:text-white">{document.filename || document.document_id}</p>
                          <p className="mt-1 text-sm text-ink-600 dark:text-ink-300">{document.author || "Unknown author"} · version {document.version}</p>
                        </div>
                      ))}
                      {!(vulnerabilitiesQuery.data?.vex_documents ?? []).length ? (
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

      {selectedVulnerability ? (
        <div className="fixed inset-0 z-40 bg-ink-950/60">
          <button
            type="button"
            aria-label="Close vulnerability details"
            onClick={() => setSelectedVulnerability(null)}
            className="absolute inset-0 h-full w-full cursor-default"
          />
          <aside
            role="dialog"
            aria-modal="true"
            aria-labelledby="vulnerability-detail-title"
            className="absolute right-0 top-0 flex h-full w-full max-w-3xl flex-col overflow-hidden border-l border-ink-200 bg-white dark:border-ink-800 dark:bg-ink-900 lg:w-[46vw]"
          >
            <div className="flex items-start justify-between gap-4 border-b border-ink-200 px-6 py-5 dark:border-ink-800">
              <div className="min-w-0">
                <p className="text-xs uppercase tracking-wider text-ink-500 dark:text-ink-400">Vulnerability details</p>
                <h2 id="vulnerability-detail-title" className="mt-2 break-all font-display text-xl text-ink-900 dark:text-white">
                  {selectedVulnerability.id}
                </h2>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <SeverityPill severity={selectedVulnerability.severity} />
                  <span className="rounded-md bg-ink-100 px-2.5 py-1 text-xs font-medium uppercase tracking-wide text-ink-700 dark:bg-ink-800 dark:text-ink-200">
                    {selectedVulnerability.status}
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedVulnerability(null)}
                className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
              >
                Close
              </button>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
              <div className="space-y-6">
                <section className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                  <h3 className="font-display text-lg text-ink-900 dark:text-white">Summary</h3>
                  <p className="mt-3 text-sm leading-7 text-ink-700 dark:text-ink-200">
                    {selectedVulnerability.title || selectedVulnerability.description || "No description was returned for this vulnerability."}
                  </p>
                  {vulnerabilityLink(selectedVulnerability) ? (
                    <a
                      href={vulnerabilityLink(selectedVulnerability)}
                      target="_blank"
                      rel="noreferrer"
                      className="mt-4 inline-flex rounded-md border border-ink-200 px-3 py-1.5 text-sm text-tide transition hover:border-tide dark:border-ink-700 dark:hover:border-sky-500 dark:hover:text-sky-300"
                    >
                      Open primary reference
                    </a>
                  ) : null}
                </section>

                <section className="grid gap-3 lg:grid-cols-2">
                  <DetailCard label="Package" value={selectedVulnerability.package_name} />
                  <DetailCard label="Package version" value={selectedVulnerability.package_version || "Unknown"} />
                  <DetailCard label="Package type" value={selectedVulnerability.package_type || "Unknown"} />
                  <DetailCard label="Namespace" value={selectedVulnerability.namespace || "Unknown"} />
                  <DetailCard label="Fix version" value={selectedVulnerability.fix_version || "Unavailable"} />
                  <DetailCard label="Status source" value={selectedVulnerability.status_source} />
                  <DetailCard label="First seen" value={formatTimestamp(selectedVulnerability.first_seen_at)} />
                  <DetailCard label="Last seen" value={formatTimestamp(selectedVulnerability.last_seen_at)} />
                </section>

                <section className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                  <h3 className="font-display text-lg text-ink-900 dark:text-white">Scanners and fixes</h3>
                  <div className="mt-4 flex flex-wrap gap-2">
                    {selectedVulnerability.scanners.map((scanner) => (
                      <span key={scanner} className="rounded-md bg-sky-100 px-2.5 py-1 text-xs font-medium uppercase tracking-wide text-sky-800 dark:bg-sky-950/40 dark:text-sky-200">
                        {scanner}
                      </span>
                    ))}
                    {selectedVulnerability.fix_versions?.map((version) => (
                      <span key={version} className="rounded-md bg-emerald-100 px-2.5 py-1 text-xs font-medium text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-300">
                        fix {version}
                      </span>
                    ))}
                  </div>
                </section>

                {selectedVulnerability.cvss?.length ? (
                  <section className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">CVSS</h3>
                    <div className="mt-4 grid gap-3 lg:grid-cols-2">
                      {selectedVulnerability.cvss.map((entry) => (
                        <article key={`${entry.source || "unknown"}-${entry.vector || entry.score || "cvss"}`} className="rounded-lg border border-ink-200 p-3 dark:border-ink-800">
                          <p className="text-sm font-medium text-ink-900 dark:text-white">{entry.source || "Unknown source"}</p>
                          <p className="mt-1 text-sm text-ink-600 dark:text-ink-300">Score: {entry.score ?? "n/a"}</p>
                          {entry.vector ? <p className="mt-1 break-all text-xs text-ink-500 dark:text-ink-400">{entry.vector}</p> : null}
                        </article>
                      ))}
                    </div>
                  </section>
                ) : null}

                {selectedVulnerability.references?.length ? (
                  <section className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">References</h3>
                    <div className="mt-4 space-y-2">
                      {selectedVulnerability.references.map((reference) => (
                        <a
                          key={reference}
                          href={reference}
                          target="_blank"
                          rel="noreferrer"
                          className="block break-all rounded-lg border border-ink-200 px-3 py-2 text-sm text-tide transition hover:border-tide dark:border-ink-800 dark:hover:border-sky-500 dark:hover:text-sky-300"
                        >
                          {reference}
                        </a>
                      ))}
                    </div>
                  </section>
                ) : null}

                {selectedVulnerability.advisory ? (
                  <section className="rounded-lg border border-ink-200 bg-ink-50 p-5 dark:border-ink-800 dark:bg-ink-950">
                    <h3 className="font-display text-lg text-ink-900 dark:text-white">Advisory / VEX overlay</h3>
                    <dl className="mt-4 grid gap-3 text-sm text-ink-600 dark:text-ink-300">
                      <div><dt className="font-medium text-ink-900 dark:text-white">Document</dt><dd>{selectedVulnerability.advisory.filename || selectedVulnerability.advisory.document_id}</dd></div>
                      <div><dt className="font-medium text-ink-900 dark:text-white">Author</dt><dd>{selectedVulnerability.advisory.author || "Unknown"}</dd></div>
                      {selectedVulnerability.advisory.status_notes ? <div><dt className="font-medium text-ink-900 dark:text-white">Notes</dt><dd>{selectedVulnerability.advisory.status_notes}</dd></div> : null}
                      {selectedVulnerability.advisory.justification ? <div><dt className="font-medium text-ink-900 dark:text-white">Justification</dt><dd>{selectedVulnerability.advisory.justification}</dd></div> : null}
                      {selectedVulnerability.advisory.impact_statement ? <div><dt className="font-medium text-ink-900 dark:text-white">Impact</dt><dd>{selectedVulnerability.advisory.impact_statement}</dd></div> : null}
                      {selectedVulnerability.advisory.action_statement ? <div><dt className="font-medium text-ink-900 dark:text-white">Action</dt><dd>{selectedVulnerability.advisory.action_statement}</dd></div> : null}
                    </dl>
                  </section>
                ) : null}
              </div>
            </div>
          </aside>
        </div>
      ) : null}

      {selectedArtifact ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink-950/70 p-4">
          <div className="flex h-[min(90vh,980px)] w-full max-w-6xl flex-col overflow-hidden rounded-xl border border-ink-200 bg-white dark:border-ink-800 dark:bg-ink-900">
            <div className="flex items-center justify-between gap-4 border-b border-ink-200 px-5 py-4 dark:border-ink-800">
              <div>
                <h2 className="font-display text-xl text-ink-900 dark:text-white">Artifact viewer</h2>
                <p className="text-sm text-ink-500 dark:text-ink-400">{selectedArtifact}</p>
              </div>
              <button
                type="button"
                onClick={() => setSelectedArtifact(null)}
                className="rounded-md border border-ink-200 px-3 py-1.5 text-sm text-ink-700 transition hover:border-ink-900 hover:text-ink-900 dark:border-ink-700 dark:text-ink-200 dark:hover:border-white dark:hover:text-white"
              >
                Close
              </button>
            </div>

            <div className="min-h-0 flex-1 p-5">
              {artifactQuery.isLoading ? (
                <div className="rounded-lg border border-ink-200 bg-ink-50 p-6 text-sm text-ink-600 dark:border-ink-800 dark:bg-ink-950 dark:text-ink-300">
                  Loading artifact JSON...
                </div>
              ) : artifactQuery.isError ? (
                <EmptyState
                  title="Artifact unavailable"
                  description={artifactQuery.error instanceof Error ? artifactQuery.error.message : "The artifact could not be loaded."}
                />
              ) : (
                <JSONViewer document={artifactQuery.data} filename={selectedArtifact} />
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
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
    return (
      <div className="rounded-lg border border-dashed border-sky-200 bg-sky-50 px-4 py-3 text-sm text-sky-700 dark:border-sky-900/60 dark:bg-sky-950/20 dark:text-sky-200">
        Additional nested dependencies are hidden on smaller layouts.
      </div>
    );
  }

  return (
    <div
      className={clsx(
        "rounded-lg border p-4",
        dependencyTone(depth),
        depth > 0 ? "border-l-4 pl-3" : ""
      )}
    >
      <p className="break-all font-medium text-ink-900 dark:text-white">{node.name} {node.version}</p>
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

function collectScannerWarnings(files: ScanFile[]) {
  return files
    .filter((file) => file.key.endsWith("-vulnerabilities.json"))
    .map((file) => ({
      scanner: file.metadata?.scanner || file.key.split("/").pop()?.replace("-vulnerabilities.json", "") || "scanner",
      status: file.metadata?.status,
      message: file.metadata?.message || "The scanner did not complete for this image."
    }))
    .filter((warning) => warning.status === "unavailable");
}

function filteredAdvisories(vulnerabilities: VulnerabilityRecord[]) {
  return vulnerabilities.filter((vulnerability) => vulnerability.status !== "affected" || vulnerability.advisory);
}

function DetailCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-ink-200 bg-ink-50 p-4 dark:border-ink-800 dark:bg-ink-950">
      <p className="text-xs font-medium uppercase tracking-wide text-ink-500 dark:text-ink-400">{label}</p>
      <p className="mt-1.5 break-all text-sm font-medium text-ink-900 dark:text-white">{value}</p>
    </div>
  );
}

function vulnerabilityLink(vulnerability: VulnerabilityRecord) {
  if (vulnerability.primary_url) {
    return vulnerability.primary_url;
  }
  if (vulnerability.references?.length) {
    return vulnerability.references[0];
  }
  if (vulnerability.id.startsWith("CVE-")) {
    return `https://nvd.nist.gov/vuln/detail/${vulnerability.id}`;
  }
  if (vulnerability.id.startsWith("GHSA-")) {
    return `https://github.com/advisories/${vulnerability.id}`;
  }
  return "";
}

function dependencyTone(depth: number) {
  switch (depth) {
    case 0:
      return "border-amber-200 bg-amber-50 dark:border-amber-900/50 dark:bg-amber-950/20";
    case 1:
      return "border-sky-200 bg-sky-50 dark:border-sky-900/50 dark:bg-sky-950/20";
    default:
      return "border-emerald-200 bg-emerald-50 dark:border-emerald-900/50 dark:bg-emerald-950/20";
  }
}

function buildTaggedImageName(repository: string, tag: string) {
  const base = repository.replace(/@sha256:[a-f0-9]+$/i, "").replace(/:[^/]+$/, "");
  return `${base}:${tag}`;
}
