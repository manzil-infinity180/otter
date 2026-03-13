export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NEGLIGIBLE" | "UNKNOWN";
export type ImageExportFormat = "cyclonedx" | "spdx" | "json" | "csv" | "sarif";

export interface LicenseSummaryEntry {
  license: string;
  count: number;
}

export interface VulnerabilitySummary {
  total: number;
  by_severity: Partial<Record<Severity, number>>;
  by_scanner: Record<string, number>;
  by_status?: Record<string, number>;
  fixable: number;
  unfixable: number;
}

export interface CatalogItem {
  org_id: string;
  image_id: string;
  image_name: string;
  registry: string;
  repository: string;
  repository_path: string;
  tag?: string;
  digest?: string;
  package_count: number;
  license_summary: LicenseSummaryEntry[];
  vulnerability_summary: VulnerabilitySummary;
  scanners: string[];
  updated_at: string;
}

export interface CatalogResponse {
  count: number;
  items: CatalogItem[];
  storage_backend: string;
}

export interface ScanFile {
  key: string;
  size: number;
  content_type: string;
  created_at: string;
  backend: string;
  metadata?: Record<string, string>;
}

export interface TagItem {
  org_id: string;
  image_id: string;
  image_name: string;
  tag?: string;
  digest?: string;
  package_count: number;
  vulnerability_summary: VulnerabilitySummary;
  updated_at: string;
}

export interface OverviewResponse extends CatalogItem {
  storage_backend: string;
  dependency_roots: string[];
  files: ScanFile[];
  tags: TagItem[];
}

export interface CVSSScore {
  source?: string;
  version?: string;
  vector?: string;
  score: number;
}

export interface Advisory {
  document_id: string;
  filename?: string;
  statement_id?: string;
  author?: string;
  status_notes?: string;
  justification?: string;
  impact_statement?: string;
  action_statement?: string;
  timestamp?: string;
}

export interface VulnerabilityRecord {
  id: string;
  severity: Severity;
  package_name: string;
  package_version?: string;
  package_type?: string;
  namespace?: string;
  title?: string;
  description?: string;
  primary_url?: string;
  references?: string[];
  fix_version?: string;
  fix_versions?: string[];
  cvss?: CVSSScore[];
  scanners: string[];
  status: string;
  status_source: string;
  advisory?: Advisory;
  first_seen_at: string;
  last_seen_at: string;
}

export interface FixRecommendation {
  package_name: string;
  package_version?: string;
  package_type?: string;
  namespace?: string;
  recommended_version: string;
  vulnerability_ids: string[];
  vulnerability_count: number;
}

export interface VexDocument {
  document_id: string;
  author?: string;
  version: number;
  timestamp?: string;
  filename?: string;
}

export interface VulnerabilitiesResponse {
  org_id: string;
  image_id: string;
  image_name: string;
  summary: VulnerabilitySummary;
  summary_all?: VulnerabilitySummary;
  vulnerabilities: VulnerabilityRecord[];
  fix_recommendations: FixRecommendation[];
  vex_documents: VexDocument[];
  updated_at: string;
}

export interface PackageRecord {
  id: string;
  name: string;
  version?: string;
  type?: string;
  purl?: string;
  licenses?: string[];
}

export interface DependencyNode {
  id: string;
  name: string;
  version?: string;
  depends_on?: string[];
}

export interface SbomResponse {
  org_id: string;
  image_id: string;
  image_name: string;
  format: "cyclonedx" | "spdx";
  package_count: number;
  packages: PackageRecord[];
  license_summary: LicenseSummaryEntry[];
  dependency_roots: string[];
  dependency_tree: DependencyNode[];
  updated_at: string;
  document: unknown;
}

export interface AttestationRecord {
  digest: string;
  media_type?: string;
  artifact_type?: string;
  kind: string;
  source: string;
  verification_status: string;
  verification_message?: string;
  signer?: string;
  issuer?: string;
  predicate_type?: string;
  dsse_payload_type?: string;
  timestamp?: string;
  provenance?: {
    builder_id?: string;
    build_type?: string;
    invocation_id?: string;
    materials?: string[];
  };
}

export interface AttestationsResponse {
  org_id: string;
  image_id: string;
  image_name: string;
  image_digest?: string;
  canonical_ref?: string;
  summary: {
    total: number;
    signatures: number;
    attestations: number;
    provenance: number;
    by_verification_status: Record<string, number>;
  };
  signatures: AttestationRecord[];
  attestations: AttestationRecord[];
  updated_at: string;
}

export interface ComparisonReport {
  id: string;
  summary: {
    message: string;
    package_delta: number;
    vulnerability_delta: number;
    changed_layer_delta: number;
    image2_fewer_packages: number;
    image2_fewer_vulnerabilities: number;
  };
  package_diff: {
    added: Array<{ name: string; to_version?: string }>;
    removed: Array<{ name: string; from_version?: string }>;
    changed: Array<{ name: string; from_version?: string; to_version?: string }>;
  };
  vulnerability_diff: {
    new: Array<{ id: string; severity: Severity; package_name: string }>;
    fixed: Array<{ id: string; severity: Severity; package_name: string }>;
    unchanged: Array<{ id: string; severity: Severity; package_name: string }>;
  };
  layer_diff: {
    image1_count: number;
    image2_count: number;
  };
  sbom_diff: {
    components_added: number;
    components_removed: number;
    components_changed: number;
  };
}

export interface ComparisonResponse {
  comparison_id: string;
  comparison: ComparisonReport;
}
