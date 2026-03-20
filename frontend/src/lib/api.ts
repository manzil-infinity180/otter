import type {
  AttestationsResponse,
  CatalogResponse,
  ComplianceResponse,
  ComparisonResponse,
  ImageExportFormat,
  OverviewResponse,
  SbomResponse,
  VulnerabilitiesResponse
} from "./types";

const apiBase = import.meta.env.VITE_API_BASE ?? "";

export function buildAPIURL(path: string, params?: Record<string, string | undefined>) {
  const url = new URL(path, window.location.origin);
  if (apiBase) {
    url.pathname = `${apiBase.replace(/\/$/, "")}${path}`;
  }
  Object.entries(params ?? {}).forEach(([key, value]) => {
    if (value) {
      url.searchParams.set(key, value);
    }
  });
  return url;
}

async function request<T>(path: string, params?: Record<string, string | undefined>): Promise<T> {
	const url = buildAPIURL(path, params);
	const response = await fetch(url.toString(), {
    headers: {
      Accept: "application/json"
    }
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }

	return (await response.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
	const url = buildAPIURL(path);
	const response = await fetch(url.toString(), {
		method: "POST",
		headers: {
			Accept: "application/json",
			"Content-Type": "application/json"
		},
		body: JSON.stringify(body)
	});

	if (!response.ok) {
		const message = await response.text();
		throw new Error(message || `Request failed with ${response.status}`);
	}

	return (await response.json()) as T;
}

export function listCatalog(params?: {
  orgId?: string;
  query?: string;
  severity?: string;
  sort?: string;
}) {
  return request<CatalogResponse>("/api/v1/catalog", {
    org_id: params?.orgId,
    query: params?.query,
    severity: params?.severity,
    sort: params?.sort
  });
}

export function getOverview(orgId: string, imageId: string) {
  return request<OverviewResponse>(`/api/v1/images/${imageId}/overview`, { org_id: orgId });
}

export function getCompliance(orgId: string, imageId: string) {
  return request<ComplianceResponse>(`/api/v1/images/${imageId}/compliance`, { org_id: orgId });
}

export function getVulnerabilities(orgId: string, imageId: string) {
  return request<VulnerabilitiesResponse>(`/api/v1/images/${imageId}/vulnerabilities`, { org_id: orgId });
}

export function getSbom(orgId: string, imageId: string) {
  return request<SbomResponse>(`/api/v1/images/${imageId}/sbom`, { org_id: orgId });
}

export function getAttestations(orgId: string, imageId: string) {
  return request<AttestationsResponse>(`/api/v1/images/${imageId}/attestations`, { org_id: orgId });
}

export function getImageExportURL(orgId: string, imageId: string, format: ImageExportFormat) {
  return buildAPIURL(`/api/v1/images/${imageId}/export`, { org_id: orgId, format }).toString();
}

export function getComparisonExportURL(comparisonId: string) {
  return buildAPIURL(`/api/v1/comparisons/${comparisonId}/export`).toString();
}

export function compareImages(params: {
  image1: string;
  image2: string;
  org1: string;
  org2: string;
}) {
  return postJSON<ComparisonResponse>("/api/v1/comparisons", params);
}
