import type {
  AttestationsResponse,
  CatalogResponse,
  ComplianceResponse,
  ComparisonResponse,
  ImageExportFormat,
  ImageTagsResponse,
  OverviewResponse,
  ScanAcceptedResponse,
  ScanJobResponse,
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
  return requestWithInit<T>(path, undefined, params);
}

async function requestWithInit<T>(
  path: string,
  init?: RequestInit,
  params?: Record<string, string | undefined>
): Promise<T> {
  const url = buildAPIURL(path, params);
  const response = await fetch(url.toString(), {
    ...init,
    headers: {
      Accept: "application/json",
      ...(init?.headers ?? {})
    }
  });

  if (!response.ok) {
    const message = await readErrorMessage(response);
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

async function readErrorMessage(response: Response) {
  const message = await response.text();
  if (!message) {
    return "";
  }

  try {
    const parsed = JSON.parse(message) as { error?: string; message?: string };
    return parsed.error || parsed.message || message;
  } catch {
    return message;
  }
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

export function getImageTags(
  orgId: string,
  imageId: string,
  params?: {
    query?: string;
    page?: number;
    pageSize?: number;
  }
) {
  return request<ImageTagsResponse>(`/api/v1/images/${imageId}/tags`, {
    org_id: orgId,
    query: params?.query,
    page: params?.page ? String(params.page) : undefined,
    page_size: params?.pageSize ? String(params.pageSize) : undefined
  });
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

export function deriveImageId(imageName: string) {
  const trimmed = imageName.trim().toLowerCase();
  let sanitized = trimmed
    .replaceAll("/", "-")
    .replaceAll(":", "-")
    .replaceAll("@", "-")
    .replaceAll("+", "-")
    .replace(/[^a-z0-9._-]/g, "-")
    .replace(/^[\-.]+|[\-.]+$/g, "");

  if (!sanitized) {
    sanitized = "image";
  }

  const digest = Array.from(trimmed).reduce((hash, character) => {
    let next = hash ^ character.charCodeAt(0);
    next = Math.imul(next, 16777619);
    return next >>> 0;
  }, 2166136261);
  const suffix = digest.toString(16).padStart(8, "0");
  const maxPrefixLength = 128 - 1 - suffix.length;
  if (sanitized.length > maxPrefixLength) {
    sanitized = sanitized.slice(0, maxPrefixLength).replace(/[\-.]+$/g, "") || "image";
  }

  return `${sanitized}-${suffix}`;
}

export function startScan(imageName: string, orgId = "default") {
  return requestWithInit<ScanAcceptedResponse>(
    "/api/v1/scans",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        image_name: imageName,
        org_id: orgId,
        image_id: deriveImageId(imageName),
        async: true
      })
    }
  );
}

export function getScanJob(jobId: string) {
  return request<ScanJobResponse>(`/api/v1/scan-jobs/${jobId}`);
}

export async function getScanArtifactJSON(orgId: string, imageId: string, filename: string) {
  return requestWithInit<unknown>(`/api/v1/scans/${orgId}/${imageId}/files/${filename}`);
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
