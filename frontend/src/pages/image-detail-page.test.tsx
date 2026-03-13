import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ImageDetailPage } from "./image-detail-page";

function renderImagePage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false }
    }
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={["/images/demo-org/image-a"]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/images/:orgId/:imageId" element={<ImageDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("ImageDetailPage", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;

      if (url.includes("/overview")) {
        return {
          ok: true,
          json: async () => ({
            org_id: "demo-org",
            image_id: "image-a",
            image_name: "alpine:3.20",
            registry: "index.docker.io",
            repository: "index.docker.io/library/alpine",
            repository_path: "library/alpine",
            tag: "3.20",
            package_count: 12,
            license_summary: [],
            vulnerability_summary: {
              total: 2,
              by_severity: { CRITICAL: 1, HIGH: 1 },
              by_scanner: { grype: 2 },
              by_status: { affected: 2 },
              fixable: 1,
              unfixable: 1
            },
            scanners: ["grype"],
            updated_at: "2026-03-13T18:30:00Z",
            storage_backend: "local",
            dependency_roots: ["pkg:apk/alpine/busybox@1.0.0"],
            files: [],
            tags: [
              {
                org_id: "demo-org",
                image_id: "image-b",
                image_name: "alpine:3.19",
                tag: "3.19",
                package_count: 10,
                vulnerability_summary: {
                  total: 4,
                  by_severity: { HIGH: 2 },
                  by_scanner: { trivy: 4 },
                  fixable: 4,
                  unfixable: 0
                },
                updated_at: "2026-03-13T17:30:00Z"
              }
            ]
          })
        };
      }

      if (url.includes("/vulnerabilities")) {
        return {
          ok: true,
          json: async () => ({
            org_id: "demo-org",
            image_id: "image-a",
            image_name: "alpine:3.20",
            summary: {
              total: 2,
              by_severity: { CRITICAL: 1, HIGH: 1 },
              by_scanner: { grype: 2 },
              by_status: { affected: 1, fixed: 1 },
              fixable: 1,
              unfixable: 1
            },
            vulnerabilities: [
              {
                id: "CVE-2024-0001",
                severity: "CRITICAL",
                package_name: "busybox",
                package_version: "1.36.1",
                scanners: ["grype"],
                status: "affected",
                status_source: "scanner",
                first_seen_at: "2026-03-13T18:30:00Z",
                last_seen_at: "2026-03-13T18:30:00Z"
              }
            ],
            fix_recommendations: [],
            vex_documents: [],
            updated_at: "2026-03-13T18:30:00Z"
          })
        };
      }

      if (url.includes("/compliance")) {
        return {
          ok: true,
          json: async () => ({
            org_id: "demo-org",
            image_id: "image-a",
            image_name: "alpine:3.20",
            storage_backend: "local",
            image_ref: "alpine:3.20",
            scope_note: "Best-effort standards tracking.",
            source_repository: {
              host: "github.com",
              owner: "demo",
              name: "project",
              repository: "github.com/demo/project",
              url: "https://github.com/demo/project",
              derived_from: "attestation.materials",
              confidence: "high"
            },
            slsa: {
              level: 3,
              target_level: 3,
              status: "pass",
              verified: true,
              builder_id: "https://github.com/actions/runner",
              build_type: "https://slsa.dev/container-based-build/v1",
              invocation_id: "run-123",
              materials: ["git+https://github.com/demo/project@refs/heads/main"],
              evidence: ["provenance attestation detected"],
              missing: []
            },
            scorecard: {
              enabled: true,
              available: true,
              status: "pass",
              repository: "github.com/demo/project",
              score: 8.9,
              risk_level: "strong",
              checks: [{ name: "Maintained", score: 10, reason: "active project" }]
            },
            standards: [
              {
                name: "SLSA",
                status: "pass",
                summary: "SLSA Level 3 evidence is present.",
                checks: [{ id: "slsa-provenance", title: "Provenance attestation", status: "pass", detail: "Detected." }]
              }
            ],
            summary: {
              overall_status: "pass",
              passed: 3,
              partial: 0,
              failed: 0,
              unavailable: 0
            },
            updated_at: "2026-03-13T18:30:00Z"
          })
        };
      }

      if (url.includes("/sbom")) {
        return {
          ok: true,
          json: async () => ({
            org_id: "demo-org",
            image_id: "image-a",
            image_name: "alpine:3.20",
            format: "cyclonedx",
            package_count: 12,
            packages: [
              { id: "pkg:apk/alpine/busybox@1.36.1", name: "busybox", version: "1.36.1", type: "apk", licenses: ["GPL-2.0-only"] }
            ],
            license_summary: [{ license: "GPL-2.0-only", count: 1 }],
            dependency_roots: ["pkg:apk/alpine/busybox@1.36.1"],
            dependency_tree: [{ id: "pkg:apk/alpine/busybox@1.36.1", name: "busybox", version: "1.36.1", depends_on: [] }],
            updated_at: "2026-03-13T18:30:00Z",
            document: {}
          })
        };
      }

      if (url.includes("/attestations")) {
        return {
          ok: true,
          json: async () => ({
            org_id: "demo-org",
            image_id: "image-a",
            image_name: "alpine:3.20",
            summary: {
              total: 1,
              signatures: 1,
              attestations: 0,
              provenance: 0,
              by_verification_status: { valid: 1 }
            },
            signatures: [
              {
                digest: "sha256:abc123",
                kind: "signature",
                source: "cosign",
                verification_status: "valid",
                signer: "builder@example.com"
              }
            ],
            attestations: [],
            updated_at: "2026-03-13T18:30:00Z"
          })
        };
      }

      if (url.includes("/api/v1/catalog")) {
        return {
          ok: true,
          json: async () => ({
            count: 1,
            storage_backend: "local",
            items: [
              {
                org_id: "demo-org",
                image_id: "image-b",
                image_name: "alpine:3.19",
                registry: "index.docker.io",
                repository: "index.docker.io/library/alpine",
                repository_path: "library/alpine",
                tag: "3.19",
                package_count: 10,
                license_summary: [],
                vulnerability_summary: {
                  total: 4,
                  by_severity: { HIGH: 2 },
                  by_scanner: { trivy: 4 },
                  fixable: 4,
                  unfixable: 0
                },
                scanners: ["trivy"],
                updated_at: "2026-03-13T17:30:00Z"
              }
            ]
          })
        };
      }

      if (url.includes("/api/v1/compare")) {
        return {
          ok: true,
          json: async () => ({
            comparison_id: "comparison-123",
            comparison: {
              id: "comparison-123",
              summary: {
                message: "Image B has 1 fewer vulns and 2 fewer packages",
                package_delta: -2,
                vulnerability_delta: -1,
                changed_layer_delta: 1,
                image2_fewer_packages: 2,
                image2_fewer_vulnerabilities: 1
              },
              package_diff: {
                added: [],
                removed: [],
                changed: []
              },
              vulnerability_diff: {
                new: [],
                fixed: [],
                unchanged: []
              },
              layer_diff: {
                image1_count: 4,
                image2_count: 3
              },
              sbom_diff: {
                components_added: 0,
                components_removed: 0,
                components_changed: 0
              }
            }
          })
        };
      }

      throw new Error(`Unhandled request ${url}`);
    }) as typeof fetch;
  });

  it("renders the vertical tab layout and vulnerability tab content", async () => {
    const user = userEvent.setup();
    renderImagePage();

    await waitFor(() => expect(screen.getByRole("heading", { name: "library/alpine" })).toBeInTheDocument());
    expect(screen.getByRole("tab", { name: "Overview" })).toHaveAttribute("aria-selected", "true");

    await user.click(screen.getByRole("tab", { name: "Vulnerabilities" }));

    await waitFor(() => expect(screen.getByText("CVE-2024-0001")).toBeInTheDocument());
    expect(screen.getByRole("tab", { name: "Vulnerabilities" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByText("busybox 1.36.1")).toBeInTheDocument();
  });

  it("renders the compliance dashboard in the overview tab", async () => {
    renderImagePage();

    await waitFor(() => expect(screen.getByRole("heading", { name: "Compliance posture" })).toBeInTheDocument());
    expect(screen.getByText("github.com/demo/project")).toBeInTheDocument();
    expect(screen.getByText("SLSA 3")).toBeInTheDocument();
    expect(screen.getByText("OpenSSF Scorecard")).toBeInTheDocument();
  });

  it("renders export links for image and comparison downloads", async () => {
    const user = userEvent.setup();
    renderImagePage();

    await waitFor(() => expect(screen.getByRole("link", { name: /Export SARIF/ })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: /Export CycloneDX/ })).toHaveAttribute(
      "href",
      expect.stringContaining("/api/v1/images/image-a/export?org_id=demo-org&format=cyclonedx")
    );
    expect(screen.getByRole("link", { name: /Export SARIF/ })).toHaveAttribute(
      "href",
      expect.stringContaining("/api/v1/images/image-a/export?org_id=demo-org&format=sarif")
    );

    await user.click(screen.getByRole("tab", { name: "Comparison" }));
    await user.selectOptions(screen.getByRole("combobox", { name: "Comparison target" }), "demo-org/image-b");
    await user.click(screen.getByRole("button", { name: "Run comparison" }));

    await waitFor(() => expect(screen.getByRole("link", { name: "Download comparison JSON" })).toBeInTheDocument());
    expect(screen.getByRole("link", { name: "Download comparison JSON" })).toHaveAttribute(
      "href",
      expect.stringContaining("/api/v1/comparisons/comparison-123/export")
    );
  });
});
