import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import userEvent from "@testing-library/user-event";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DirectoryPage } from "./directory-page";

function renderDirectory(entry = "/") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false }
    }
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <MemoryRouter initialEntries={[entry]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <Routes>
          <Route path="/" element={<DirectoryPage />} />
          <Route path="/images/:orgId/:imageId" element={<div>Image detail route</div>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("DirectoryPage", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      const method = init?.method ?? (input instanceof Request ? input.method : "GET");

      if (url.includes("/api/v1/scans") && method === "POST") {
        return {
          ok: true,
          json: async () => ({
            message: "scan queued successfully",
            status_url: "/api/v1/scan-jobs/scanjob-123",
            job: {
              id: "scanjob-123",
              status: "pending",
              created_at: "2026-03-13T18:35:00Z",
              request: {
                org_id: "default",
                image_id: "nginx-latest-deadbeef",
                image_name: "nginx:latest",
                source: "api",
                trigger: "manual"
              }
            }
          })
        };
      }

      if (url.includes("/api/v1/scan-jobs/scanjob-123")) {
        return {
          ok: true,
          json: async () => ({
            storage_backend: "local",
            job: {
              id: "scanjob-123",
              status: "pending",
              created_at: "2026-03-13T18:35:00Z",
              request: {
                org_id: "default",
                image_id: "nginx-latest-deadbeef",
                image_name: "nginx:latest",
                source: "api",
                trigger: "manual"
              }
            }
          })
        };
      }

      return {
        ok: true,
        json: async () => ({
          count: 1,
          storage_backend: "local",
          items: [
            {
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
                total: 3,
                by_severity: { CRITICAL: 1, HIGH: 2 },
                by_scanner: { grype: 3 },
                fixable: 2,
                unfixable: 1
              },
              scanners: ["grype"],
              updated_at: "2026-03-13T18:30:00Z"
            }
          ]
        })
      };
    }) as typeof fetch;
  });

  it("renders catalog results from the API", async () => {
    renderDirectory("/");

    expect(screen.getByRole("textbox", { name: /filter catalog/i })).toBeInTheDocument();

    await waitFor(() => expect(screen.getByRole("heading", { name: "library/alpine" })).toBeInTheDocument());
    expect(screen.getByText("alpine:3.20")).toBeInTheDocument();
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
    expect(screen.getByText("Merged scanner findings")).toBeInTheDocument();
  });

  it("queues a new scan job from the directory hero", async () => {
    const user = userEvent.setup();
    renderDirectory("/");

    await user.type(screen.getByRole("textbox", { name: /scan image/i }), "nginx:latest");
    await user.click(screen.getByRole("button", { name: "Scan image" }));

    await waitFor(() => expect(screen.getByRole("heading", { name: "Active scan jobs" })).toBeInTheDocument());
    expect(screen.getAllByText("nginx:latest").length).toBeGreaterThan(0);
    expect(screen.getByText("Queued and waiting for a scanner worker.")).toBeInTheDocument();
  });
});
