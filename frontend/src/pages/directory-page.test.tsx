import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
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
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

describe("DirectoryPage", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockResolvedValue({
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
    }) as typeof fetch;
  });

  it("renders catalog results from the API", async () => {
    renderDirectory("/");

    expect(screen.getByRole("textbox", { name: /search images/i })).toBeInTheDocument();

    await waitFor(() => expect(screen.getByRole("heading", { name: "library/alpine" })).toBeInTheDocument());
    expect(screen.getByText("alpine:3.20")).toBeInTheDocument();
    expect(screen.getAllByText("CRITICAL").length).toBeGreaterThan(0);
    expect(screen.getByText("Merged scanner findings")).toBeInTheDocument();
  });
});
