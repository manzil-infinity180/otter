# Otter Architecture

This document describes the current Otter architecture, the main request and scan flows, how to run the stack locally, and the capabilities the project supports today.

## System shape

Otter is split into a Go backend and a React frontend.

### Backend layers

- `main.go`
  - loads configuration
  - selects the storage backend
  - initializes the SBOM and vulnerability repositories
  - builds the analyzer, registry manager, catalog worker, and Gin router
- `pkg/routes/`
  - registers API routes
  - serves the built SPA when `frontend/dist` exists
  - falls back to `/browse` HTML pages when the SPA bundle is absent
- `pkg/api/`
  - exposes scan, catalog, image detail, export, compare, registry, compliance, and attestation endpoints
- `pkg/scan/`
  - runs Syft
  - runs Grype and optional Trivy
  - merges scanner results into the combined vulnerability report
- `pkg/storage/`
  - persists raw artifacts in local storage, PostgreSQL, or S3
- `pkg/sbomindex/`
  - stores normalized package, license, and dependency metadata
- `pkg/vulnindex/`
  - stores normalized findings, scanner summaries, status overlays, and trends
- `pkg/attestation/`
  - discovers signatures and attestations through OCI referrers
- `pkg/compliance/`
  - evaluates SLSA-style provenance evidence and OpenSSF Scorecard posture
- `pkg/catalogscan/`
  - runs async scan jobs and the seeded catalog scheduler
- `pkg/registry/`
  - manages registry auth, preflight checks, and host-level pull throttling

### Frontend layers

- `frontend/src/App.tsx`
  - top-level routes and shell
- `frontend/src/pages/landing-page.tsx`
  - product overview and getting-started entry point
- `frontend/src/pages/directory-page.tsx`
  - scan intake, catalog listing, and active scan jobs
- `frontend/src/pages/image-detail-page.tsx`
  - deep image analysis tabs
- `frontend/src/pages/docs-page.tsx`
  - in-app architecture and usage guide
- `frontend/src/lib/api.ts`
  - REST client helpers
- `frontend/src/lib/types.ts`
  - shared frontend response contracts

## Primary flows

## Manual scan flow

1. The user enters an image reference in the directory page.
2. The frontend sends `POST /api/v1/scans` with `async=true`.
3. The backend validates the request and creates or runs the scan job.
4. Registry configuration is resolved, including public fallback when possible.
5. Syft generates the SBOM documents and normalized package graph.
6. Grype and optional Trivy run in parallel.
7. Otter merges findings and writes:
   - CycloneDX SBOM
   - SPDX SBOM
   - combined vulnerability report
   - per-scanner reports
8. Otter updates the SBOM and vulnerability indexes.
9. The frontend polls `GET /api/v1/scan-jobs/:id` and redirects to the image detail page when the job succeeds.

## Catalog flow

1. The directory page requests `GET /api/v1/catalog`.
2. The backend lists indexed images from the SBOM and vulnerability repositories.
3. The frontend filters the returned catalog cards client-side for quick browsing.
4. The user can open any stored image or start a new public scan.

## Image detail flow

1. The frontend requests:
   - `GET /api/v1/images/:id/overview`
   - `GET /api/v1/images/:id/vulnerabilities`
   - `GET /api/v1/images/:id/sbom`
   - `GET /api/v1/images/:id/attestations`
   - `GET /api/v1/images/:id/compliance`
   - `GET /api/v1/images/:id/tags`
2. The backend resolves normalized indexed data and stored artifacts.
3. The frontend renders tabs for overview, tags, comparison, vulnerabilities, SBOM, attestations, and advisories.

## Async catalog scheduler flow

1. On boot, Otter seeds a configured image list under the catalog org.
2. The scheduler queues scans on a repeating interval.
3. Re-scans keep stable `org_id` and `image_id` values so trend data stays attached to the same image record.

## Storage model

Artifacts and indexes are separated intentionally.

- Artifacts
  - stored through `storage.Store`
  - examples: `sbom.json`, `sbom-cyclonedx.json`, `sbom-spdx.json`, `vulnerabilities.json`, `grype-vulnerabilities.json`
- Indexes
  - stored through `sbomindex.Repository` and `vulnindex.Repository`
  - power the UI and filtered APIs without reparsing every raw artifact on each request

## Run locally

## Local storage mode

```bash
OTTER_STORAGE=local go run .
```

Backend URL: `http://localhost:7789`

## Frontend dev server

```bash
cd frontend
npm install
npm run dev
```

Frontend URL: `http://localhost:4173`

## Optional Trivy server

```bash
trivy server --listen 0.0.0.0:4954
OTTER_STORAGE=local OTTER_TRIVY_ENABLED=true OTTER_TRIVY_SERVER_URL=http://localhost:4954 go run .
```

## Docker Compose

```bash
docker compose up --build
```

## How to use Otter

### Through the UI

1. Open the landing page.
2. Click `Get started`.
3. Enter a public image reference such as `nginx:latest`.
4. Wait for the job status to complete.
5. Review the image detail tabs.
6. Export artifacts or compare against another stored tag.

### Through the API

1. Queue a scan with `POST /api/v1/scans`
2. Poll `GET /api/v1/scan-jobs/:id`
3. Query image data from the `overview`, `tags`, `vulnerabilities`, `sbom`, `attestations`, and `compliance` endpoints
4. Export results from `GET /api/v1/images/:id/export`

## Supported capabilities

- Public image scans
- Registry auth via docker config or explicit credentials
- Async jobs and seeded background scans
- CycloneDX and SPDX generation
- Grype and Trivy vulnerability analysis
- Advisory and OpenVEX status overlays
- OCI signature and attestation discovery
- Compliance posture derived from provenance and Scorecard signals
- Image comparison
- JSON, CSV, SARIF, SPDX, and CycloneDX exports
- SPA UI and HTML fallback browse mode

## Current route model

Frontend SPA routes:

- `/`
- `/directory`
- `/docs`
- `/images/:orgId/:imageId`

Fallback HTML routes:

- `/browse`
- `/browse/images/:org_id/:id`

## Tests and verification

Backend:

```bash
go test ./...
go vet ./...
```

Frontend:

```bash
cd frontend && npm test
cd frontend && npm run build
```
