# Otter

Otter is an open-source SBOM and vulnerability analyzer for container images.

It scans container images, generates CycloneDX and SPDX SBOMs, merges vulnerability findings from Grype and Trivy, stores scan artifacts, and exposes a React UI plus REST APIs for review, export, compliance posture, attestations, advisories, and comparisons.

For a deeper architecture walkthrough, see [docs/architecture.md](docs/architecture.md) and [docs/api.md](docs/api.md).

Tutorials:

- [docs/tutorial-otter-supply-chain-walkthrough.md](docs/tutorial-otter-supply-chain-walkthrough.md)
- [docs/tutorial-baseline-vs-hardened.md](docs/tutorial-baseline-vs-hardened.md)
- [docs/issues/README.md](docs/issues/README.md)

## Current architecture

### Backend

- `main.go` initializes storage, the SBOM and vulnerability repositories, the analyzer pipeline, the registry manager, the background catalog worker, and the Gin router.
- `pkg/api/` contains HTTP handlers. `ScanHandler` is the main orchestration point for scan, catalog, image detail, comparison, export, compliance, attestation, and registry endpoints.
- `pkg/scan/` runs Syft for SBOM generation and Grype plus optional Trivy for vulnerability scanning.
- `pkg/storage/` persists artifacts across local filesystem, PostgreSQL, or S3.
- `pkg/sbomindex/` and `pkg/vulnindex/` normalize queryable image-level records for the UI and APIs.
- `pkg/attestation/` and `pkg/compliance/` evaluate OCI referrers, provenance, signatures, and OpenSSF Scorecard signals.
- `pkg/catalogscan/` provides async jobs and the seeded background catalog scanner.

### Frontend

- `frontend/src/App.tsx` defines the SPA shell and routes.
- `frontend/src/pages/landing-page.tsx` is the landing page.
- `frontend/src/pages/directory-page.tsx` is the scan intake and catalog browsing view.
- `frontend/src/pages/image-detail-page.tsx` is the tabbed detail view for overview, tags, comparison, vulnerabilities, SBOM, attestations, and advisories.
- `frontend/src/pages/docs-page.tsx` documents the current architecture and usage in-app.
- `frontend/src/lib/api.ts` and `frontend/src/lib/types.ts` define the frontend contract with the Go backend.

## Main flow

1. A user scans an image from the UI or sends `POST /api/v1/scans`.
2. Otter performs registry preflight and resolves credentials or anonymous public access.
3. Syft generates CycloneDX and SPDX SBOMs.
4. Grype and optional Trivy run in parallel to produce vulnerability findings.
5. Otter merges findings into a combined report and stores all artifacts.
6. The SBOM and vulnerability indexes are updated for image-level APIs and UI tabs.
7. The image detail page becomes available for review, export, comparison, compliance, and attestation discovery.

## What Otter supports

- Public image scanning from the UI and API
- Async scan jobs with polling via `GET /api/v1/scan-jobs/:id`
- Seeded background catalog scans
- Local filesystem, PostgreSQL, and S3 storage modes
- CycloneDX and SPDX SBOM generation
- Grype and Trivy vulnerability scanning
- OpenVEX import and advisory-aware vulnerability status
- OCI signature and attestation discovery
- OpenSSF Scorecard and supply-chain posture checks
- Image comparison plus CycloneDX, SPDX, JSON, CSV, and SARIF exports
- React UI and HTML fallback browsing mode

## Run locally

### Backend

```bash
OTTER_STORAGE=local go run .
```

This starts the API on `http://localhost:7789`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

This starts the Vite dev server on `http://localhost:4173` and proxies API calls to the Go backend.

### Optional Trivy server

```bash
trivy server --listen 0.0.0.0:4954
OTTER_STORAGE=local OTTER_TRIVY_ENABLED=true OTTER_TRIVY_SERVER_URL=http://localhost:4954 go run .
```

### Full stack with Docker Compose

```bash
docker compose up --build
```

## Typical local workflow

1. Start the backend with `OTTER_STORAGE=local go run .`
2. Start the frontend with `cd frontend && npm run dev`
3. Open `http://localhost:4173`
4. Use the landing page to jump into the directory or docs
5. Scan a public image such as `nginx:latest`
6. Wait for the async scan job to finish
7. Open the image detail page and inspect the tabs

## Environment variables

Common variables:

- `OTTER_STORAGE`
- `OTTER_DATA_DIR`
- `OTTER_DOCKER_CONFIG_PATH`
- `OTTER_REGISTRY_HEALTHCHECK_TIMEOUT`
- `OTTER_REGISTRY_PULL_INTERVAL`
- `OTTER_REGISTRY_PULLS_PER_SECOND`
- `OTTER_POSTGRES_DSN`
- `OTTER_POSTGRES_MIGRATIONS`
- `OTTER_TRIVY_ENABLED`
- `OTTER_TRIVY_SERVER_URL`
- `OTTER_TRIVY_BINARY`
- `OTTER_TRIVY_TIMEOUT`
- `OTTER_TRIVY_SCANNERS`
- `OTTER_COSIGN_BINARY`
- `OTTER_COSIGN_TIMEOUT`
- `OTTER_COSIGN_PUBLIC_KEY`
- `OTTER_COSIGN_IDENTITY_REGEXP`
- `OTTER_COSIGN_OIDC_ISSUER_REGEXP`
- `OTTER_CATALOG_SCANNER_ENABLED`
- `OTTER_CATALOG_SCANNER_INTERVAL`
- `OTTER_CATALOG_SCANNER_TIMEOUT`
- `OTTER_CATALOG_SCANNER_WORKERS`
- `OTTER_CATALOG_SCANNER_QUEUE_SIZE`
- `OTTER_CATALOG_SCANNER_JOB_HISTORY_LIMIT`
- `OTTER_CATALOG_SCANNER_ORG_ID`
- `OTTER_CATALOG_SCANNER_IMAGES`
- `OTTER_SCORECARD_ENABLED`
- `OTTER_SCORECARD_BASE_URL`
- `OTTER_SCORECARD_TIMEOUT`
- `OTTER_SCORECARD_SHOW_DETAILS`
- `S3_BUCKET_NAME`
- `AWS_REGION`

## Useful commands

### Backend

```bash
make build
make lint
go test ./...
go vet ./...
```

### Frontend

```bash
cd frontend && npm test
cd frontend && npm run build
```

## API highlights

- `POST /api/v1/scans`
- `GET /api/v1/scan-jobs/:id`
- `GET /api/v1/catalog`
- `GET /api/v1/images/:id/overview`
- `GET /api/v1/images/:id/tags`
- `GET /api/v1/images/:id/vulnerabilities`
- `GET /api/v1/images/:id/sbom`
- `GET /api/v1/images/:id/attestations`
- `GET /api/v1/images/:id/compliance`
- `POST /api/v1/images/:id/vex`
- `GET /api/v1/images/:id/export`
- `GET /api/v1/compare`
- `GET /browse`

See [docs/api.md](docs/api.md) for the complete API behavior.
