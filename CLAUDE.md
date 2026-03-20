# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Otter is an open-source SBOM & vulnerability analyzer for container images. It scans images, generates CycloneDX/SPDX SBOMs, lists vulnerabilities, and provides compliance assessments. Built with Go (backend) + React/TypeScript (frontend).

## Build & Development Commands

### Backend (Go)
```bash
make build                    # Build binary to ./bin/otter
make lint                     # golangci-lint + go fmt + go vet
go test ./...                 # Run all Go tests
go test ./pkg/scan/...        # Run tests for a single package
go vet ./...                  # Vet check
OTTER_STORAGE=local go run .  # Run locally with filesystem storage
```

### Frontend (React/TypeScript)
```bash
cd frontend && npm install    # Install dependencies
cd frontend && npm test       # Run Vitest tests
cd frontend && npm run build  # Build to frontend/dist/
cd frontend && npm run dev    # Dev server on :4173 (proxies API to :7789)
```

### Full Stack
```bash
docker compose up --build     # PostgreSQL + Trivy + Otter
```

### CI Pipeline
CI runs: gofmt check → golangci-lint (v1.64.8, 10m timeout) → go vet → go test → go build, plus frontend test → frontend build. golangci-lint is installed in CI via `go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8`.

## Architecture

### Backend Structure (`pkg/`)

- **`api/`** — HTTP handlers (Gin). `ScanHandler` orchestrates the full scan workflow.
- **`scan/`** — Image analysis engine. Uses Syft for SBOM generation, Grype + optional Trivy for vulnerability scanning. Scanners run in parallel via `errgroup`.
- **`storage/`** — Multi-backend storage abstraction (`Store` interface) with local filesystem, PostgreSQL, and S3 implementations. Backend selected via `OTTER_STORAGE` env var.
- **`sbomindex/`** — SBOM normalization and indexing. Normalizes CycloneDX/SPDX into a common model. `Repository` interface with local and PostgreSQL backends.
- **`vulnindex/`** — Vulnerability indexing with trend tracking, advisory status, and OpenVEX support. `Repository` interface with local and PostgreSQL backends.
- **`catalogscan/`** — Background worker queue + scheduler for periodic catalog scanning.
- **`attestation/`** — OCI referrer discovery + DSSE/in-toto/SLSA attestation parsing.
- **`compliance/`** — SLSA provenance assessment + OpenSSF Scorecard integration.
- **`compare/`** — Image-to-image comparison reports.
- **`reportexport/`** — Export to CSV, JSON, SPDX, CycloneDX, SARIF.
- **`routes/`** — HTTP route registration, SPA serving, fallback HTML browse mode.
- **`registry/`** — Registry configuration, auth, and rate-limited image access.

### Key Interfaces

- `storage.Store` — Put/Get/List/Delete across backends
- `scan.ImageAnalyzer` — `Analyze(ctx, imageRef) → AnalysisResult`
- `scan.VulnerabilityScanner` — `Scan(ctx, imageRef, sbom) → ScannerReport`
- `sbomindex.Repository` / `vulnindex.Repository` — Save/Get/List/Delete for index data
- `compliance.Assessor` — `Assess(ctx, Input) → Result`

### Entry Point

`main.go` initializes: storage backend → SBOM/vuln repositories → analyzer (Syft+scanners) → registry manager → catalog job queue + scheduler → Gin HTTP router on `:7789`.

### Frontend (`frontend/src/`)

React 18 + TypeScript + Vite + Tailwind CSS + React Query. Two main pages:
- `DirectoryPage` — searchable image catalog
- `ImageDetailPage` — tabbed detail view (overview, vulnerabilities, SBOM, attestations, compliance)

API client in `lib/api.ts`, types in `lib/types.ts`.

### Database

PostgreSQL with migrations in `db/migrations/`. Three tables: `scan_artifacts`, `sbom_indexes`, `vulnerability_indexes`.

### Storage Key Format

`otterxf/:org_id/:image_id/:filename`

### Scan Workflow

POST scan request → registry preflight → Syft SBOM generation → parallel Grype+Trivy scanning → vulnerability merge → index storage → artifact persistence. Supports async mode (returns 202, poll via `/api/v1/scan-jobs/:id`).

## Environment Variables

All prefixed with `OTTER_`. Key ones:
- `OTTER_STORAGE` — `local` (default), `postgres`, `s3`
- `OTTER_POSTGRES_DSN` — PostgreSQL connection string
- `OTTER_TRIVY_ENABLED` / `OTTER_TRIVY_SERVER_URL` — Enable Trivy scanning
- `OTTER_CATALOG_SCANNER_ENABLED` — Background catalog scanning (default: enabled)

See `Readme.md` for the full list.

## Testing Patterns

Go tests use `t.TempDir()` and `t.Setenv()` for isolated test environments. API tests use `httptest` and `sqlmock`. Frontend tests use Vitest with React Testing Library.
