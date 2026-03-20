# Otter — Agent Process

This is the project-level handoff file for future work in `otter/`.

It summarizes:

- what was implemented
- what was verified
- what still needs live-environment validation
- what future agents should preserve

## Purpose

Recommended reading order for a future agent:

1. `AGENT_PROCESS.md`
2. `Readme.md`
3. `scripts/ralph/otter/prd.json`
4. `scripts/ralph/otter/CLAUDE.md`
5. backend and frontend tests for the area being changed

## Project Status

The Ralph development track for Otter is complete.

All PRD stories in `scripts/ralph/otter/prd.json` are marked complete:

- `OTTER-001` through `OTTER-013`

## What Exists Today

Otter currently includes:

- local-first storage with local filesystem, PostgreSQL, and optional S3 backends
- Syft + Grype scanning with Trivy integration support
- CycloneDX and SPDX SBOM generation and import/export
- structured SBOM and vulnerability indexes
- image comparison reports
- attestation and provenance discovery
- compliance and standards tracking
- registry configuration and authenticated pull support
- async catalog scanning and scheduled rescans
- export formats including JSON, CSV, SPDX, CycloneDX, and SARIF
- React frontend with vertical tab layout and no-JavaScript browse fallback
- GitHub Actions CI/CD and release workflows
- backend and frontend test coverage meeting the PRD threshold

## Implemented Milestones

### OTTER-001: Local-first storage

- added a shared storage abstraction
- added local, PostgreSQL, and S3 backends
- migrated scan handlers to use the abstraction
- added Postgres migrations and compose support

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- local smoke test with `alpine:latest`

### OTTER-002: Trivy integration

- added analyzer abstraction
- added Trivy client wrapper
- merged Grype and Trivy vulnerability reports
- added runtime Docker and compose support for Trivy

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `docker compose config`

Note:

- a compose-backed live scan was attempted but image pulls were too slow during that session

### OTTER-003: SBOM storage and APIs

- added CycloneDX and SPDX generation
- added structured SBOM indexing
- added image SBOM read/import endpoints
- documented and tested SBOM APIs

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`

### OTTER-004: Vulnerability management and OpenVEX

- added structured vulnerability indexing
- added filtering and status-aware vulnerability APIs
- added OpenVEX import and advisory status application

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- local smoke test with `alpine:latest`

### OTTER-005: Image comparison

- added stored comparison generation
- added package, vulnerability, SBOM, and layer diffs
- added compare and comparison retrieval endpoints

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`

### OTTER-006: Attestation and provenance display

- added OCI referrer discovery
- added DSSE and in-toto parsing
- added best-effort Cosign verification support
- added attestation API

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`

### OTTER-007: Modern frontend

- added React + TypeScript + Vite frontend
- implemented directory plus all requested detail tabs
- added UI-facing backend APIs
- added static SPA serving and no-JS `/browse` fallback

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test`
- `npm run build`

### OTTER-008: Registry integration

- added registry configuration persistence
- added auth modes and health checks
- added scan preflight validation
- added registry APIs

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test`
- `npm run build`

### OTTER-009: Automated catalog scanning

- added async scan jobs
- added bounded worker queue and periodic scheduler
- added catalog APIs and env-driven default seeds

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test`
- `npm run build`

Note:

- live image scanning could not be fully exercised in that shell because `syft`, `grype`, and `trivy` were not installed there

### OTTER-010: Export functionality

- added export endpoints for SBOMs, vulnerability reports, and comparisons
- added CSV and SARIF generators
- wired export links into the frontend and HTML fallback

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test -- --run`
- `npm run build`

### OTTER-011: GitHub Actions CI/CD

- replaced the old CI workflow with real PR/main checks
- added GoReleaser and container workflows
- improved reusable workflow support and dependency review

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test`
- `npm run build`
- `actionlint .github/workflows/*.yml`
- `docker build -t otter-ci-smoke .`
- `docker run --rm otter-ci-smoke ...`
- `goreleaser ... check`

### OTTER-012: Compliance tracking

- added SLSA level detection
- added OpenSSF Scorecard integration
- added standards checklist summaries
- surfaced compliance in API and frontend overview

Verification:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- `npm test -- --run`
- `npm run build`

### OTTER-013: End-to-end testing and coverage

- expanded backend API/workflow coverage
- expanded frontend tab coverage
- raised Go coverage above the PRD threshold

Verification:

- `go test ./...`
- `go build ./...`
- `go vet ./...`
- `npm test -- --run`
- `npm run build`
- Go statement coverage verified at `70.0254%`

## What Was Verified

Verified during development:

- Go backend builds, vets, and tests
- frontend tests and production build
- many API workflow paths
- Dockerfile/CI/release configuration
- no-JS browse fallback

## What Still Needs Live-Environment Validation

The following are best-effort in code but still need real environment checks:

- full live scans with locally installed `syft`, `grype`, and optionally `trivy`
- live registry authentication against private registries
- live OCI referrer / Cosign verification against real signed images
- live Scorecard lookups under real network conditions
- production-like Docker Compose scans with all external scanners installed

## Operational Notes

- the backend listens on `:7789`
- if `frontend/dist` exists, the SPA is served at `/`
- without a built frontend, `/` redirects to `/browse`
- the catalog scanner is enabled by default unless `OTTER_CATALOG_SCANNER_ENABLED=false`
- scanner binaries are external runtime dependencies for real image analysis

## What Future Agents Should Preserve

- local-first operation as the default
- storage/scanning/registry abstractions rather than direct hardcoded coupling
- input validation for image names and registry config
- no-JS browse fallback
- API documentation in `docs/api.md`
- parity between backend capabilities and frontend tabs
- coverage discipline for both backend and frontend

## What Future Agents Should Update

If a major feature is added, update:

- `AGENT_PROCESS.md`
- `Readme.md`
- `docs/api.md`
- `scripts/ralph/otter/prd.json`
- frontend tests and backend tests for the changed behavior

If runtime dependencies change, also document:

- which scanner binaries are required
- which env vars are required
- how to run a local smoke test
