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

The feature delivery track for Otter is complete, and the audit-remediation track is now in progress.

- Product stories `OTTER-001` through `OTTER-013` remain complete.
- Audit stories `OTTER-AUDIT-01` through `OTTER-AUDIT-10` are complete.
- Additional `OTTER-AUDIT-*` stories remain open in `scripts/ralph/otter/prd.json`.

## Latest Audit Remediation

### OTTER-AUDIT-10: cache and paginate remote repository tag discovery

What changed:

- added TTL-based remote tag caching to `pkg/registry.Manager`, configurable with `OTTER_REGISTRY_TAG_CACHE_TTL`, so repeated repository tag reads reuse the cached tag set instead of re-fetching the full registry listing on every request
- extended the registry service contract with `ListRepositoryTags`, keeping registry auth, policy enforcement, and rate limiting on the same path used for scan preflight before any remote tag discovery
- implemented `GET /api/v1/images/:id/tags` to merge the current image tag plus other stored same-repository scans with best-effort remote tag discovery, then paginate and filter the combined result set
- exposed additive response metadata for tag paging and cache visibility: `count`, `total`, `page`, `page_size`, `has_more`, `remote_cached`, `remote_cache_expires_at`, and `remote_tag_error`
- documented the new image-tag API and the remote tag cache TTL setting in `docs/api.md` and `Readme.md`

What was verified:

- `go test ./pkg/registry ./pkg/api ./pkg/routes`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- remote tag pagination is API-side over a cached full repository tag snapshot because the upstream registry client still exposes whole-list tag discovery; this remediation removes repeated full fetches on page loads without changing the existing registry dependency shape
- the tag listing route is additive and does not replace the existing overview payload, so current clients stay compatible while newer clients can move tag-heavy views to `GET /api/v1/images/:id/tags`
- operators with very large registries can tune `OTTER_REGISTRY_TAG_CACHE_TTL` upward to reduce registry traffic further, or set it to `0` to disable the cache if they prefer fresh tag reads every request

### OTTER-AUDIT-09: indexed catalog queries and pagination

What changed:

- restored and extended the `pkg/sbomindex` local repository with lightweight catalog sidecars plus per-repository tag indexes, so catalog listings no longer need to deserialize full SBOM records or scan every repository to build the image overview tag list
- added repository-level `QueryCatalog` and `ListRepositoryTags` support to both local and PostgreSQL SBOM index backends, including a new PostgreSQL migration that persists `repository_key` and adds supporting indexes for catalog and tag lookups
- refactored `pkg/api/catalog.go` to serve `GET /api/v1/catalog` and `/browse` from the indexed query path, with additive `page`, `page_size`, `total`, and `has_more` response metadata while preserving the existing `items` and `count` fields
- switched image overview tag resolution from a full `sbomIndex.List()` scan to `ListRepositoryTags`, so related-tag queries stay scoped to the current repository instead of walking the full catalog
- added local vulnerability summary sidecars so the filesystem-backed catalog query can still filter and sort on vulnerability severity without loading full vulnerability documents for every record
- added regression coverage for local and PostgreSQL catalog pagination, severity-aware query behavior, repository tag lookups, and API pagination metadata

What was verified:

- `go test ./pkg/sbomindex ./pkg/api`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- `GET /api/v1/catalog` now returns additive pagination metadata fields; older clients remain compatible because the existing `items` and `count` fields are unchanged
- PostgreSQL deployments need the new `000006_add_sbom_repository_keys` migration before the indexed catalog and repository-tag queries can use the persisted `repository_key` column
- existing local filesystem data picks up catalog sidecars opportunistically as records are rewritten; PostgreSQL records are backfilled by the migration, but operators with mixed historical image-name formats should still prefer rescanning if they need the most consistent repository grouping

### OTTER-AUDIT-08: persistent scan-job storage, retries, and restart recovery

What changed:

- replaced the in-memory-only catalog scan queue with a durable local job store under `OTTER_CATALOG_SCANNER_STATE_DIR`, writing one JSON record per async scan job so queued state survives process restarts across all storage backends
- refactored `pkg/catalogscan.Queue` to restore persisted pending and interrupted running jobs on startup, rebuild active-target deduplication state, and resume dispatch without requiring clients to re-enqueue work
- added capped retry behavior with queue-configurable `OTTER_CATALOG_SCANNER_RETRY_LIMIT`, `OTTER_CATALOG_SCANNER_RETRY_BACKOFF`, and `OTTER_CATALOG_SCANNER_RETRY_BACKOFF_MAX` settings; retry metadata now persists on the job record
- exposed queue observability through `Queue.Stats()` and surfaced queue-depth counters alongside `GET /api/v1/scan-jobs/:id`, while keeping the existing job-status route and status values backward compatible
- added regression coverage for persisted pending/running job recovery, retry success and retry exhaustion paths, env-driven queue durability settings, and queue metadata in the scan-job API response

What was verified:

- `go test ./pkg/catalogscan ./pkg/api`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- queue durability is intentionally local-file backed for this remediation pass, which keeps restart recovery simple without introducing a new shared database contract; multi-node queue coordination and broader retention controls remain later work
- operators upgrading existing deployments should ensure `OTTER_DATA_DIR` or `OTTER_CATALOG_SCANNER_STATE_DIR` points to persistent disk if they expect async jobs to survive container restarts
- `GET /api/v1/scan-jobs/:id` now includes additive retry and queue metadata fields, so strict response decoders should tolerate the extended payload

### OTTER-AUDIT-07: remove write side effects from read-only GET endpoints

What changed:

- refactored SBOM and vulnerability read handlers to build transient records from stored artifacts when an index row is missing instead of silently saving rebuilt indexes during GET requests
- updated the browse page and comparison target resolution to use the same read-only fallback path, so GET requests no longer mutate the vulnerability index as a side effect
- changed `GET /api/v1/compare` into a pure read-only comparison preview and added `POST /api/v1/comparisons` as the explicit persistence path for stored comparison artifacts and later exports
- added `POST /api/v1/images/:id/indexes/repair` so operators can explicitly rebuild missing SBOM and vulnerability indexes from already-stored artifacts without relying on request-time backfills
- updated the frontend comparison client to use the new persisted-comparison POST route and documented the new compare/repair flow in `docs/api.md`
- added regression coverage proving GET SBOM and vulnerability reads leave indexes absent, GET comparisons no longer write storage, repair requests persist missing indexes, and stored comparison workflows now go through the new POST route

What was verified:

- `go test ./pkg/api ./pkg/routes`
- `go test ./...`
- `go vet ./...`
- `go build ./...`
- `cd frontend && npm test`
- `cd frontend && npm run build`

Follow-up and rollout notes:

- existing clients that depended on `GET /api/v1/compare` creating a stored artifact now need to call `POST /api/v1/comparisons` before fetching `/api/v1/comparisons/:id` or `/export`
- the new repair endpoint is intentionally per-image and operator-driven; larger backfill or retention work for historical data still belongs in later queue/cleanup stories

### OTTER-AUDIT-06: honor platform selection end to end for multi-arch scans

What changed:

- added explicit scan platform normalization so `platform` is accepted end to end and the existing `arch` field now acts as a backward-compatible alias that normalizes to `linux/<arch>`
- threaded the selected platform through synchronous scans, async scan jobs, and catalog worker execution, then applied it to the Syft source configuration so requested platforms influence manifest resolution for multi-arch images
- captured the resolved platform from Syft image metadata and persisted it on stored artifacts plus structured SBOM and vulnerability index records across local and PostgreSQL backends, including a new migration for index platform columns
- exposed stored platform metadata in scan responses, job payloads, catalog and overview APIs, no-JavaScript browse pages, and the React image detail view and tag table
- added regression coverage for async platform propagation, analyze-context platform selection, persisted platform metadata, overview/tag platform rendering, PostgreSQL round-tripping, and frontend display

What was verified:

- `go test ./pkg/api ./pkg/scan ./pkg/sbomindex ./pkg/vulnindex ./pkg/catalogscan`
- `go test ./...`
- `go vet ./...`
- `go build ./...`
- `cd frontend && npm test`
- `cd frontend && npm run build`

Follow-up and rollout notes:

- imported SBOM or vulnerability documents that were never scanned still have no platform metadata unless operators re-scan them or enrich those records separately
- `platform` is now the preferred request field for scans; `arch` remains supported for compatibility, but future clients should send full OCI platform strings when they need variant-aware selection

### OTTER-AUDIT-05: persist artifact metadata across local, PostgreSQL, and S3 backends

What changed:

- added shared storage metadata helpers so artifact `metadata` maps are cloned, marshaled, and encoded consistently instead of only surviving the immediate `Put` response path
- updated the local filesystem backend to write a sidecar `.meta.json` file per artifact and to read persisted content type, metadata, and timestamps back through `Get` and `List`
- added a PostgreSQL migration for a nullable `scan_artifacts.metadata` JSONB column and updated the store queries so metadata round-trips through `Put`, `Get`, and `List`
- refactored the S3 backend to persist content type on upload, wrap artifact metadata into a single encoded S3 metadata envelope, and reload it through `GetObject` and `ListObjects`
- added regression coverage for local restart-safe metadata persistence, PostgreSQL metadata query round-tripping, S3 metadata/content-type round-tripping, and stored image reference fallback using a real persisted local artifact

What was verified:

- `go test ./pkg/storage ./pkg/api`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- existing artifacts written before this remediation keep their payloads, but they do not magically gain persisted metadata; operators should re-scan or re-import artifacts if they need metadata-backed fallback behavior on older records
- the local backend now maintains one metadata sidecar per stored artifact, and the S3 backend now performs a head/read of object metadata during listings; this fixes correctness first, while later performance work should optimize listing behavior if S3-backed catalogs grow large

### OTTER-AUDIT-04: audit events for scans, deletes, imports, and registry changes

What changed:

- added a new `pkg/audit` subsystem that emits structured JSON-line records with actor, org, target, action, outcome, timestamp, and metadata fields
- enabled env-configured audit sinks via `OTTER_AUDIT_ENABLED`, `OTTER_AUDIT_OUTPUTS`, and `OTTER_AUDIT_FILE`; by default Otter now appends events to `data/_audit/events.jsonl`
- wired audit emission into scan enqueue, synchronous scan completion, async catalog scan completion, scan deletion, SBOM import, VEX import, and registry configure flows
- propagated actor identity into async scan requests so queue-driven completion events preserve the initiating user or scheduler identity instead of collapsing to an anonymous worker
- added regression coverage for JSON-line audit recording, file-backed persistence, scheduler actor defaults, scan enqueue and completion events, import and delete events, and registry create events

What was verified:

- `go test ./pkg/audit ./pkg/api ./pkg/catalogscan`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- audit output is local-file backed by default, which is useful for single-node deployments, but operators using centralized logging should set `OTTER_AUDIT_OUTPUTS=file,stdout` or a similar forwarding configuration
- audit emission is best-effort and intentionally does not fail the user-facing API path if the sink write fails; sink failures are logged through the server logger and should be monitored in production

### OTTER-AUDIT-03: registry egress allowlists and safer defaults

What changed:

- added registry egress policy enforcement in `pkg/registry` so both registry configuration and image scan preflight now validate the target host before any outbound request is made
- added env-driven `OTTER_REGISTRY_ALLOWLIST` and `OTTER_REGISTRY_DENYLIST` support with exact-host and `*.` suffix matching
- blocked loopback, RFC1918/private, link-local, carrier-grade NAT, benchmark, and common cluster-internal registry targets by default, including DNS names that resolve to private addresses
- required explicit operator opt-in through `OTTER_REGISTRY_ALLOW_PRIVATE_NETWORKS=true` for internal targets and `OTTER_REGISTRY_ALLOW_INSECURE=true` for `insecure_use_http` or `insecure_skip_tls_verify`
- logged allow and deny policy decisions with registry, host, action, and reason so operator overrides are visible in server logs
- updated scan error rendering so registry policy denials return `400` instead of a generic upstream/preflight failure
- added regression tests covering blocked loopback/private targets, insecure override rejection, allowlist and denylist matching, explicit operator opt-ins, DNS-to-private blocking, and the API error mapping

What was verified:

- `go test ./pkg/registry/... ./pkg/api/...`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- existing localhost or in-cluster registry deployments now need explicit environment opt-ins before registry configuration or scans will succeed
- allowlist/denylist matching is hostname-based and intentionally simple; if operators need more complex network policy, keep using upstream network controls in addition to these app-level checks

### OTTER-AUDIT-02: stop storing registry credentials in plaintext on disk

What changed:

- refactored `pkg/registry` local persistence so `registries.json` now stores only registry metadata plus a per-registry `secret_ref` marker instead of raw explicit credentials
- added an encrypted local secret store under `pkg/registry` that writes one AES-GCM protected secret blob per registry, so secret rotation only rewrites that registry's secret file
- kept the runtime `Record` contract intact by decrypting registry credentials on repository reads before health checks and scan preflight use them
- added in-place compatibility migration for legacy plaintext `registries.json` entries so existing explicit credentials are moved into encrypted secret files and removed from metadata on first read/write
- removed orphaned secret files when a registry switches from explicit credentials back to docker-config auth
- added repository tests covering redaction, encrypted persistence, per-registry secret rotation isolation, and legacy plaintext migration

What was verified:

- `go test ./pkg/registry/...`
- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- operators can provide `OTTER_REGISTRY_SECRET_KEY` or `OTTER_REGISTRY_SECRET_KEY_FILE` to supply a stable 32-byte base64 or hex key; otherwise Otter auto-generates a local key file at `_registry/registry-secrets.key`
- the auto-generated key file preserves backward compatibility for local installs, but managed deployments should inject the key through environment or a mounted file so secret storage can be rotated and controlled explicitly

### OTTER-AUDIT-01: authentication, authorization, and org isolation

What changed:

- added a token-based auth layer in `pkg/auth` with explicit org scopes, optional admin tokens, and support for `Authorization: Bearer`, `X-Otter-API-Token`, or `otter_api_token` cookie credentials
- enabled auth middleware in the real Gin router and protected all `/api/v1/**`, `/api/v1/aws/**`, and server-rendered `/browse` routes
- made registry configuration/listing admin-only because those endpoints mutate or expose global registry state
- enforced org access checks inside scan, image, catalog, job, and comparison handlers so callers cannot read or modify resources outside their assigned orgs
- removed implicit `default_org` and `default_image` fallbacking from artifact ID normalization so write paths now require explicit org and image IDs
- restricted catalog listings and comparison resolution to the authenticated identity's allowed org set when auth is enabled
- added route-level regression tests for unauthenticated requests, cross-org access, admin-only registry access, and stored comparison access

What was verified:

- `go test ./...`
- `go vet ./...`
- `go build ./...`

Follow-up and rollout notes:

- auth now defaults to enabled in the main server; operators must provide `OTTER_AUTH_TOKENS` or `OTTER_AUTH_TOKENS_FILE`, or explicitly set `OTTER_AUTH_ENABLED=false` for a localhost/demo-only deployment
- the token configuration format is a JSON array of `{token, subject, orgs, admin}` records
- the SPA remains static, so browser-based access should use the `otter_api_token` cookie or a same-origin proxy/header injection strategy until a first-class login/session flow exists

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
