# Otter Repo Audit

Date: 2026-03-20

Scope:

- backend architecture
- scan pipeline
- storage and indexing
- registry integration
- attestation and compliance paths
- frontend product flow
- operational and enterprise adoption gaps

GitHub issue creation status:

- `gh auth status` currently reports an invalid token for `manzil-infinity180`
- issue creation from this machine is blocked until `gh auth login -h github.com` is fixed

## Executive summary

Otter has a solid local-first base: the scan flow is coherent, the APIs are reasonably structured, the test coverage is good for the current size, and the product direction is clear. The main blockers for broader company adoption are not UI polish. They are security boundaries, secret handling, persistence semantics, and scale characteristics.

The highest-priority adoption blockers are:

1. no authentication or authorization boundary across the API
2. plaintext registry credentials stored on disk
3. unrestricted outbound registry access from user-supplied image references
4. in-memory async job state with no restart durability
5. catalog and image-detail read paths that do full scans or backfill writes

## Recommended issue labels

- `security`
- `bug`
- `reliability`
- `performance`
- `feature`
- `adoption`
- `api`
- `frontend`
- `backend`
- `priority/p0`
- `priority/p1`
- `priority/p2`

## Issue register

| ID | Priority | Type | Title |
| --- | --- | --- | --- |
| OTTER-AUDIT-01 | P0 | Security | Add authentication, authorization, and org isolation across the API |
| OTTER-AUDIT-02 | P0 | Security | Stop storing registry credentials in plaintext on disk |
| OTTER-AUDIT-03 | P0 | Security | Add outbound registry allowlists and block unsafe internal-network scans by default |
| OTTER-AUDIT-04 | P1 | Security | Add audit events for scans, deletes, imports, and registry configuration changes |
| OTTER-AUDIT-05 | P1 | Bug | Persist artifact metadata across local, PostgreSQL, and S3 backends |
| OTTER-AUDIT-06 | P1 | Bug | Honor the `arch` scan request field and expose platform selection end to end |
| OTTER-AUDIT-07 | P1 | Reliability | Remove write side effects from read-only GET endpoints |
| OTTER-AUDIT-08 | P1 | Reliability | Replace the in-memory scan queue with persistent job storage, retries, and recovery |
| OTTER-AUDIT-09 | P1 | Performance | Replace full-catalog scans and N+1 lookups with indexed queries and pagination |
| OTTER-AUDIT-10 | P1 | Performance | Cache and paginate remote repository tag discovery |
| OTTER-AUDIT-11 | P1 | Bug | Verify signatures and attestations per record instead of applying one shared result |
| OTTER-AUDIT-12 | P2 | Operations | Extend `/healthz` into real readiness and dependency health checks |
| OTTER-AUDIT-13 | P2 | Operations | Add retention and garbage collection for comparison artifacts and historical jobs |
| OTTER-AUDIT-14 | P1 | Feature | Add policy-as-code and gating modes for enterprise adoption |
| OTTER-AUDIT-15 | P1 | Feature | Add OIDC/SSO, service tokens, and tenant-aware audit UI |
| OTTER-AUDIT-16 | P2 | Feature | Add metrics, tracing, and operator-facing scan/queue observability |

## Detailed issue drafts

## OTTER-AUDIT-01

Title:
Add authentication, authorization, and org isolation across the API

Type:
Security

Priority:
P0

Why this matters:

Otter currently exposes scan creation, scan deletion, SBOM import, VEX import, registry configuration, and all read endpoints without any authentication or authorization guard. That is acceptable for a localhost demo, but it is a hard blocker for any multi-user or company deployment.

Evidence:

- [pkg/routes/scan.go](pkg/routes/scan.go)
- [pkg/api/scan.go](pkg/api/scan.go)
- [pkg/api/registry.go](pkg/api/registry.go)
- [pkg/api/keys.go](pkg/api/keys.go)

Notes:

- `DELETE /api/v1/scans/:org_id/:image_id` is unauthenticated
- `POST /api/v1/registries` is unauthenticated
- `POST /api/v1/images/:id/sbom` and `POST /api/v1/images/:id/vex` are unauthenticated
- `normalizeArtifactIDs()` silently defaults empty IDs, which is unsafe in a shared deployment

Proposed work:

- add auth middleware for API routes
- support OIDC or bearer tokens for users and automation
- introduce org ownership checks on all read and write operations
- remove silent fallback to `default_org` and `default_image` for write paths

Acceptance criteria:

- every mutating endpoint requires authenticated identity
- org-scoped resources cannot be read or modified across org boundaries
- unauthenticated requests receive `401`
- unauthorized org access receives `403`

## OTTER-AUDIT-02

Title:
Stop storing registry credentials in plaintext on disk

Type:
Security

Priority:
P0

Why this matters:

Explicit registry usernames, passwords, and tokens are persisted directly in the local registry repository file. That creates immediate credential-at-rest risk.

Evidence:

- [pkg/registry/types.go](pkg/registry/types.go)
- [pkg/registry/local.go](pkg/registry/local.go)

Notes:

- `registry.Record` contains `Username`, `Password`, and `Token`
- `LocalRepository.store()` writes the whole record set as JSON to disk

Proposed work:

- encrypt credentials at rest or store only references to a secret backend
- integrate with OS keychain, Vault, or cloud secret managers
- separate safe registry metadata from secret material

Acceptance criteria:

- no raw passwords or tokens are written to `registries.json`
- secret rotation can happen without rewriting unrelated registry metadata
- exported registry summaries remain secret-free

## OTTER-AUDIT-03

Title:
Add outbound registry allowlists and block unsafe internal-network scans by default

Type:
Security

Priority:
P0

Why this matters:

Otter will attempt remote registry access for user-supplied image references and configured registry hosts. In a company environment, that can become an SSRF-style egress surface into internal registries or internal network targets.

Evidence:

- [pkg/api/validation.go](pkg/api/validation.go)
- [pkg/registry/service.go](pkg/registry/service.go)

Notes:

- `validateRegistryName()` accepts arbitrary hostnames
- `PrepareImage()` calls `remote.Head()` against the resolved registry
- `ConfigureRequest` also exposes `insecure_skip_tls_verify` and `insecure_use_http`

Proposed work:

- introduce a registry hostname allowlist and optional denylist
- reject RFC1918, loopback, link-local, and cluster-internal targets by default
- require explicit config to permit plain HTTP or TLS skip-verify
- expose egress policy settings in config and docs

Acceptance criteria:

- internal-network registry access is blocked by default
- unsafe HTTP/TLS bypass requires explicit operator opt-in
- policy decisions are logged clearly

## OTTER-AUDIT-04

Title:
Add audit events for scans, deletes, imports, and registry configuration changes

Type:
Security

Priority:
P1

Why this matters:

Even after auth is added, Otter still needs traceability for who scanned what, who imported advisory data, and who changed registry access settings.

Evidence:

- [pkg/api/scan.go](pkg/api/scan.go)
- [pkg/api/registry.go](pkg/api/registry.go)

Proposed work:

- add structured audit events for scan enqueue, scan completion, scan delete, SBOM import, VEX import, registry create/update
- persist a minimal audit log or emit to external sinks
- surface actor identity, org, target image, and timestamp

Acceptance criteria:

- all sensitive actions emit structured audit records
- audit output can be exported or forwarded

## OTTER-AUDIT-05

Title:
Persist artifact metadata across local, PostgreSQL, and S3 backends

Type:
Bug

Priority:
P1

Why this matters:

Several flows rely on artifact metadata, but the storage backends do not round-trip it consistently. That breaks scanner-unavailable UX, weakens image reference fallback logic, and creates backend-dependent behavior.

Evidence:

- [pkg/storage/local.go](pkg/storage/local.go)
- [pkg/storage/postgres.go](pkg/storage/postgres.go)
- [pkg/storage/s3.go](pkg/storage/s3.go)
- [pkg/api/scan.go](pkg/api/scan.go)

Notes:

- `store.Put()` accepts metadata
- `resolveStoredImageReference()` searches `object.Metadata["image_name"]`
- `collectScannerWarnings()` and the overview artifact table depend on scanner metadata
- `Get()` and `List()` do not reload metadata for local, PostgreSQL, or S3 objects

Acceptance criteria:

- metadata is preserved and returned identically across all storage backends
- scanner availability messages survive process restarts
- fallback image reference resolution works from stored artifacts

## OTTER-AUDIT-06

Title:
Honor the `arch` scan request field and expose platform selection end to end

Type:
Bug

Priority:
P1

Why this matters:

The public API advertises an `arch` field, but the scan execution path currently ignores it. That is a correctness gap for multi-arch images and can produce misleading SBOMs or vulnerability results.

Evidence:

- [pkg/api/scan.go](pkg/api/scan.go)
- [docs/api.md](docs/api.md)

Notes:

- `ImageGeneratePayload` contains `Arch`
- `executeScan()` never uses `payload.Arch`

Proposed work:

- map API arch/platform input into the image source resolution layer
- support `linux/amd64`, `linux/arm64`, and future full platform strings
- expose the chosen platform in stored metadata and UI

Acceptance criteria:

- requesting a non-default platform changes the resolved image manifest
- stored scan metadata includes the selected platform

## OTTER-AUDIT-07

Title:
Remove write side effects from read-only GET endpoints

Type:
Reliability

Priority:
P1

Why this matters:

GET handlers currently backfill missing index records on demand. That means reads can write to storage, which creates surprising behavior, hidden performance costs, and harder operational reasoning.

Evidence:

- [pkg/api/scan.go](pkg/api/scan.go)

Notes:

- `getOrCreateSBOMRecord()`
- `getOrCreateVulnerabilityRecord()`
- both are called from GET request paths

Proposed work:

- separate repair/backfill jobs from request serving
- treat GET handlers as read-only
- add an explicit reindex endpoint or background repair worker

Acceptance criteria:

- GET endpoints do not mutate indexes
- missing indexes are handled by reindex workflows, not user traffic

## OTTER-AUDIT-08

Title:
Replace the in-memory scan queue with persistent job storage, retries, and recovery

Type:
Reliability

Priority:
P1

Why this matters:

The current async job queue is process-local memory only. Restart the server and active or historical jobs disappear. That is not acceptable for shared or production deployments.

Evidence:

- [pkg/catalogscan/queue.go](pkg/catalogscan/queue.go)
- [pkg/catalogscan/scheduler.go](pkg/catalogscan/scheduler.go)

Notes:

- jobs live only in `map[string]*Job`
- no durable queue storage
- no retry policy
- no dead-letter handling

Acceptance criteria:

- queued and running jobs survive process restart
- failed jobs can retry with capped backoff
- queue depth and failed-job metrics are observable

## OTTER-AUDIT-09

Title:
Replace full-catalog scans and N+1 lookups with indexed queries and pagination

Type:
Performance

Priority:
P1

Why this matters:

Catalog and detail views currently read the full SBOM index and then perform per-image vulnerability lookups. That will degrade sharply as stored images grow.

Evidence:

- [pkg/api/catalog.go](pkg/api/catalog.go)

Notes:

- `buildCatalog()` calls `sbomIndex.List()` for everything
- then `buildCatalogEntry()` does per-record vulnerability lookup
- `buildImageOverview()` calls `sbomIndex.List()` again to find related tags

Proposed work:

- add repository-aware list queries with filters and pagination in the index layer
- add combined catalog projections to avoid N+1 lookups
- stop scanning all records to build a single image detail page

Acceptance criteria:

- catalog APIs support page and page size
- tags and overview queries avoid full repository scans
- large datasets do not require full in-memory listing

## OTTER-AUDIT-10

Title:
Cache and paginate remote repository tag discovery

Type:
Performance

Priority:
P1

Why this matters:

Remote tag discovery currently fetches and sorts the full remote tag list on request. Large registries or frequently viewed repositories will hit rate limits or respond slowly.

Evidence:

- [pkg/registry/service.go](pkg/registry/service.go)
- [pkg/api/catalog.go](pkg/api/catalog.go)

Notes:

- `ListRepositoryTags()` calls `remote.List()`
- results are sorted in memory
- no caching layer
- no registry-side pagination support in the service abstraction

Acceptance criteria:

- remote tags are cached with TTL
- the API can page through large tag sets
- repeated page loads do not re-fetch the full remote tag list

## OTTER-AUDIT-11

Title:
Verify signatures and attestations per record instead of applying one shared result

Type:
Bug

Priority:
P1

Why this matters:

Attestation verification currently calculates one verification outcome and applies it to every discovered signature or attestation record. That can overstate confidence or blur which record actually verified.

Evidence:

- [pkg/attestation/discover.go](pkg/attestation/discover.go)

Notes:

- `verify()` returns one `verificationOutcome`
- `applyVerification()` copies it to every record in a slice

Acceptance criteria:

- verification status is attached to the matching referrer or statement record
- mixed valid/invalid results are represented accurately

## OTTER-AUDIT-12

Title:
Extend `/healthz` into real readiness and dependency health checks

Type:
Operations

Priority:
P2

Why this matters:

The current health endpoint always returns `ok` plus the storage backend name. It does not report scanner availability, queue state, repository access, or degraded dependencies.

Evidence:

- [main.go](main.go)

Acceptance criteria:

- readiness reports storage/index connectivity
- scanner availability for Syft, Grype DB, Trivy, and Cosign is visible
- queue health and catalog worker state are exposed

## OTTER-AUDIT-13

Title:
Add retention and garbage collection for comparison artifacts and historical jobs

Type:
Operations

Priority:
P2

Why this matters:

Otter stores comparison artifacts and keeps job history in memory, but there is no lifecycle policy. Long-lived installs will accumulate data without clear retention rules.

Evidence:

- [pkg/api/scan.go](pkg/api/scan.go)
- [pkg/catalogscan/queue.go](pkg/catalogscan/queue.go)
- [pkg/compare/report.go](pkg/compare/report.go)

Acceptance criteria:

- comparison artifacts have configurable retention
- job history has persistent retention and cleanup semantics
- operators can disable or limit stored comparison history

## OTTER-AUDIT-14

Title:
Add policy-as-code and gating modes for enterprise adoption

Type:
Feature

Priority:
P1

Why this matters:

Companies will adopt Otter faster if it can move from passive reporting to enforceable policy. Today it reports evidence, but it does not support policy decisions such as failing builds on critical vulns or missing provenance.

Proposed scope:

- severity thresholds
- allowed scanner sources
- provenance requirements
- signature verification requirements
- VEX-aware exceptions
- JSON/YAML policy bundles

Acceptance criteria:

- policies can evaluate image detail data consistently
- scan results can return a pass/fail gate summary
- exports and APIs include policy evaluation status

## OTTER-AUDIT-15

Title:
Add OIDC/SSO, service tokens, and tenant-aware audit UI

Type:
Feature

Priority:
P1

Why this matters:

For company adoption, Otter needs a usable identity story for humans and automation.

Proposed scope:

- OIDC login for users
- service tokens for CI and registry automation
- tenant and org management UI
- audit history UI for sensitive actions

Acceptance criteria:

- users can log in through an identity provider
- service accounts can call the API with scoped tokens
- org-level activity is visible in the UI

## OTTER-AUDIT-16

Title:
Add metrics, tracing, and operator-facing scan and queue observability

Type:
Feature

Priority:
P2

Why this matters:

Otter currently lacks enough operational visibility for sustained production use. Companies need to know queue depth, average scan latency, scanner failure rate, registry error rate, and storage error rate.

Proposed scope:

- Prometheus metrics
- OpenTelemetry traces
- queue depth and job latency
- registry preflight latency
- scanner duration and failure counters
- export and compare request metrics

Acceptance criteria:

- operator dashboards can show scan throughput, error rates, and queue saturation
- tracing links scan requests to storage and scanner steps

## Additional adoption recommendations

These are not all immediate GitHub issues, but they would materially improve company adoption:

- provide a Helm chart and documented Kubernetes deployment model
- add webhook integrations for scan completion and policy failures
- add scheduled re-scan policies by repository instead of only static seeded image lists
- add signed Otter-produced attestations for exported reports
- add repository webhooks or CI-native integrations for automatic rescans on new tags
