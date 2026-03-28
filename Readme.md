# otter

**Otter correlates vulnerability findings from multiple scanners into a single trust decision for container images.**

*One scan. Every scanner. One decision.*

Otter runs Grype, Trivy, and OSV scanners in parallel against container images, then merges their findings into a unified compliance view combining vulnerabilities, SBOMs, attestations, and provenance. Where scanners disagree, that disagreement itself becomes a signal.

### What Otter does
- **Multi-scanner correlation** — Run multiple vulnerability scanners in parallel and merge their findings
- **Unified compliance view** — Vulnerabilities + SBOM + attestations + provenance + license compliance in one place
- **Scanner disagreement analysis** — Surface where scanners disagree as a trust signal
- **CycloneDX/SPDX SBOM generation** — Generate and index SBOMs via Syft
- **SARIF/CSV/JSON export** — Push findings to GitHub Code Scanning or any CI tool

### What Otter is NOT
- Not a replacement for Trivy or Grype — Otter uses them
- Not a general-purpose vulnerability database

For the project-level implementation summary and future-agent handoff, see
`AGENT_PROCESS.md`.



https://github.com/user-attachments/assets/60a8e2e2-3fb9-4687-979f-f980c1fbcac2

## Storage backends

Otter now runs locally by default.

- `OTTER_STORAGE=local`: stores scan artifacts in `./data/`
- `OTTER_STORAGE=postgres`: stores scan artifacts in PostgreSQL with migrations from `db/migrations/`
- `OTTER_STORAGE=s3`: keeps S3 available as an optional backend

Useful environment variables:

- `OTTER_DATA_DIR`
- `OTTER_DOCKER_CONFIG_PATH`
- `OTTER_REGISTRY_HEALTHCHECK_TIMEOUT`
- `OTTER_REGISTRY_PULL_INTERVAL`
- `OTTER_REGISTRY_PULLS_PER_SECOND`
- `OTTER_REGISTRY_TAG_CACHE_TTL`
- `OTTER_REGISTRY_ALLOWLIST`
- `OTTER_REGISTRY_DENYLIST`
- `OTTER_REGISTRY_ALLOW_PRIVATE_NETWORKS`
- `OTTER_REGISTRY_ALLOW_INSECURE`
- `OTTER_REGISTRY_SECRET_KEY`
- `OTTER_REGISTRY_SECRET_KEY_FILE`
- `OTTER_AUDIT_ENABLED`
- `OTTER_AUDIT_OUTPUTS`
- `OTTER_AUDIT_FILE`
- `OTTER_POLICY_BUNDLE`
- `OTTER_POLICY_MODE`
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
- `OTTER_CATALOG_SCANNER_STATE_DIR`
- `OTTER_CATALOG_SCANNER_RETRY_LIMIT`
- `OTTER_CATALOG_SCANNER_RETRY_BACKOFF`
- `OTTER_CATALOG_SCANNER_RETRY_BACKOFF_MAX`
- `OTTER_CATALOG_SCANNER_ORG_ID`
- `OTTER_CATALOG_SCANNER_IMAGES`
- `S3_BUCKET_NAME`
- `AWS_REGION`

## Local development

Run with local storage:

```bash
OTTER_STORAGE=local go run .
```

Configure a registry for authenticated pulls:

```bash
curl -X POST http://localhost:7789/api/v1/registries \
  -H 'Content-Type: application/json' \
  -d '{
    "registry": "ghcr.io",
    "auth_mode": "docker_config",
    "docker_config_path": "'"$HOME"'/.docker/config.json"
  }'
```

Otter uses configured registry settings to preflight image access before each scan and throttles registry API pulls per host. If no explicit registry configuration exists, public images still fall back to the default Docker keychain behavior.

Registry egress is policy-controlled by default:

- loopback, RFC1918/private, link-local, and cluster-internal registry targets are blocked unless `OTTER_REGISTRY_ALLOW_PRIVATE_NETWORKS=true`
- `insecure_use_http` and `insecure_skip_tls_verify` require `OTTER_REGISTRY_ALLOW_INSECURE=true`
- `OTTER_REGISTRY_ALLOWLIST` and `OTTER_REGISTRY_DENYLIST` accept comma-separated hostname patterns such as `ghcr.io,*.docker.io`
- `OTTER_REGISTRY_TAG_CACHE_TTL` controls how long remote repository tag listings stay cached before Otter re-queries the registry

When explicit registry credentials are configured, Otter stores registry metadata in `./data/_registry/registries.json` and writes the credential blob separately with local encryption. For managed deployments, provide `OTTER_REGISTRY_SECRET_KEY` or `OTTER_REGISTRY_SECRET_KEY_FILE` so the encryption key is controlled outside the data directory.

Otter now emits structured JSON-line audit records for scan queueing and completion, scan deletion, SBOM and VEX imports, and registry configuration changes. By default it appends them to `./data/_audit/events.jsonl`. Set `OTTER_AUDIT_OUTPUTS=stdout`, `stderr`, or a comma-separated mix such as `file,stdout` to forward them into your log pipeline; override the file path with `OTTER_AUDIT_FILE`, or disable audit output with `OTTER_AUDIT_ENABLED=false`.

Otter can also evaluate scans against a JSON or YAML policy bundle. Set `OTTER_POLICY_BUNDLE` to a bundle file and choose `OTTER_POLICY_MODE=report` or `enforce`. In `report` mode, scan and image APIs return an additive `policy` gate summary. In `enforce` mode, synchronous `POST /api/v1/scans` still stores the scan but returns `409 Conflict` when the gate fails.

Example bundle:

```yaml
name: default-gates
version: 1
mode: enforce
policies:
  - id: no-critical
    title: Block critical vulnerabilities
    max_severity: CRITICAL
  - id: trusted-scanners
    allowed_scanners: [grype, trivy]
  - id: signed-provenance
    min_verified_signatures: 1
    min_verified_provenance: 1
```

The background catalog worker is enabled by default and seeds the local catalog with common base images under the `catalog` org. Disable it with `OTTER_CATALOG_SCANNER_ENABLED=false` if you only want manual scans.

Build and test the React frontend:

```bash
cd frontend
npm install
npm test
npm run build
```

When `frontend/dist` exists, Otter serves the React UI at `/` with the image detail route at `/images/:org_id/:image_id`. Without the built bundle, Otter redirects `/` to the basic HTML browse mode at `/browse`.

Run with PostgreSQL via Docker Compose:

```bash
docker compose up --build
```

Run with local storage plus a local Trivy server:

```bash
trivy server --listen 0.0.0.0:4954
OTTER_STORAGE=local OTTER_TRIVY_ENABLED=true OTTER_TRIVY_SERVER_URL=http://localhost:4954 go run .
```

Successful scans now store:

- `sbom.json`
- `vulnerabilities.json` (combined Grype + Trivy report)
- `grype-vulnerabilities.json`
- `trivy-vulnerabilities.json`

Otter also indexes vulnerability findings for image-level APIs:

- `GET /api/v1/images/:id/vulnerabilities?org_id=default_org`
- optional `severity=critical|high|medium|low|negligible`
- optional `status=affected|not_affected|fixed|under_investigation`
- `GET /api/v1/images/:id/compliance?org_id=default_org`
- `GET /api/v1/images/:id/attestations?org_id=default_org`
- OpenVEX import via `POST /api/v1/images/:id/vex?org_id=default_org`

The vulnerability response includes:

- full finding records with CVSS, fix versions, scanner attribution, and advisory status
- summary counts by severity, scanner, and advisory status
- fix recommendations grouped by affected package
- trend snapshots preserved across re-scans
- additive `policy` gate results for the current image

The attestation response includes:

- signatures discovered through OCI referrers plus `cosign verify` status
- in-toto and DSSE attestations with parsed SLSA provenance summaries
- signer, issuer, timestamp, predicate type, and statement subjects when present
- additive `policy` gate results when a bundle requires signature or provenance checks

The compliance response includes:

- SLSA provenance level detection derived from stored provenance evidence
- OpenSSF Scorecard lookups for detected GitHub source repositories
- a standards checklist for SLSA, NIST SSDF, and CIS Container Image guidance
- best-effort evidence errors when registry attestation discovery or Scorecard lookups are unavailable

Scorecard integration is enabled by default and can be tuned with:

- `OTTER_SCORECARD_ENABLED`
- `OTTER_SCORECARD_BASE_URL`
- `OTTER_SCORECARD_TIMEOUT`
- `OTTER_SCORECARD_SHOW_DETAILS`

## Automated catalog scanning

Otter now includes a local-first catalog scan pipeline backed by an in-process worker queue.

- The worker accepts async scan requests via `POST /api/v1/scans` with `"async": true`.
- Job status is available at `GET /api/v1/scan-jobs/:id`.
- Async jobs are persisted under `OTTER_CATALOG_SCANNER_STATE_DIR` and recover queued or in-flight work after process restarts.
- Failed jobs retry with capped exponential backoff before settling in a terminal `failed` state, and the job status response now includes queue-depth counters plus retry metadata.
- A scheduler enqueues a default image set on boot and then repeats on `OTTER_CATALOG_SCANNER_INTERVAL`.
- Re-scans reuse stable `org_id` and `image_id` values, so vulnerability trend snapshots continue to build over time.

Default seeded image refs:

- `alpine:latest`
- `alpine:3.19`
- `debian:latest`
- `debian:12-slim`
- `ubuntu:latest`
- `ubuntu:24.04`
- `nginx:latest`
- `nginx:1.27`
- `python:latest`
- `python:3.12`
- `golang:latest`
- `golang:1.24`
- `cgr.dev/chainguard/static:latest`

Override the catalog list with a comma-separated value:

```bash
OTTER_CATALOG_SCANNER_IMAGES="alpine:latest,nginx:latest,cgr.dev/chainguard/static:latest" go run .
```

Export formats are available from the image detail UI and the REST API:

- `GET /api/v1/images/:id/export?org_id=...&format=cyclonedx|spdx|json|csv|sarif`
- `GET /api/v1/comparisons/:id/export`

Image exports also include `X-Otter-Policy-Mode`, `X-Otter-Policy-Status`, and `X-Otter-Policy-Allowed` headers so downstream automation can read the gate result without changing the exported filename or primary payload format.



1. Task: Setting up trivy server (dockerfile/docker compose) and scan the image (look also for the case)
2. Task: Setting up the postresql and how to store the sbom or other things (read it and store)
3. Task: github action to build everything on main branch pr merged
4. Task: Save different things like sbom, vex, provenances, cve (with the fixes details)
5. Task: add the open source project scan (+ task 4)
6. Task: add integration for different oci registry like ghrc, docker private (i mean for pvt)
7. Task: Minimal UI + export option (different view or render options)
---
8. Look for the attestation if possible or for the compilances ?
