# Otter API

## Configure registry access

`POST /api/v1/registries`

Request body examples:

Explicit credentials:

```json
{
  "registry": "ghcr.io",
  "auth_mode": "explicit",
  "token": "ghp_example",
  "insecure_skip_tls_verify": false,
  "insecure_use_http": false
}
```

Docker config:

```json
{
  "registry": "index.docker.io",
  "auth_mode": "docker_config",
  "docker_config_path": "/Users/example/.docker/config.json"
}
```

Behavior:

- validates the registry hostname
- checks registry API reachability before saving configuration
- supports `docker_config` auth from `config.json` and `explicit` username/password or token auth
- persists per-registry settings for later scans without returning stored secrets

## List configured registries

`GET /api/v1/registries`

Returns saved registry configuration summaries without secret material.

## Scan image

`POST /api/v1/scans`

Request body:

```json
{
  "arch": "amd64",
  "platform": "linux/amd64",
  "image_name": "alpine:latest",
  "registry": "index.docker.io",
  "org_id": "default_org",
  "image_id": "alpine-latest",
  "async": false
}
```

Behavior:

- Generates a CycloneDX SBOM and SPDX SBOM.
- Runs configured vulnerability scanners.
- Performs a registry preflight check with configured auth before Syft pulls the image.
- Honors `platform` during multi-arch image resolution. `arch` remains supported as a legacy alias and normalizes to `linux/<arch>`.
- Applies per-registry pull throttling before registry API access.
- Stores:
  - `sbom.json` as the legacy CycloneDX alias
  - `sbom-cyclonedx.json`
  - `sbom-spdx.json`
  - `vulnerabilities.json`
  - per-scanner vulnerability reports
- Indexes packages, license summary, and dependency tree for image-level SBOM APIs.

Async mode:

- set `"async": true` or `?async=true` to hand the scan to the background worker
- returns `202 Accepted` with a job record and `status_url`
- the worker queue is also used by the built-in catalog scheduler

## Get async scan job status

`GET /api/v1/scan-jobs/:id`

Returns the current job state for an async scan request, including:

- pending, running, succeeded, or failed status
- attempt count, max attempts, last error, and the next retry timestamp when a retry is scheduled
- original scan request payload with the normalized `platform` when provided
- completion timestamps
- vulnerability summary, scanner list, and resolved platform when the job succeeds
- queue counters for pending, running, succeeded, failed, current queue depth, and active targets

## List scan artifacts

`GET /api/v1/scans/:org_id/:image_id`

Returns all stored artifacts for the image scan.

## Download a scan artifact

`GET /api/v1/scans/:org_id/:image_id/files/:filename`

Downloads a stored artifact by filename.

## Delete scan artifacts

`DELETE /api/v1/scans/:org_id/:image_id`

Deletes stored scan artifacts and the structured SBOM index for the image.

## Compare two scanned images

`GET /api/v1/compare?image1=alpine:3.19&image2=alpine:3.20`

Optional disambiguation:

- `org1=demo-org`
- `org2=demo-org`

Behavior:

- resolves each image by stored `image_name`
- compares packages as added, removed, and changed components
- compares vulnerabilities as new, fixed, and unchanged findings
- derives layer changes from stored CycloneDX SBOM metadata (`syft:location:*:layerID`)
- does not write storage; it returns a read-only diff preview

Response includes:

- deterministic `comparison_id`
- summary message in the form `Image B has X fewer vulns and Y fewer packages`
- package, vulnerability, layer, and SBOM diffs

If the same image reference exists in multiple orgs, Otter returns `409 Conflict` until `org1` or `org2` is provided.

## Persist a comparison report

`POST /api/v1/comparisons`

Request body:

```json
{
  "image1": "alpine:3.19",
  "image2": "alpine:3.20",
  "org1": "demo-org",
  "org2": "demo-org"
}
```

Behavior:

- builds the same comparison payload as `GET /api/v1/compare`
- stores the report as `otterxf/comparisons/<comparison-id>/comparison.json`
- returns the persisted artifact metadata for later retrieval/export

## Get a stored comparison

`GET /api/v1/comparisons/:id`

Returns the persisted comparison report for a previously generated `comparison_id`.

## Export a stored comparison

`GET /api/v1/comparisons/:id/export`

Downloads the persisted comparison report as `comparison-<comparison-id>.json`.

## Browse the image catalog

`GET /api/v1/catalog?query=alpine&severity=critical&sort=recent`

Optional filters:

- `org_id=demo-org`
- `query=...` or `q=...`
- `severity=critical|high|medium|low|negligible|unknown`
- `sort=recent|critical|packages|name`

Response includes:

- indexed image list with parsed registry, repository, tag, and digest fields
- package counts, license summary, and vulnerability summary per image
- scanner attribution and last updated time
- the seeded catalog scans appear under `org_id=catalog` by default

Otter also exposes HTML browse fallbacks at:

- `GET /browse`
- `GET /browse/images/:org_id/:id`

These pages are intended for basic no-JavaScript viewing when the React bundle is not built.

## Get image overview

`GET /api/v1/images/:id/overview?org_id=default_org`

Response includes:

- parsed image metadata for the directory/detail UI
- stored platform metadata for the selected image and related tags
- package and vulnerability summary cards
- available scan artifacts for download
- related tags already stored for the same repository within the org

## Get image tags

`GET /api/v1/images/:id/tags?org_id=default_org&page=1&page_size=25&query=3.19`

Response includes:

- the current tag plus other stored tags for the same repository within the org
- best-effort remote registry tags for the same repository
- pagination metadata: `count`, `total`, `page`, `page_size`, and `has_more`
- per-tag scan metadata so clients can distinguish stored scans from remote-only tags
- `remote_cached` and `remote_cache_expires_at` for cache visibility
- `remote_tag_error` when remote tag discovery fails but stored tags are still returned

## Get image compliance

`GET /api/v1/images/:id/compliance?org_id=default_org`

Behavior:

- resolves the stored image reference from indexed scan data
- performs best-effort attestation discovery for provenance and verification signals
- derives a SLSA provenance level from builder, build type, materials, invocation, and verification evidence
- looks up OpenSSF Scorecard data when a GitHub source repository can be inferred from provenance materials or GHCR naming
- summarizes a standards checklist for SLSA, NIST SSDF, and CIS Container Image guidance

Response includes:

- `source_repository` metadata with the inference source and confidence
- `slsa` evidence, missing signals, and detected level
- `scorecard` availability, score, risk level, and lowest-scoring checks
- `standards` checklist entries with `pass`, `partial`, `fail`, or `unavailable` states
- `summary` totals plus `evidence_errors` for upstream lookup failures that were downgraded instead of failing the request

## Export image data

`GET /api/v1/images/:id/export?org_id=default_org&format=cyclonedx|spdx|json|csv|sarif`

Formats:

- `cyclonedx`: raw CycloneDX SBOM JSON
- `spdx`: raw SPDX SBOM JSON
- `json`: structured vulnerability report JSON
- `csv`: flat vulnerability export for spreadsheets
- `sarif`: SARIF 2.1.0 vulnerability report with stable fingerprints for code-scanning ingestion

Otter returns an attachment download with a deterministic filename based on `org_id`, `image_id`, and the selected format.

## Get image SBOM

`GET /api/v1/images/:id/sbom?org_id=default_org&format=cyclonedx|spdx`

Response includes:

- raw SBOM document
- normalized package list
- license summary
- dependency roots
- dependency tree

If `format` is omitted, Otter returns the CycloneDX document.

## Repair missing image indexes

`POST /api/v1/images/:id/indexes/repair?org_id=default_org`

Behavior:

- rebuilds the SBOM and vulnerability indexes from already-stored scan artifacts
- leaves existing index rows untouched when they are already present
- returns `404` if Otter cannot find any stored artifacts to rebuild from

## Import image SBOM

`POST /api/v1/images/:id/sbom?org_id=default_org`

Upload a multipart form with:

- `file`: required JSON SBOM file
- `format`: optional, `cyclonedx` or `spdx`
- `image_name`: optional display name stored in the SBOM index

Otter validates the uploaded JSON, detects format when omitted, stores the original document, and rebuilds the structured SBOM index.

## Get image vulnerabilities

`GET /api/v1/images/:id/vulnerabilities?org_id=default_org`

Optional filters:

- `severity=critical|high|medium|low|negligible`
- `status=affected|not_affected|fixed|under_investigation`

Response includes:

- structured vulnerabilities with CVE ID, CVSS, description, fix version, affected package, and scanner attribution
- advisory status derived from imported OpenVEX documents
- summary counts by severity, scanner, and status
- fix recommendations grouped by package
- trend snapshots across scans

If filters are applied, Otter also includes `summary_all` for the unfiltered record.

## Get image attestations

`GET /api/v1/images/:id/attestations?org_id=default_org`

Behavior:

- resolves the stored `image_name` from indexed scan data
- queries OCI referrers for attached signatures and attestations
- parses DSSE envelopes, in-toto statements, and SLSA provenance summaries
- verifies discovered signatures with `cosign verify`
- verifies discovered attestations with `cosign verify-attestation`

Response includes:

- canonical image digest reference used for registry discovery
- signature records with signer, issuer, timestamp, and verification status
- attestation records with predicate type, DSSE payload type, statement subjects, and provenance summary
- summary counts by verification status plus a provenance total

Verification defaults to permissive keyless identity regexes (`.*`). For stricter validation or key-based verification, configure:

- `OTTER_COSIGN_PUBLIC_KEY`
- `OTTER_COSIGN_IDENTITY_REGEXP`
- `OTTER_COSIGN_OIDC_ISSUER_REGEXP`

## Import OpenVEX

`POST /api/v1/images/:id/vex?org_id=default_org`

Alias:

- `POST /api/v1/images/:id/vulnerabilities/vex?org_id=default_org`

Upload a multipart form with:

- `file`: required OpenVEX JSON document
- `image_name`: optional display name when importing VEX before the first scan

Otter validates each OpenVEX statement, stores the source document as a scan artifact, updates vulnerability status to `affected`, `not_affected`, `fixed`, or `under_investigation`, and persists the advisory metadata for later reads.
