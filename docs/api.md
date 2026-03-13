# Otter API

## Scan image

`POST /api/v1/scans`

Request body:

```json
{
  "arch": "amd64",
  "image_name": "alpine:latest",
  "registry": "https://index.docker.io/v1",
  "org_id": "default_org",
  "image_id": "alpine-latest"
}
```

Behavior:

- Generates a CycloneDX SBOM and SPDX SBOM.
- Runs configured vulnerability scanners.
- Stores:
  - `sbom.json` as the legacy CycloneDX alias
  - `sbom-cyclonedx.json`
  - `sbom-spdx.json`
  - `vulnerabilities.json`
  - per-scanner vulnerability reports
- Indexes packages, license summary, and dependency tree for image-level SBOM APIs.

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
- stores the comparison report as `otterxf/comparisons/<comparison-id>/comparison.json`

Response includes:

- deterministic `comparison_id`
- summary message in the form `Image B has X fewer vulns and Y fewer packages`
- package, vulnerability, layer, and SBOM diffs
- stored comparison artifact metadata

If the same image reference exists in multiple orgs, Otter returns `409 Conflict` until `org1` or `org2` is provided.

## Get a stored comparison

`GET /api/v1/comparisons/:id`

Returns the persisted comparison report for a previously generated `comparison_id`.

## Get image SBOM

`GET /api/v1/images/:id/sbom?org_id=default_org&format=cyclonedx|spdx`

Response includes:

- raw SBOM document
- normalized package list
- license summary
- dependency roots
- dependency tree

If `format` is omitted, Otter returns the CycloneDX document.

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
