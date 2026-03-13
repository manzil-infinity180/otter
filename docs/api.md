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

## Import OpenVEX

`POST /api/v1/images/:id/vex?org_id=default_org`

Alias:

- `POST /api/v1/images/:id/vulnerabilities/vex?org_id=default_org`

Upload a multipart form with:

- `file`: required OpenVEX JSON document
- `image_name`: optional display name when importing VEX before the first scan

Otter validates each OpenVEX statement, stores the source document as a scan artifact, updates vulnerability status to `affected`, `not_affected`, `fixed`, or `under_investigation`, and persists the advisory metadata for later reads.
