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
