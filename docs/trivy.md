# Trivy integration

Otter now supports Trivy server mode alongside the existing Syft and Grype flow.

## Compose workflow

```bash
docker compose up --build
```

This starts:

- `trivy` on `http://localhost:4954`
- `postgres` on `localhost:5432`
- `otter` on `http://localhost:7789`

The Otter container includes the `trivy` CLI client and calls the sidecar server with:

```bash
trivy image --server http://trivy:4954 --format json --quiet --scanners vuln <image>
```

## Local workflow

Start a Trivy server:

```bash
trivy server --listen 0.0.0.0:4954
```

Run Otter against it:

```bash
OTTER_STORAGE=local \
OTTER_TRIVY_ENABLED=true \
OTTER_TRIVY_SERVER_URL=http://localhost:4954 \
go run .
```

## Scan response artifacts

`POST /api/v1/scans` now persists four artifacts per image:

- `sbom.json`
- `vulnerabilities.json` for the merged report
- `grype-vulnerabilities.json`
- `trivy-vulnerabilities.json`

The merged `vulnerabilities.json` includes:

- deduplicated vulnerabilities across Grype and Trivy
- `scanners` attribution per finding
- summary counts by severity and by scanner
