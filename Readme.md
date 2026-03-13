# otter
An open-source SBOM & vulnerability analyzer.
It scans container images generates CycloneDX SBOMs, lists vulnerabilities



https://github.com/user-attachments/assets/60a8e2e2-3fb9-4687-979f-f980c1fbcac2

## Storage backends

Otter now runs locally by default.

- `OTTER_STORAGE=local`: stores scan artifacts in `./data/`
- `OTTER_STORAGE=postgres`: stores scan artifacts in PostgreSQL with migrations from `db/migrations/`
- `OTTER_STORAGE=s3`: keeps S3 available as an optional backend

Useful environment variables:

- `OTTER_DATA_DIR`
- `OTTER_POSTGRES_DSN`
- `OTTER_POSTGRES_MIGRATIONS`
- `S3_BUCKET_NAME`
- `AWS_REGION`

## Local development

Run with local storage:

```bash
OTTER_STORAGE=local go run .
```

Run with PostgreSQL via Docker Compose:

```bash
docker compose up --build
```




1. Task: Setting up trivy server (dockerfile/docker compose) and scan the image (look also for the case)
2. Task: Setting up the postresql and how to store the sbom or other things (read it and store)
3. Task: github action to build everything on main branch pr merged
4. Task: Save different things like sbom, vex, provenances, cve (with the fixes details)
5. Task: add the open source project scan (+ task 4)
6. Task: add integration for different oci registry like ghrc, docker private (i mean for pvt)
7. Task: Minimal UI + export option (different view or render options)
---
8. Look for the attestation if possible or for the compilances ?
