# Replace full catalog scans and N+1 lookups with indexed queries and pagination
labels: performance,backend,api,priority/p1

## Problem

Catalog and image detail endpoints currently load broad record sets and then do follow-up lookups per item.

## Why this matters

This will degrade quickly as stored images grow and is a real adoption bottleneck for company-sized catalogs.

## Evidence

- `pkg/api/catalog.go`

## Proposed work

- add paginated catalog APIs
- add repository-aware index queries for tags and related images
- remove full-repository scans from overview paths

## Acceptance criteria

- catalog APIs support paging
- related-tag lookup avoids listing the full SBOM index
- large datasets do not require full in-memory assembly
