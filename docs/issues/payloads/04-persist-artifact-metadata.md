# Persist artifact metadata across local, PostgreSQL, and S3 backends
labels: bug,backend,priority/p1

## Problem

Artifact metadata is written on `Put()` but not consistently returned by `Get()` and `List()` across storage backends.

## Why this matters

Otter relies on artifact metadata for scanner-unavailable messages, fallback image reference resolution, and richer UI behavior.

## Evidence

- `pkg/storage/local.go`
- `pkg/storage/postgres.go`
- `pkg/storage/s3.go`
- `pkg/api/scan.go`

## Proposed work

- persist metadata in every backend
- return metadata from `Get()` and `List()`
- add parity tests across local, postgres, and s3 paths

## Acceptance criteria

- metadata round-trips identically across all backends
- scanner warning UX survives restart and backend changes
