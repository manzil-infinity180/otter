# Add authentication, authorization, and org isolation across the API
labels: security,backend,api,priority/p0

## Problem

Otter currently exposes scan creation, scan deletion, SBOM import, VEX import, registry configuration, and read APIs without authentication or authorization.

## Why this matters

This is the main blocker for any shared or company deployment. Right now the API is effectively single-user demo mode even though the resource model already uses `org_id`.

## Evidence

- `pkg/routes/scan.go`
- `pkg/api/scan.go`
- `pkg/api/registry.go`
- `pkg/api/keys.go`

## Proposed work

- add auth middleware for API routes
- support OIDC or bearer tokens
- enforce org ownership checks
- stop silently defaulting empty write-path IDs to shared fallback values

## Acceptance criteria

- mutating endpoints require authentication
- cross-org access is blocked
- `401` and `403` behavior is explicit and tested
