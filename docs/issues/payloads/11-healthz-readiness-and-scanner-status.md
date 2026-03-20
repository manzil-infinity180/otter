# Extend /healthz into real readiness and dependency health checks
labels: feature,operations,backend,priority/p2

## Summary

The current health endpoint always returns `ok` plus the storage backend name. It does not report scanner availability, queue state, repository access, or degraded dependencies.

## Evidence

- [main.go](main.go)

## Proposed work

- add readiness checks for storage and index connectivity
- report scanner availability for Syft, Grype, Trivy, and Cosign
- surface queue health and catalog worker state
- distinguish healthy, degraded, and unavailable dependency states

## Acceptance criteria

- readiness reports storage and index connectivity
- scanner availability is visible in the response
- queue health and catalog worker state are exposed
