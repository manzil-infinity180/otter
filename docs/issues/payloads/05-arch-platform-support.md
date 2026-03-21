# Honor the arch or platform scan request end to end
labels: bug,api,backend,priority/p1

## Problem

The scan request model exposes an `arch` field, but the execution path does not use it.

## Why this matters

Multi-arch image scans can produce misleading results if the selected platform is ignored.

## Evidence

- `pkg/api/scan.go`
- `docs/api.md`

## Proposed work

- wire `arch` or full platform selection into image resolution
- expose selected platform in stored metadata and responses
- update the UI and docs

## Acceptance criteria

- selecting `amd64` or `arm64` changes the resolved manifest where applicable
- platform is visible in scan results and stored artifacts
