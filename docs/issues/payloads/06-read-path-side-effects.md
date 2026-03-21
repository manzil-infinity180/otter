# Remove write side effects from read-only GET endpoints
labels: reliability,backend,priority/p1

## Problem

Some GET handlers backfill or create index records on demand.

## Why this matters

Reads should not mutate state. This makes caching, scaling, and operational debugging harder and hides expensive work in normal page loads.

## Evidence

- `pkg/api/scan.go`

## Proposed work

- remove backfill writes from GET handlers
- introduce explicit reindex or repair jobs
- keep read paths read-only

## Acceptance criteria

- GET endpoints never write indexes
- missing indexes are handled by a separate reindex path
