# Add retention and garbage collection for comparison artifacts and historical jobs
labels: operations,reliability,backend,priority/p2

## Summary

Otter stores comparison artifacts and keeps job history, but there is no lifecycle policy. Long-lived installs will accumulate data without clear retention rules.

## Evidence

- [pkg/api/scan.go](pkg/api/scan.go)
- [pkg/catalogscan/queue.go](pkg/catalogscan/queue.go)
- [pkg/compare/report.go](pkg/compare/report.go)

## Proposed work

- add configurable retention for comparison artifacts
- define cleanup semantics for persisted job history
- allow operators to disable or limit stored comparison history
- document retention settings and cleanup behavior

## Acceptance criteria

- comparison artifacts have configurable retention
- job history has persistent retention and cleanup semantics
- operators can disable or limit stored comparison history
