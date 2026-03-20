# Add audit events for scans, deletes, imports, and registry configuration changes
labels: security,feature,backend,priority/p1

## Summary

Even after authentication is added, Otter still needs traceability for who scanned what, who imported advisory data, and who changed registry access settings.

## Evidence

- [pkg/api/scan.go](pkg/api/scan.go)
- [pkg/api/registry.go](pkg/api/registry.go)

## Proposed work

- add structured audit events for scan enqueue, scan completion, scan delete, SBOM import, VEX import, and registry create or update
- persist a minimal audit log or emit to external sinks
- surface actor identity, org, target image, and timestamp

## Acceptance criteria

- all sensitive actions emit structured audit records
- audit output can be exported or forwarded
