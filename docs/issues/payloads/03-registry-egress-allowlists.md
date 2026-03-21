# Add outbound registry allowlists and safer egress defaults
labels: security,backend,priority/p0

## Problem

Otter accepts user-controlled image references and registry configuration, then performs remote registry access without an allowlist model.

## Why this matters

In shared environments this becomes an egress and SSRF-style risk surface, especially with internal hostnames and unsafe HTTP/TLS overrides.

## Evidence

- `pkg/api/validation.go`
- `pkg/registry/service.go`

## Proposed work

- allowlist registry hostnames
- deny RFC1918, loopback, and internal targets by default
- require explicit opt-in for HTTP and TLS skip-verify
- document operator egress policy settings

## Acceptance criteria

- unsafe internal targets are blocked by default
- policy is configurable and logged
