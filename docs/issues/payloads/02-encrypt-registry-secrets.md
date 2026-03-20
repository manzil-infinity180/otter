# Stop storing registry credentials in plaintext on disk
labels: security,backend,priority/p0

## Problem

Explicit registry usernames, passwords, and tokens are stored directly in the local registry repository file.

## Why this matters

This is unacceptable for enterprise adoption and creates immediate credential-at-rest risk.

## Evidence

- `pkg/registry/types.go`
- `pkg/registry/local.go`

## Proposed work

- separate safe registry metadata from secret material
- encrypt secrets at rest or delegate to a secret backend
- support OS keychain, Vault, or cloud secret stores

## Acceptance criteria

- no raw passwords or tokens are written to local JSON state
- registry summaries remain safe to return over the API
