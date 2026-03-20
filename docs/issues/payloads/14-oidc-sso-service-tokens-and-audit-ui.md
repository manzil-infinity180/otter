# Add OIDC/SSO, service tokens, and tenant-aware audit UI
labels: feature,adoption,security,frontend,backend,priority/p1

## Summary

For company adoption, Otter needs a usable identity story for humans and automation.

## Proposed scope

- OIDC login for users
- service tokens for CI and registry automation
- tenant and org management UI
- audit history UI for sensitive actions

## Acceptance criteria

- users can log in through an identity provider
- service accounts can call the API with scoped tokens
- org-level activity is visible in the UI
