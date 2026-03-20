# Verify signatures and attestations per record instead of applying one shared result
labels: bug,security,backend,priority/p1

## Summary

Attestation verification currently calculates one verification outcome and applies it to every discovered signature or attestation record. That can overstate confidence or blur which record actually verified.

## Evidence

- [pkg/attestation/discover.go](pkg/attestation/discover.go)

## Notes

- `verify()` returns one `verificationOutcome`
- `applyVerification()` copies it to every record in a slice

## Proposed work

- verify each signature and attestation record independently
- attach verification results to the matching referrer or statement
- preserve mixed valid and invalid outcomes in the API model and UI

## Acceptance criteria

- verification status is attached to the matching referrer or statement record
- mixed valid and invalid results are represented accurately
