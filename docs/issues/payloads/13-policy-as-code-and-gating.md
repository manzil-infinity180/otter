# Add policy-as-code and gating modes for enterprise adoption
labels: feature,adoption,backend,frontend,priority/p1

## Summary

Companies will adopt Otter faster if it can move from passive reporting to enforceable policy. Today it reports evidence, but it does not support policy decisions such as failing builds on critical vulnerabilities or missing provenance.

## Proposed scope

- severity thresholds
- allowed scanner sources
- provenance requirements
- signature verification requirements
- VEX-aware exceptions
- JSON and YAML policy bundles

## Acceptance criteria

- policies can evaluate image detail data consistently
- scan results can return a pass or fail gate summary
- exports and APIs include policy evaluation status
