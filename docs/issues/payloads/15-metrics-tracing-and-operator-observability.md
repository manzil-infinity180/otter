# Add metrics, tracing, and operator-facing scan and queue observability
labels: feature,operations,backend,priority/p2

## Summary

Otter currently lacks enough operational visibility for sustained production use. Companies need to know queue depth, average scan latency, scanner failure rate, registry error rate, and storage error rate.

## Proposed scope

- Prometheus metrics
- OpenTelemetry traces
- queue depth and job latency
- registry preflight latency
- scanner duration and failure counters
- export and compare request metrics

## Acceptance criteria

- operator dashboards can show scan throughput, error rates, and queue saturation
- tracing links scan requests to storage and scanner steps
