# Replace the in-memory scan queue with persistent job storage and recovery
labels: reliability,backend,priority/p1

## Problem

Async scan jobs exist only in process memory.

## Why this matters

Server restarts lose queued and running jobs, which is a serious operational limitation for real deployments.

## Evidence

- `pkg/catalogscan/queue.go`
- `pkg/catalogscan/scheduler.go`

## Proposed work

- persist jobs in storage
- add retry and recovery semantics
- surface queue metrics and failed job state

## Acceptance criteria

- jobs survive restart
- failed jobs are retryable
- queue state is observable
