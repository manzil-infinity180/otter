# Cache and paginate remote repository tag discovery
labels: performance,backend,api,priority/p1

## Summary

Remote tag discovery currently fetches and sorts the full remote tag list on request. Large registries or frequently viewed repositories will hit rate limits or respond slowly.

## Evidence

- [pkg/registry/service.go](pkg/registry/service.go)
- [pkg/api/catalog.go](pkg/api/catalog.go)

## Notes

- `ListRepositoryTags()` calls `remote.List()`
- results are sorted in memory
- there is no caching layer
- there is no paging support in the service abstraction

## Proposed work

- add TTL-based remote tag caching
- support page and page size on the tag listing API
- avoid re-fetching the full remote tag list on repeated page loads
- expose remote tag source status separately from stored scan tags

## Acceptance criteria

- remote tags are cached with TTL
- the API can page through large tag sets
- repeated page loads do not re-fetch the full remote tag list
