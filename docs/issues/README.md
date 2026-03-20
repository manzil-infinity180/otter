# GitHub Issue Filing Bundle

These files are generated from the repo audit so the issues can be filed quickly into GitHub.

## What is here

- `payloads/*.md`: one issue draft per audit finding
- `bootstrap-labels.sh`: creates or updates the labels used by the audit issues
- `file-audit-issues.sh`: bootstraps labels, then creates the issues

## Recommended usage

Create labels first:

```bash
bash docs/issues/bootstrap-labels.sh
```

Create the full audit issue set:

```bash
bash docs/issues/file-audit-issues.sh
```

Target a specific repository:

```bash
bash docs/issues/file-audit-issues.sh --repo manzil-infinity180/otter
```

Preview without making changes:

```bash
bash docs/issues/file-audit-issues.sh --repo manzil-infinity180/otter --dry-run
```
