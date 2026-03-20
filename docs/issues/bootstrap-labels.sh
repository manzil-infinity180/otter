#!/usr/bin/env bash
set -euo pipefail

repo_args=()
dry_run=false

usage() {
  cat <<'EOF'
Usage: bash docs/issues/bootstrap-labels.sh [--repo owner/name] [--dry-run]

Options:
  --repo     Explicit GitHub repository to target.
  --dry-run  Print the commands that would run without changing labels.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      shift
      if [[ $# -eq 0 ]]; then
        echo "--repo requires a value" >&2
        exit 1
      fi
      repo_args=(--repo "$1")
      ;;
    --dry-run)
      dry_run=true
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
  shift
done

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI is required" >&2
  exit 1
fi

gh auth status >/dev/null

ensure_label() {
  local name="$1"
  local color="$2"
  local description="$3"

  cmd=(gh label create "${repo_args[@]}" "$name" --color "$color" --description "$description" --force)

  if [[ "$dry_run" == true ]]; then
    printf 'DRY RUN:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
  else
    "${cmd[@]}"
  fi
}

ensure_label "security" "B60205" "Security boundary, secret handling, or trust issues"
ensure_label "bug" "D73A4A" "Behavior that is incorrect or broken"
ensure_label "reliability" "FBCA04" "Durability, recovery, or operational correctness work"
ensure_label "performance" "0E8A16" "Latency, scale, or resource efficiency work"
ensure_label "feature" "1D76DB" "New product capability"
ensure_label "adoption" "7C3AED" "Capabilities needed for company rollout and adoption"
ensure_label "api" "0891B2" "API contract or handler work"
ensure_label "frontend" "DB2777" "React or UI work"
ensure_label "backend" "2563EB" "Go service or data layer work"
ensure_label "operations" "4B5563" "Deployment, health, or lifecycle operations work"
ensure_label "priority/p0" "991B1B" "Highest urgency"
ensure_label "priority/p1" "C2410C" "High urgency"
ensure_label "priority/p2" "CA8A04" "Medium urgency"
