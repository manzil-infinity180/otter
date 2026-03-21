#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
ISSUE_DIR="$ROOT_DIR/docs/issues/payloads"
LABEL_SCRIPT="$ROOT_DIR/docs/issues/bootstrap-labels.sh"

repo_args=()
dry_run=false

usage() {
  cat <<'EOF'
Usage: bash docs/issues/file-audit-issues.sh [--repo owner/name] [--dry-run]

Options:
  --repo     Explicit GitHub repository to target.
  --dry-run  Print the commands that would run without creating issues.
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

if [[ ! -x "$LABEL_SCRIPT" ]]; then
  chmod +x "$LABEL_SCRIPT"
fi

if [[ "$dry_run" == true ]]; then
  bash "$LABEL_SCRIPT" "${repo_args[@]}" --dry-run
else
  bash "$LABEL_SCRIPT" "${repo_args[@]}"
fi

for file in "$ISSUE_DIR"/*.md; do
  title="$(sed -n '1p' "$file" | sed 's/^# //')"
  labels_line="$(sed -n '2p' "$file" | sed 's/^labels: //')"
  body_file="$(mktemp)"
  sed '1,2d' "$file" > "$body_file"

  cmd=(gh issue create "${repo_args[@]}" --title "$title" --body-file "$body_file")

  OLDIFS="$IFS"
  IFS=',' read -r -a labels <<< "$labels_line"
  IFS="$OLDIFS"
  for label in "${labels[@]}"; do
    trimmed_label="$(echo "$label" | sed 's/^ *//; s/ *$//')"
    if [[ -n "$trimmed_label" ]]; then
      cmd+=(--label "$trimmed_label")
    fi
  done

  if [[ "$dry_run" == true ]]; then
    printf 'DRY RUN:'
    printf ' %q' "${cmd[@]}"
    printf '\n'
  else
    echo "Creating issue: $title"
    "${cmd[@]}"
  fi

  rm -f "$body_file"
done
