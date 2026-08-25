#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly PIN="40ecbd035e5541bf099917c5033cceb8959c4737"
readonly PATCH_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly PYTHON="${PYTHON:-python3}"

usage() {
  echo "usage: $0 /path/to/prowler [--pytest]" >&2
  exit 2
}

[[ $# -eq 1 || $# -eq 2 ]] || usage
[[ $# -eq 1 || "$2" == "--pytest" ]] || usage

readonly SOURCE_REPO="$(realpath -- "$1")"
git -C "$SOURCE_REPO" rev-parse --git-dir >/dev/null
git -C "$SOURCE_REPO" cat-file -e "${PIN}^{commit}"

temp_parent="$(mktemp -d "${TMPDIR:-/var/tmp}/ai-security-scanner-prowler-patches.XXXXXX")"
temp_tree="${temp_parent}/tree"

cleanup() {
  if [[ -e "$temp_tree" ]]; then
    git -C "$SOURCE_REPO" worktree remove --force "$temp_tree" >/dev/null 2>&1 || true
  fi
  if [[ -d "$temp_parent" ]]; then
    rmdir "$temp_parent" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

git -C "$SOURCE_REPO" worktree add --quiet --detach "$temp_tree" "$PIN"
[[ "$(git -C "$temp_tree" rev-parse HEAD)" == "$PIN" ]]

while IFS= read -r patch_name; do
  [[ -n "$patch_name" ]] || continue
  [[ "$patch_name" =~ ^[0-9]{4}-[a-z0-9-]+\.patch$ ]] || {
    echo "invalid patch name in series: $patch_name" >&2
    exit 1
  }
  patch_path="${PATCH_DIR}/${patch_name}"
  [[ -f "$patch_path" ]] || {
    echo "missing patch: $patch_path" >&2
    exit 1
  }
  git -C "$temp_tree" apply --check "$patch_path"
  git -C "$temp_tree" apply "$patch_path"
done <"${PATCH_DIR}/series"

readonly EXPECTED_FILES=$'prowler/providers/azure/azure_provider.py\nprowler/providers/azure/lib/arguments/arguments.py\nprowler/providers/common/provider.py\nprowler/providers/gcp/gcp_provider.py\ntests/providers/azure/azure_access_token_auth_test.py\ntests/providers/gcp/gcp_exact_projects_test.py'
actual_files="$(git -C "$temp_tree" status --short | sed 's/^...//' | sort)"
if [[ "$actual_files" != "$EXPECTED_FILES" ]]; then
  echo "patched file set differs from the reviewed allowlist" >&2
  diff <(printf '%s\n' "$EXPECTED_FILES") <(printf '%s\n' "$actual_files") >&2 || true
  exit 1
fi

git -C "$temp_tree" diff --check
"$PYTHON" -m compileall -q \
  "$temp_tree/prowler/providers/azure/azure_provider.py" \
  "$temp_tree/prowler/providers/azure/lib/arguments/arguments.py" \
  "$temp_tree/prowler/providers/common/provider.py" \
  "$temp_tree/prowler/providers/gcp/gcp_provider.py" \
  "$temp_tree/tests/providers/azure/azure_access_token_auth_test.py" \
  "$temp_tree/tests/providers/gcp/gcp_exact_projects_test.py"

if [[ $# -eq 2 ]]; then
  (
    cd "$temp_tree"
    "$PYTHON" -m pytest -q \
      tests/providers/azure/azure_access_token_auth_test.py \
      tests/providers/azure/azure_provider_test.py \
      tests/providers/gcp/gcp_exact_projects_test.py \
      tests/providers/gcp/gcp_provider_test.py \
      tests/lib/cli/parser_test.py \
      -p no:randomly
  )
fi

echo "Prowler patches verified at ${PIN}"

