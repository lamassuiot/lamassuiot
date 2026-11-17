#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# The source path is resolved from the test script location at runtime.
# shellcheck disable=SC1091
source "$script_dir/codecov-watchdog.sh"

assert_state() {
  local expected="$1"
  local checks="$2"
  local statuses="$3"
  local actual

  actual=$(codecov_state "$checks" "$statuses")
  if [[ "$actual" != "$expected" ]]; then
    echo "Expected state '$expected', got '$actual'" >&2
    return 1
  fi
}

pending_checks='{"check_runs":[{"name":"Codecov result","app":{"slug":"codecov"},"status":"in_progress","conclusion":null},{"name":"Codecov result watchdog","app":{"slug":"github-actions"},"status":"in_progress","conclusion":null}]}'
completed_checks='{"check_runs":[{"name":"codecov/project","app":{"slug":"codecov"},"status":"completed","conclusion":"success"},{"name":"Codecov result watchdog","app":{"slug":"github-actions"},"status":"in_progress","conclusion":null}]}'
empty_statuses='[]'
completed_statuses='[{"context":"codecov/project","state":"success"}]'

assert_state pending "$pending_checks" "$empty_statuses"
assert_state success "$completed_checks" "$empty_statuses"
assert_state success '{"check_runs":[]}' "$completed_statuses"

checks_url='https://example.test/check-runs?per_page=100'
fetch_json() {
  echo '{"message":"temporary API failure"}'
}

if fetch_all_check_runs >/dev/null 2>&1; then
  echo "Expected malformed check-runs response to fail" >&2
  exit 1
fi

echo "Codecov watchdog smoke tests passed"
