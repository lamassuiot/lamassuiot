#!/usr/bin/env bash

# fetch_json is replaced by test stubs and invoked indirectly by the sourced
# fetch_all_check_runs function.
# shellcheck disable=SC2329
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
stale_statuses='[{"context":"codecov/project","state":"failure","created_at":"2026-11-17T10:00:00Z"},{"context":"codecov/project","state":"success","created_at":"2026-11-17T10:01:00Z"}]'

assert_state pending "$pending_checks" "$empty_statuses"
assert_state success "$completed_checks" "$empty_statuses"
assert_state success '{"check_runs":[]}' "$completed_statuses"
assert_state success '{"check_runs":[]}' "$stale_statuses"

# The variable is consumed by fetch_all_check_runs from the sourced script.
# shellcheck disable=SC2034
export checks_url='https://example.test/check-runs?per_page=100'
requested_url_file="$(mktemp)"
trap 'rm -f "$requested_url_file"' EXIT
# The sourced fetch_all_check_runs function invokes this stub indirectly.
# shellcheck disable=SC2329
fetch_json() {
  printf '%s\n' "$1" >"$requested_url_file"
  echo '{"message":"temporary API failure"}'
}

if fetch_all_check_runs >/dev/null 2>&1; then
  echo "Expected malformed check-runs response to fail" >&2
  exit 1
fi
if [[ "$(cat "$requested_url_file")" != "${checks_url}&page=1" ]]; then
  echo "Unexpected check-runs URL: $(cat "$requested_url_file")" >&2
  exit 1
fi

# The sourced fetch_all_check_runs function invokes this stub indirectly.
# shellcheck disable=SC2329
fetch_json() {
  return 1
}

if fetch_all_check_runs >/dev/null 2>&1; then
  echo "Expected fetch failure to propagate" >&2
  exit 1
fi

# The sourced fetch_all_check_runs function invokes this stub indirectly.
# shellcheck disable=SC2329
fetch_json() {
  printf '%s\n' "$1" >"$requested_url_file"
  if [[ "$1" == *"page=1" ]]; then
    jq -n '{check_runs: [range(0; 100) | {name: ("check-" + tostring)}]}'
  else
    echo '{"check_runs":[{"name":"last-check"}]}'
  fi
}

if ! all_runs=$(fetch_all_check_runs); then
  echo "Expected multi-page check-runs response to succeed" >&2
  exit 1
fi
if [[ "$(jq '.check_runs | length' <<<"$all_runs")" != "101" ]]; then
  echo "Expected 101 aggregated check-runs" >&2
  exit 1
fi
if [[ "$(cat "$requested_url_file")" != "${checks_url}&page=2" ]]; then
  echo "Expected pagination to request page 2" >&2
  exit 1
fi

echo "Codecov watchdog smoke tests passed"
