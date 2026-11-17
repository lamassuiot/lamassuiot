#!/usr/bin/env bash

set -euo pipefail

fetch_json() {
  local url="$1"
  curl \
    --fail-with-body \
    --silent \
    --show-error \
    --retry 3 \
    --retry-delay 2 \
    --retry-max-time 20 \
    --retry-all-errors \
    "${api_headers[@]}" \
    "$url"
}

fetch_all_check_runs() {
  local page=1
  local page_payload
  local page_runs
  local all_runs='[]'

  while :; do
    if ! page_payload=$(fetch_json "${checks_url}&page=${page}"); then
      return 1
    fi
    if ! jq -e '(.check_runs | type) == "array"' <<<"$page_payload" >/dev/null; then
      return 1
    fi
    if ! page_runs=$(jq '.check_runs' <<<"$page_payload"); then
      return 1
    fi
    if ! all_runs=$(jq -n --argjson all "$all_runs" --argjson page "$page_runs" '$all + $page'); then
      return 1
    fi

    if (( $(jq 'length' <<<"$page_runs") < 100 )); then
      if ! jq -n --argjson check_runs "$all_runs" '{check_runs: $check_runs}'; then
        return 1
      fi
      return 0
    fi
    page=$((page + 1))
  done
}

codecov_state() {
  local checks="$1"
  local statuses="$2"
  local codecov_checks
  local codecov_statuses
  local check_count
  local status_count
  local failed_checks
  local failed_statuses
  local pending_checks
  local pending_statuses

  # Only checks created by Codecov count; the watchdog is a GitHub Actions check.
  codecov_checks=$(jq '[.check_runs[] | select(.app.slug == "codecov")]' <<<"$checks")
  codecov_statuses=$(jq '[.[] | select((.context | ascii_downcase | contains("codecov")))]' <<<"$statuses")
  check_count=$(jq 'length' <<<"$codecov_checks")
  status_count=$(jq 'length' <<<"$codecov_statuses")
  failed_checks=$(jq '[.[] | select(.conclusion == "failure" or .conclusion == "cancelled" or .conclusion == "timed_out" or .conclusion == "action_required")] | length' <<<"$codecov_checks")
  failed_statuses=$(jq '[.[] | select(.state == "failure" or .state == "error")] | length' <<<"$codecov_statuses")
  pending_checks=$(jq '[.[] | select(.status != "completed" or .conclusion == null)] | length' <<<"$codecov_checks")
  pending_statuses=$(jq '[.[] | select(.state == "pending")] | length' <<<"$codecov_statuses")

  if (( failed_checks > 0 || failed_statuses > 0 )); then
    echo failure
  elif (( (check_count > 0 || status_count > 0) && pending_checks == 0 && pending_statuses == 0 )); then
    echo success
  else
    echo pending
  fi
}

main() {
  if [[ "${NOTIFY_RESULT:-}" != "success" ]]; then
    echo "Codecov notifications did not complete successfully: ${NOTIFY_RESULT:-unset}"
    return 1
  fi

  api_headers=(-H "Accept: application/vnd.github+json" -H "Authorization: Bearer ${GH_TOKEN:?}" -H "X-GitHub-Api-Version: 2022-11-28")
  checks_url="https://api.github.com/repos/${GITHUB_REPOSITORY:?}/commits/${CODECOV_SHA:?}/check-runs?per_page=100"
  statuses_url="https://api.github.com/repos/${GITHUB_REPOSITORY}/commits/${CODECOV_SHA}/statuses"
  consecutive_api_failures=0

  for attempt in $(seq 1 "${MAX_ATTEMPTS:-30}"); do
    if ! checks=$(fetch_all_check_runs) || ! statuses=$(fetch_json "$statuses_url"); then
      consecutive_api_failures=$((consecutive_api_failures + 1))
      echo "GitHub API polling failed ($consecutive_api_failures/${MAX_API_FAILURES:-5})"
      if (( consecutive_api_failures >= ${MAX_API_FAILURES:-5} )); then
        echo "GitHub API polling failed too many times"
        return 1
      fi
      sleep "${POLL_SECONDS:-20}"
      continue
    fi
    consecutive_api_failures=0

    state=$(codecov_state "$checks" "$statuses")
    echo "Attempt $attempt/${MAX_ATTEMPTS:-30}: Codecov state=$state"

    case "$state" in
      success)
        echo "Codecov completed for $CODECOV_SHA"
        return 0
        ;;
      failure)
        echo "Codecov reported a failure for $CODECOV_SHA"
        return 1
        ;;
    esac

    sleep "${POLL_SECONDS:-20}"
  done

  echo "Codecov did not complete within $((${POLL_SECONDS:-20} * ${MAX_ATTEMPTS:-30})) seconds"
  return 1
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
