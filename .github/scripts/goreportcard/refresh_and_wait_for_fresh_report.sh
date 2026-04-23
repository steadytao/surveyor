#!/usr/bin/env bash
# Copyright 2026 The Surveyor Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Record when this workflow requested a refresh so later checks can prove the report is fresh.
refresh_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "REFRESH_STARTED_AT=${refresh_started_at}" >> "${GITHUB_ENV}"

refresh_response_path="$(mktemp)"
report_url="https://goreportcard.com/report/${REPO}"
max_attempts=12
sleep_seconds=5

cleanup() {
  rm -f "${refresh_response_path}"
}

trap cleanup EXIT

curl --fail --silent --show-error \
  --connect-timeout 10 \
  --max-time 60 \
  --retry 3 \
  --retry-delay 2 \
  --retry-all-errors \
  --request POST \
  --header 'User-Agent: Witness-GoReportCard-Check/1' \
  --header 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode "repo=${REPO}" \
  https://goreportcard.com/checks \
  --output "${refresh_response_path}"

report_path="$(python3 .github/scripts/goreportcard/report_payload.py parse-refresh-redirect "${refresh_response_path}")"

curl --fail --silent --show-error \
  --connect-timeout 10 \
  --max-time 60 \
  --retry 3 \
  --retry-delay 2 \
  --retry-all-errors \
  --header 'User-Agent: Witness-GoReportCard-Check/1' \
  --location \
  "https://goreportcard.com${report_path}" \
  --output goreportcard-response.html

for attempt in $(seq 1 "${max_attempts}"); do
  last_refresh="$(python3 .github/scripts/goreportcard/report_payload.py extract-last-refresh goreportcard-response.html)"

  if [ -n "${last_refresh}" ] && [ "$(date -u -d "${last_refresh}" +%s)" -ge "$(date -u -d "${refresh_started_at}" +%s)" ]; then
    echo "Report freshness confirmed at ${last_refresh}."
    exit 0
  fi

  if [ "${attempt}" -eq "${max_attempts}" ]; then
    echo "Go Report Card report did not refresh after ${max_attempts} attempts." >&2
    echo "Last seen refresh time: ${last_refresh:-<empty>}" >&2
    exit 1
  fi

  sleep "${sleep_seconds}"
  curl --fail --silent --show-error \
    --connect-timeout 10 \
    --max-time 60 \
    --retry 3 \
    --retry-delay 2 \
    --retry-all-errors \
    --header 'User-Agent: Witness-GoReportCard-Check/1' \
    --location \
    "${report_url}" \
    --output goreportcard-response.html
done
