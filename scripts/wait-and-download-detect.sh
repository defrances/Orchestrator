#!/usr/bin/env bash
# Prefer FindUpdates detect.yml (source=live). If dispatch is denied, run the same live detect locally.
set -euo pipefail

REPO="${FINDUPDATES_REPO:-defrances/FindUpdates}"
WORKFLOW="${FINDUPDATES_WORKFLOW:-detect.yml}"
SOURCE="${FINDUPDATES_SOURCE:-live}"
ARTIFACT="${FINDUPDATES_ARTIFACT:-findupdates-report-json}"
OUT_DIR="${REPORT_DIR:-inputs}"
APPEAR_TIMEOUT="${DETECT_APPEAR_TIMEOUT:-180}"
WATCH_TIMEOUT="${DETECT_WATCH_TIMEOUT:-1500}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "${OUT_DIR}"

dispatch_remote() {
  if [ -z "${GH_TOKEN:-}" ]; then
    echo "No GH_TOKEN; skipping remote detect.yml dispatch"
    return 1
  fi

  echo "Dispatching ${REPO} ${WORKFLOW} source=${SOURCE}"
  if ! gh workflow run "${WORKFLOW}" --repo "${REPO}" -f "source=${SOURCE}"; then
    echo "Remote detect.yml dispatch failed; will run live detect locally"
    return 1
  fi

  local start_iso run_id deadline
  start_iso="$(date -u -d '15 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"
  run_id=""
  deadline=$(( $(date -u +%s) + APPEAR_TIMEOUT ))
  while [ "$(date -u +%s)" -lt "${deadline}" ]; do
    run_id="$(
      gh run list \
        --repo "${REPO}" \
        --workflow "${WORKFLOW}" \
        --event workflow_dispatch \
        --limit 20 \
        --json databaseId,createdAt \
        --jq --arg start "${start_iso}" \
        '[.[] | select(.createdAt >= $start)]
         | sort_by(.createdAt)
         | reverse
         | .[0].databaseId // empty'
    )"
    if [ -n "${run_id}" ]; then
      break
    fi
    sleep 5
  done

  if [ -z "${run_id}" ]; then
    echo "Timed out waiting for ${WORKFLOW} to appear; will run live detect locally"
    return 1
  fi

  echo "Waiting for FindUpdates run ${run_id}"
  echo "https://github.com/${REPO}/actions/runs/${run_id}"
  if ! timeout "${WATCH_TIMEOUT}" gh run watch "${run_id}" --repo "${REPO}" --exit-status; then
    echo "FindUpdates ${WORKFLOW} run ${run_id} failed"
    gh run view "${run_id}" --repo "${REPO}" >&2 || true
    return 1
  fi

  local tmp report
  tmp="$(mktemp -d)"
  gh run download "${run_id}" --repo "${REPO}" --name "${ARTIFACT}" --dir "${tmp}"
  report="$(find "${tmp}" -type f -name 'report.json' | head -n 1)"
  if [ -z "${report}" ]; then
    echo "Artifact ${ARTIFACT} did not contain report.json" >&2
    find "${tmp}" -type f >&2 || true
    rm -rf "${tmp}"
    return 1
  fi
  cp "${report}" "${OUT_DIR}/report.json"
  rm -rf "${tmp}"
  echo "Saved ${OUT_DIR}/report.json from ${REPO} run ${run_id}"
}

if dispatch_remote; then
  exit 0
fi

bash "${SCRIPT_DIR}/run-detect-live.sh"
