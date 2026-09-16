#!/usr/bin/env bash
# Dispatch FindUpdates detect.yml with source=live, wait, download findupdates-report-json.
set -euo pipefail

REPO="${FINDUPDATES_REPO:-defrances/FindUpdates}"
WORKFLOW="${FINDUPDATES_WORKFLOW:-detect.yml}"
SOURCE="${FINDUPDATES_SOURCE:-live}"
ARTIFACT="${FINDUPDATES_ARTIFACT:-findupdates-report-json}"
OUT_DIR="${REPORT_DIR:-inputs}"
APPEAR_TIMEOUT="${DETECT_APPEAR_TIMEOUT:-180}"
WATCH_TIMEOUT="${DETECT_WATCH_TIMEOUT:-1500}"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN / ORCHESTRATOR_PAT is required to dispatch FindUpdates." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
START_ISO="$(date -u -d '15 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"

echo "Dispatching ${REPO} ${WORKFLOW} source=${SOURCE}"
gh workflow run "${WORKFLOW}" --repo "${REPO}" -f "source=${SOURCE}"

RUN_ID=""
DEADLINE=$(( $(date -u +%s) + APPEAR_TIMEOUT ))
while [ "$(date -u +%s)" -lt "${DEADLINE}" ]; do
  RUN_ID="$(
    gh run list \
      --repo "${REPO}" \
      --workflow "${WORKFLOW}" \
      --event workflow_dispatch \
      --limit 20 \
      --json databaseId,createdAt,status,headBranch \
      --jq --arg start "${START_ISO}" \
      '[.[] | select(.createdAt >= $start)]
       | sort_by(.createdAt)
       | reverse
       | .[0].databaseId // empty'
  )"
  if [ -n "${RUN_ID}" ]; then
    break
  fi
  sleep 5
done

if [ -z "${RUN_ID}" ]; then
  echo "Timed out waiting for ${WORKFLOW} workflow_dispatch run to appear." >&2
  gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 5 >&2 || true
  exit 1
fi

echo "Waiting for FindUpdates run ${RUN_ID}"
echo "https://github.com/${REPO}/actions/runs/${RUN_ID}"

if ! timeout "${WATCH_TIMEOUT}" gh run watch "${RUN_ID}" --repo "${REPO}" --exit-status; then
  echo "FindUpdates ${WORKFLOW} run ${RUN_ID} failed or timed out." >&2
  gh run view "${RUN_ID}" --repo "${REPO}" >&2 || true
  exit 1
fi

TMP="$(mktemp -d)"
cleanup() { rm -rf "${TMP}"; }
trap cleanup EXIT

gh run download "${RUN_ID}" --repo "${REPO}" --name "${ARTIFACT}" --dir "${TMP}"

REPORT="$(find "${TMP}" -type f -name 'report.json' | head -n 1)"
if [ -z "${REPORT}" ]; then
  echo "Artifact ${ARTIFACT} from run ${RUN_ID} did not contain report.json" >&2
  find "${TMP}" -type f >&2 || true
  exit 1
fi

cp "${REPORT}" "${OUT_DIR}/report.json"
echo "Saved ${OUT_DIR}/report.json from ${REPO} run ${RUN_ID}"
