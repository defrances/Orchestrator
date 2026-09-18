#!/usr/bin/env bash
# Download findupdates-report-json from an existing FindUpdates run.
# Does not start FindUpdates (that would loop with detect.yml dispatch).
set -euo pipefail

REPO="${FINDUPDATES_REPO:-defrances/FindUpdates}"
ARTIFACT="${FINDUPDATES_ARTIFACT:-findupdates-report-json}"
OUT_DIR="${REPORT_DIR:-inputs}"
RUN_ID="${FU_RUN_ID:-}"

mkdir -p "${OUT_DIR}"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN / ORCHESTRATOR_PAT is required to download ${ARTIFACT} from ${REPO}" >&2
  exit 1
fi

if [ -z "${RUN_ID}" ]; then
  echo "FU_RUN_ID is empty; cannot download ${ARTIFACT}." >&2
  echo "Pass FindUpdates run id via repository_dispatch client_payload.run_id or workflow_dispatch findupdates_run_id." >&2
  exit 1
fi

echo "Downloading ${ARTIFACT} from ${REPO} run ${RUN_ID}"
echo "https://github.com/${REPO}/actions/runs/${RUN_ID}"

tmp="$(mktemp -d)"
cleanup() { rm -rf "${tmp}"; }
trap cleanup EXIT

if ! gh run download "${RUN_ID}" --repo "${REPO}" --name "${ARTIFACT}" --dir "${tmp}"; then
  echo "Could not download artifact ${ARTIFACT} from ${REPO} run ${RUN_ID}" >&2
  gh run view "${RUN_ID}" --repo "${REPO}" >&2 || true
  exit 1
fi

report="$(find "${tmp}" -type f -name 'report.json' | head -n 1)"
if [ -z "${report}" ]; then
  echo "Artifact ${ARTIFACT} did not contain report.json" >&2
  find "${tmp}" -type f >&2 || true
  exit 1
fi
cp "${report}" "${OUT_DIR}/report.json"
echo "Saved ${OUT_DIR}/report.json from ${REPO} run ${RUN_ID}"
