#!/usr/bin/env bash
# Dispatch FindUpdates detect.yml (source=live), wait, download findupdates-report-json.
set -euo pipefail

REPO="${FINDUPDATES_REPO:-defrances/FindUpdates}"
WORKFLOW="${FINDUPDATES_WORKFLOW:-detect.yml}"
SOURCE="${FINDUPDATES_SOURCE:-live}"
ARTIFACT="${FINDUPDATES_ARTIFACT:-findupdates-report-json}"
OUT_DIR="${REPORT_DIR:-inputs}"
APPEAR_TIMEOUT="${DETECT_APPEAR_TIMEOUT:-180}"
WATCH_TIMEOUT="${DETECT_WATCH_TIMEOUT:-1500}"

mkdir -p "${OUT_DIR}"

if [ -z "${GH_TOKEN:-}" ]; then
  echo "GH_TOKEN / ORCHESTRATOR_PAT is required to start ${REPO} ${WORKFLOW}" >&2
  exit 1
fi

echo "Dispatching ${REPO} ${WORKFLOW} source=${SOURCE}"
if ! dispatch_out="$(gh workflow run "${WORKFLOW}" --repo "${REPO}" -f "source=${SOURCE}" 2>&1)"; then
  echo "${dispatch_out}" >&2
  echo "Could not start ${WORKFLOW} in ${REPO}." >&2
  echo "Edit the existing fine-grained PAT (same token value is fine) and grant:" >&2
  echo "  ${REPO}  Actions: Read and write" >&2
  echo "https://github.com/settings/personal-access-tokens" >&2
  echo "https://github.com/${REPO}/actions/workflows/${WORKFLOW}" >&2
  exit 1
fi
echo "${dispatch_out}"

start_iso="$(date -u -d '30 seconds ago' +%Y-%m-%dT%H:%M:%SZ)"
run_id="$(printf '%s\n' "${dispatch_out}" | sed -n 's#.*/actions/runs/\([0-9][0-9]*\).*#\1#p' | tail -n 1)"

deadline=$(( $(date -u +%s) + APPEAR_TIMEOUT ))
while [ -z "${run_id}" ] && [ "$(date -u +%s)" -lt "${deadline}" ]; do
  run_id="$(
    gh run list \
      --repo "${REPO}" \
      --workflow "${WORKFLOW}" \
      --event workflow_dispatch \
      --limit 20 \
      --json databaseId,createdAt \
      --jq "[.[] | select(.createdAt >= \"${start_iso}\")] | sort_by(.createdAt) | reverse | .[0].databaseId // empty"
  )"
  if [ -n "${run_id}" ]; then
    break
  fi
  sleep 5
done

if [ -z "${run_id}" ]; then
  echo "Timed out waiting for ${WORKFLOW} to appear in ${REPO}" >&2
  gh run list --repo "${REPO}" --workflow "${WORKFLOW}" --limit 5 >&2 || true
  exit 1
fi

echo "Waiting for FindUpdates run ${run_id}"
echo "https://github.com/${REPO}/actions/runs/${run_id}"
if ! timeout "${WATCH_TIMEOUT}" gh run watch "${run_id}" --repo "${REPO}" --exit-status; then
  echo "FindUpdates ${WORKFLOW} run ${run_id} failed" >&2
  gh run view "${run_id}" --repo "${REPO}" >&2 || true
  exit 1
fi

tmp="$(mktemp -d)"
gh run download "${run_id}" --repo "${REPO}" --name "${ARTIFACT}" --dir "${tmp}"
report="$(find "${tmp}" -type f -name 'report.json' | head -n 1)"
if [ -z "${report}" ]; then
  echo "Artifact ${ARTIFACT} did not contain report.json" >&2
  find "${tmp}" -type f >&2 || true
  rm -rf "${tmp}"
  exit 1
fi
cp "${report}" "${OUT_DIR}/report.json"
rm -rf "${tmp}"
echo "Saved ${OUT_DIR}/report.json from ${REPO} run ${run_id}"
