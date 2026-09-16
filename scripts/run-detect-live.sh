#!/usr/bin/env bash
# Run FindUpdates live detect locally (same path as detect.yml) and write inputs/report.json.
set -euo pipefail

REPO="${FINDUPDATES_REPO:-defrances/FindUpdates}"
OUT_DIR="${REPORT_DIR:-inputs}"
WORK_DIR="${FINDUPDATES_WORKDIR:-workspace/FindUpdates}"
DETECT_OUT="${FINDUPDATES_DETECT_OUT:-${RUNNER_TEMP:-/tmp}/findupdates-detect}"

mkdir -p "${OUT_DIR}" "${WORK_DIR}" "${DETECT_OUT}"

if [ ! -d "${WORK_DIR}/.git" ]; then
  echo "Cloning ${REPO} for live detect"
  git clone --depth 1 "https://github.com/${REPO}.git" "${WORK_DIR}"
fi

python3 -m pip install --upgrade pip
python3 -m pip install -r "${WORK_DIR}/requirements-dev.lock"

export PYTHONPATH="${WORK_DIR}/src"
export FINDUPDATES_AI_ENABLED="${FINDUPDATES_AI_ENABLED:-true}"
export FINDUPDATES_AI_PROVIDER="${FINDUPDATES_AI_PROVIDER:-copilot}"
export FINDUPDATES_COPILOT_MAX_COMPLETIONS="${FINDUPDATES_COPILOT_MAX_COMPLETIONS:-8}"
export FINDUPDATES_MSRC_LOOKBACK_DAYS="${FINDUPDATES_MSRC_LOOKBACK_DAYS:-45}"
export FINDUPDATES_INTEL_LOOKBACK_DAYS="${FINDUPDATES_INTEL_LOOKBACK_DAYS:-45}"
export COPILOT_AUTO_UPDATE="${COPILOT_AUTO_UPDATE:-false}"

echo "Running FindUpdates detect --source live"
python3 -m findupdates.pipeline detect \
  --source live \
  --inventory "${WORK_DIR}/configs/inventory/synthetic-workstations.json" \
  --output-dir "${DETECT_OUT}"

if [ -f "${DETECT_OUT}/report.md" ]; then
  cat "${DETECT_OUT}/report.md" >> "${GITHUB_STEP_SUMMARY:-/dev/null}" || true
fi

if [ ! -f "${DETECT_OUT}/report.json" ]; then
  echo "Live detect did not produce report.json" >&2
  ls -la "${DETECT_OUT}" >&2 || true
  exit 1
fi

cp "${DETECT_OUT}/report.json" "${OUT_DIR}/report.json"
echo "Saved ${OUT_DIR}/report.json from local live detect"
