#!/usr/bin/env bash
# Compatibility wrapper. Orchestrator no longer starts FindUpdates.
# Download an existing findupdates-report-json artifact instead.
set -euo pipefail
exec "$(dirname "$0")/download-findupdates-report.sh"
