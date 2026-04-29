#!/usr/bin/env bash
# Capture a full-page screenshot of a public Inkog scan report.
# Used to produce docs/screenshots/dashboard-report.png for the README.
#
# Usage:
#   scripts/record-dashboard.sh                                        # uses default report URL
#   scripts/record-dashboard.sh https://app.inkog.io/report/<id>       # custom report
#
# Requires Node.js. Playwright + Chromium are installed on demand.

set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p docs/screenshots

URL="${1:-https://app.inkog.io/report/37e0bb44-b93e-4d03-be10-1276ba9ad3c4}"
OUT="docs/screenshots/dashboard-report.png"

if ! command -v node >/dev/null 2>&1; then
  echo "Error: node is required" >&2
  exit 1
fi

# Install playwright-core into a temp dir so we don't pollute the repo with node_modules
TMP="${TMPDIR:-/tmp}/inkog-playwright-stage"
if [ ! -d "$TMP/node_modules/playwright" ]; then
  mkdir -p "$TMP"
  ( cd "$TMP" && npm init -y >/dev/null 2>&1 && npm install --silent playwright@1 >/dev/null 2>&1 )
  npx --prefix "$TMP" playwright install chromium >/dev/null 2>&1 || true
fi

REPO_ROOT="$(pwd)"
# Copy script into the temp dir so its `import 'playwright'` resolves
cp scripts/record-dashboard.mjs "$TMP/record-dashboard.mjs"
( cd "$TMP" && node ./record-dashboard.mjs "$URL" "$REPO_ROOT/$OUT" )
echo "Wrote $OUT ($(du -h "$OUT" | cut -f1))"
