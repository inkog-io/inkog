#!/usr/bin/env bash
# Record a fresh demo.gif for the README.
#
# Usage:
#   INKOG_API_KEY=sk_live_... scripts/record-demo.sh
#
# Requires: vhs (brew install vhs), a fresh ./inkog binary (run `make build`).

set -euo pipefail

if [ -z "${INKOG_API_KEY:-}" ]; then
  echo "Error: INKOG_API_KEY must be set in the environment." >&2
  echo "Get one at https://app.inkog.io and run:" >&2
  echo "  export INKOG_API_KEY=sk_live_..." >&2
  exit 1
fi

if ! command -v vhs >/dev/null 2>&1; then
  echo "Error: vhs is not installed." >&2
  echo "  brew install vhs" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

if [ ! -x "./inkog" ]; then
  echo "Building inkog binary..."
  make build
fi

# Stage a clean target dir so the demo always shows the same agent
WORK_DIR="/tmp/inkog-demo-record"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"
cp -R "${REPO_ROOT}/../demo_agent" "$WORK_DIR/agent"

echo "Recording demo.gif (this takes ~30 seconds)..."
vhs scripts/demo.tape

if [ -f demo.gif ]; then
  SIZE=$(du -h demo.gif | cut -f1)
  echo "Recorded demo.gif ($SIZE)"
else
  echo "Recording failed — no demo.gif produced." >&2
  exit 1
fi
