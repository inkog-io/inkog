#!/bin/sh
set -e

# Inkog CLI Installer
# Usage: curl -fsSL https://inkog.io/install.sh | sh

REPO="inkog-io/inkog"

echo "Installing Inkog..."

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# For now, use go install (until we have binary releases)
if command -v go >/dev/null 2>&1; then
  echo "Found Go, installing via go install..."
  go install github.com/${REPO}/cmd/cli@latest

  # Verify installation
  if command -v inkog >/dev/null 2>&1; then
    echo ""
    echo "Inkog installed successfully!"
    echo ""
    echo "  Run: inkog --help"
    echo ""
  else
    echo ""
    echo "Installed! Binary is at: $(go env GOPATH)/bin/inkog"
    echo "Add $(go env GOPATH)/bin to your PATH if not already."
    echo ""
  fi
else
  echo "Error: Go is required for installation."
  echo ""
  echo "Install Go from: https://go.dev/dl/"
  echo ""
  echo "Or download a pre-built binary from:"
  echo "  https://github.com/${REPO}/releases"
  echo ""
  exit 1
fi
