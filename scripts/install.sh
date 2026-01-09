#!/bin/sh
set -e

# Inkog CLI Installer
# Usage: curl -fsSL https://inkog.io/install.sh | sh
#
# This script installs the Inkog CLI. It will:
# 1. Try to download a pre-built binary (fastest)
# 2. Fall back to `go install` if Go is available
#
# Environment variables:
#   INKOG_INSTALL_DIR  - Installation directory (default: /usr/local/bin or ~/bin)
#   INKOG_VERSION      - Specific version to install (default: latest)

REPO="inkog-io/inkog"
BINARY_NAME="inkog"
GITHUB_RELEASES="https://github.com/${REPO}/releases"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}==>${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}Warning:${NC} %s\n" "$1"
}

error() {
    printf "${RED}Error:${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$OS" in
        darwin) OS="darwin" ;;
        linux) OS="linux" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) error "Unsupported operating system: $OS" ;;
    esac
    echo "$OS"
}

# Detect architecture
detect_arch() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64|amd64) ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7*) ARCH="arm" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac
    echo "$ARCH"
}

# Get latest version from GitHub
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo ""
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo ""
    fi
}

# Determine install directory
get_install_dir() {
    if [ -n "$INKOG_INSTALL_DIR" ]; then
        echo "$INKOG_INSTALL_DIR"
    elif [ -w "/usr/local/bin" ]; then
        echo "/usr/local/bin"
    else
        mkdir -p "$HOME/bin"
        echo "$HOME/bin"
    fi
}

# Try to download pre-built binary
try_binary_install() {
    local os="$1"
    local arch="$2"
    local version="$3"
    local install_dir="$4"

    if [ -z "$version" ]; then
        return 1
    fi

    local binary_name="${BINARY_NAME}-${os}-${arch}"
    if [ "$os" = "windows" ]; then
        binary_name="${binary_name}.exe"
    fi

    local download_url="${GITHUB_RELEASES}/download/${version}/${binary_name}"

    info "Downloading Inkog ${version} for ${os}/${arch}..."

    local tmp_file=$(mktemp)

    if command -v curl >/dev/null 2>&1; then
        if curl -fsSL "$download_url" -o "$tmp_file" 2>/dev/null; then
            chmod +x "$tmp_file"
            mv "$tmp_file" "${install_dir}/${BINARY_NAME}"
            return 0
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q "$download_url" -O "$tmp_file" 2>/dev/null; then
            chmod +x "$tmp_file"
            mv "$tmp_file" "${install_dir}/${BINARY_NAME}"
            return 0
        fi
    fi

    rm -f "$tmp_file"
    return 1
}

# Install via Go
try_go_install() {
    if ! command -v go >/dev/null 2>&1; then
        return 1
    fi

    info "Installing via 'go install'..."

    # Use GOPROXY=direct to get the latest version
    GOPROXY=direct go install "github.com/${REPO}/cmd/inkog@latest" 2>/dev/null

    if [ $? -eq 0 ]; then
        return 0
    fi

    # Fallback to default proxy
    go install "github.com/${REPO}/cmd/inkog@latest" 2>/dev/null
    return $?
}

# Main installation
main() {
    printf "\n"
    printf "  ${GREEN}╦${NC}${GREEN}╔╗╔${NC}${GREEN}╦╔═${NC}${GREEN}╔═╗${NC}${GREEN}╔═╗${NC}\n"
    printf "  ${GREEN}║${NC}${GREEN}║║║${NC}${GREEN}╠╩╗${NC}${GREEN}║ ║${NC}${GREEN}║ ╦${NC}\n"
    printf "  ${GREEN}╩${NC}${GREEN}╝╚╝${NC}${GREEN}╩ ╩${NC}${GREEN}╚═╝${NC}${GREEN}╚═╝${NC}\n"
    printf "\n"
    printf "  Static security scanner for AI agents\n"
    printf "\n"

    OS=$(detect_os)
    ARCH=$(detect_arch)
    VERSION=${INKOG_VERSION:-$(get_latest_version)}
    INSTALL_DIR=$(get_install_dir)

    info "Detected: ${OS}/${ARCH}"

    # Try binary download first (fastest)
    if try_binary_install "$OS" "$ARCH" "$VERSION" "$INSTALL_DIR"; then
        info "Installed to: ${INSTALL_DIR}/${BINARY_NAME}"
    # Fall back to go install
    elif try_go_install; then
        INSTALL_DIR="$(go env GOPATH)/bin"
        info "Installed to: ${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo ""
        error "Installation failed. Please try one of these methods:"
        echo ""
        echo "  1. Install Go and run:"
        echo "     go install github.com/${REPO}/cmd/inkog@latest"
        echo ""
        echo "  2. Download binary manually from:"
        echo "     ${GITHUB_RELEASES}"
        echo ""
        exit 1
    fi

    # Verify installation
    if command -v inkog >/dev/null 2>&1; then
        echo ""
        info "Inkog installed successfully!"
        echo ""
        echo "  Get started:"
        echo "    1. Get your API key at https://app.inkog.io"
        echo "    2. export INKOG_API_KEY=sk_live_your_key"
        echo "    3. inkog ./your-agent-code"
        echo ""
    else
        echo ""
        warn "Installed but 'inkog' not in PATH."
        echo ""
        echo "  Add to your PATH:"
        echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
        echo "  Then run:"
        echo "    inkog --help"
        echo ""
    fi
}

main "$@"
