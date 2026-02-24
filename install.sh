#!/usr/bin/env bash
set -euo pipefail

# Forgemax installer — downloads pre-built binaries from GitHub releases.
# Usage: curl -fsSL https://raw.githubusercontent.com/postrv/forgemax/main/install.sh | bash

REPO="postrv/forgemax"
INSTALL_DIR="${FORGEMAX_INSTALL_DIR:-$HOME/.local/bin}"
BINARY_NAME="forgemax"
WORKER_NAME="forgemax-worker"

# Colors (only if terminal supports it)
if [ -t 1 ]; then
  BOLD='\033[1m'
  GREEN='\033[0;32m'
  YELLOW='\033[0;33m'
  RED='\033[0;31m'
  RESET='\033[0m'
else
  BOLD='' GREEN='' YELLOW='' RED='' RESET=''
fi

info()  { echo -e "${GREEN}${BOLD}info${RESET}  $*"; }
warn()  { echo -e "${YELLOW}${BOLD}warn${RESET}  $*"; }
error() { echo -e "${RED}${BOLD}error${RESET} $*" >&2; }

detect_platform() {
  local os arch

  case "$(uname -s)" in
    Linux*)  os="linux" ;;
    Darwin*) os="macos" ;;
    *)
      error "Unsupported OS: $(uname -s)"
      error "Try: cargo install forge-cli"
      exit 1
      ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      error "Unsupported architecture: $(uname -m)"
      error "Try: cargo install forge-cli"
      exit 1
      ;;
  esac

  echo "${os}-${arch}"
}

get_latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/'
  elif command -v wget &>/dev/null; then
    wget -qO- "$url" | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/'
  else
    error "Neither curl nor wget found"
    exit 1
  fi
}

download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL "$url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q "$url" -O "$dest"
  fi
}

main() {
  local platform version archive_url archive_file

  info "Detecting platform..."
  platform="$(detect_platform)"
  info "Platform: ${platform}"

  if [ -n "${FORGEMAX_VERSION:-}" ]; then
    version="$FORGEMAX_VERSION"
    info "Using specified version: v${version}"
  else
    info "Fetching latest version..."
    version="$(get_latest_version)"
    if [ -z "$version" ]; then
      error "Failed to determine latest version"
      error "Try: cargo install forge-cli"
      exit 1
    fi
    info "Latest version: v${version}"
  fi

  archive_url="https://github.com/${REPO}/releases/download/v${version}/forgemax-v${version}-${platform}.tar.gz"
  archive_file="$(mktemp)"

  info "Downloading ${archive_url}..."
  if ! download "$archive_url" "$archive_file"; then
    rm -f "$archive_file"
    error "Download failed"
    error "Try: cargo install forge-cli"
    exit 1
  fi

  info "Installing to ${INSTALL_DIR}..."
  mkdir -p "$INSTALL_DIR"

  tar xzf "$archive_file" -C "$INSTALL_DIR" "$BINARY_NAME" "$WORKER_NAME" 2>/dev/null || \
  tar xzf "$archive_file" -C "$INSTALL_DIR"
  rm -f "$archive_file"

  chmod 755 "$INSTALL_DIR/$BINARY_NAME" "$INSTALL_DIR/$WORKER_NAME"

  # Verify
  if "$INSTALL_DIR/$BINARY_NAME" --version &>/dev/null; then
    info "Installed: $("$INSTALL_DIR/$BINARY_NAME" --version)"
  else
    warn "Installed but version check failed"
  fi

  # Check PATH
  if ! echo "$PATH" | tr ':' '\n' | grep -q "^${INSTALL_DIR}$"; then
    warn "${INSTALL_DIR} is not in your PATH"
    echo ""
    info "Add to your shell profile:"

    local shell_name
    shell_name="$(basename "${SHELL:-/bin/bash}")"

    case "$shell_name" in
      zsh)
        echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.zshrc"
        echo "  source ~/.zshrc"
        ;;
      fish)
        echo "  fish_add_path ${INSTALL_DIR}"
        ;;
      *)
        echo "  echo 'export PATH=\"${INSTALL_DIR}:\$PATH\"' >> ~/.bashrc"
        echo "  source ~/.bashrc"
        ;;
    esac
    echo ""
  fi

  info "Quick start:"
  echo ""
  echo "  1. Create a config file:"
  echo "     curl -fsSL https://raw.githubusercontent.com/${REPO}/main/forge.toml.example > forge.toml"
  echo ""
  echo "  2. Configure your MCP client (Claude Desktop, Cursor, VS Code):"
  echo ""
  echo "     Claude Desktop (~/.claude/claude_desktop_config.json):"
  echo '     { "mcpServers": { "forge": { "command": "forgemax" } } }'
  echo ""
  echo "     VS Code / Cursor (.mcp.json):"
  echo '     { "servers": { "forge": { "command": "forgemax", "type": "stdio" } } }'
  echo ""
}

main "$@"
