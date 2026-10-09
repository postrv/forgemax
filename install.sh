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
      error "Try: cargo install --locked forgemax forge-sandbox-worker"
      exit 1
      ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)  arch="x86_64" ;;
    aarch64|arm64) arch="aarch64" ;;
    *)
      error "Unsupported architecture: $(uname -m)"
      error "Try: cargo install --locked forgemax forge-sandbox-worker"
      exit 1
      ;;
  esac

  echo "${os}-${arch}"
}

get_latest_version() {
  local url="https://api.github.com/repos/${REPO}/releases/latest"
  download "$url" "$TEMP_DIR/latest.json"
  sed -nE 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v([^"]+)".*/\1/p' "$TEMP_DIR/latest.json"
}

download() {
  local url="$1" dest="$2"
  if command -v curl &>/dev/null; then
    curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --connect-timeout 30 --max-time 300 --max-redirs 5 "$url" -o "$dest"
  elif command -v wget &>/dev/null; then
    wget -q --https-only --timeout=30 --tries=3 --max-redirect=5 "$url" -O "$dest"
  else
    error "Neither curl nor wget found"
    return 1
  fi
}

# Detect available SHA256 command
detect_sha256_cmd() {
  if command -v sha256sum &>/dev/null; then
    echo "sha256sum"
  elif command -v shasum &>/dev/null; then
    echo "shasum -a 256"
  else
    echo ""
  fi
}

# Verify SHA256 checksum of downloaded archive
verify_checksum() {
  local archive_file="$1" version="$2" platform="$3"
  local sha_cmd checksum_url checksum_file expected actual filename

  sha_cmd="$(detect_sha256_cmd)"
  if [ -z "$sha_cmd" ]; then
    error "A SHA256 tool (sha256sum or shasum) is required"
    return 1
  fi

  checksum_url="https://github.com/${REPO}/releases/download/v${version}/SHA256SUMS.txt"
  checksum_file="$TEMP_DIR/SHA256SUMS.txt"
  filename="forgemax-v${version}-${platform}.tar.gz"

  if ! download "$checksum_url" "$checksum_file"; then
    error "Could not download required checksums"
    return 1
  fi
  expected=$(awk -v name="$filename" 'NF == 2 { sub(/^\*/, "", $2); if ($2 == name) print tolower($1) }' "$checksum_file")
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
    error "Expected exactly one valid SHA256 checksum for ${filename}"
    return 1
  fi
  # sha_cmd is selected exclusively from the fixed commands above.
  actual=$($sha_cmd "$archive_file" | awk '{print $1}')
  if [ "$expected" != "$actual" ]; then
    error "SHA256 mismatch for ${filename}"
    return 1
  fi
  info "SHA256 verified"
}

publish_binaries() {
  local name failed=0 rollback_failed=0
  local backed_up=() published=()
  mkdir -p "$INSTALL_DIR" "$TEMP_DIR/previous"
  for name in "$BINARY_NAME" "$WORKER_NAME"; do
    if [ -L "$INSTALL_DIR/$name" ] || { [ -e "$INSTALL_DIR/$name" ] && [ ! -f "$INSTALL_DIR/$name" ]; }; then
      error "Install destination must be a regular file: $INSTALL_DIR/$name"
      return 1
    fi
  done
  for name in "$BINARY_NAME" "$WORKER_NAME"; do
    if [ -e "$INSTALL_DIR/$name" ]; then
      if ! mv -f "$INSTALL_DIR/$name" "$TEMP_DIR/previous/$name"; then
        failed=1
        break
      fi
      backed_up+=("$name")
    fi
  done
  if [ "$failed" -eq 0 ]; then
    for name in "$BINARY_NAME" "$WORKER_NAME"; do
      # A cross-filesystem mv can leave a partial destination before failing.
      published+=("$name")
      if ! mv -f "$TEMP_DIR/$name" "$INSTALL_DIR/$name"; then
        failed=1
        break
      fi
    done
  fi
  if [ "$failed" -ne 0 ]; then
    # Bash 3.2's nounset handling requires this expansion for empty arrays.
    for name in ${published[@]+"${published[@]}"}; do
      rm -f "$INSTALL_DIR/$name" || rollback_failed=1
    done
    for name in ${backed_up[@]+"${backed_up[@]}"}; do
      mv -f "$TEMP_DIR/previous/$name" "$INSTALL_DIR/$name" || rollback_failed=1
    done
    if [ "$rollback_failed" -ne 0 ]; then
      PRESERVE_TEMP=true
      error "Rollback incomplete; recovery files retained at $TEMP_DIR"
    fi
    error "Could not replace the installed binaries"
    return 1
  fi
}

main() {
  local platform version archive_url archive_file entries name member version_output

  TEMP_DIR="$(mktemp -d)"
  PRESERVE_TEMP=false
  trap 'if [ "$PRESERVE_TEMP" = false ]; then rm -rf "$TEMP_DIR"; fi' EXIT

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
      error "Try: cargo install --locked forgemax forge-sandbox-worker"
      exit 1
    fi
    info "Latest version: v${version}"
  fi

  if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
    error "Invalid release version: ${version}"
    exit 1
  fi

  archive_url="https://github.com/${REPO}/releases/download/v${version}/forgemax-v${version}-${platform}.tar.gz"
  archive_file="$TEMP_DIR/release.tar.gz"

  info "Downloading ${archive_url}..."
  if ! download "$archive_url" "$archive_file"; then
    error "Download failed"
    error "Try: cargo install --locked forgemax forge-sandbox-worker"
    exit 1
  fi

  verify_checksum "$archive_file" "$version" "$platform"

  # Extract only the two required files to fixed paths. tar writes file contents
  # to stdout, so archive paths and metadata are never applied to the filesystem.
  entries="$(tar tzf "$archive_file")"
  for name in "$BINARY_NAME" "$WORKER_NAME"; do
    member=$(printf '%s\n' "$entries" | awk -v name="$name" '$0 == name || $0 == "./" name { print }')
    if [ "$member" != "$name" ] && [ "$member" != "./$name" ]; then
      error "Archive must contain exactly one ${name}"
      exit 1
    fi
    tar xOzf "$archive_file" "$member" > "$TEMP_DIR/$name"
    [ -s "$TEMP_DIR/$name" ] || { error "Empty binary: ${name}"; exit 1; }
    chmod 755 "$TEMP_DIR/$name"
  done
  version_output="$("$TEMP_DIR/$BINARY_NAME" --version)"
  if [ "$version_output" != "forgemax $version" ]; then
    error "Downloaded binary version does not match v${version}"
    exit 1
  fi

  info "Installing to ${INSTALL_DIR}..."
  publish_binaries
  info "Installed: ${version_output}"

  # Check PATH
  if ! printf '%s' "$PATH" | tr ':' '\n' | grep -Fx "$INSTALL_DIR" >/dev/null; then
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
  echo '     { "mcpServers": { "forgemax": { "command": "forgemax" } } }'
  echo ""
  echo "     VS Code / Cursor (.mcp.json):"
  echo '     { "servers": { "forgemax": { "command": "forgemax", "type": "stdio" } } }'
  echo ""
}

main "$@"
