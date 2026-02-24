# Forgemax installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/postrv/forgemax/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "postrv/forgemax"
$InstallDir = if ($env:FORGEMAX_INSTALL_DIR) { $env:FORGEMAX_INSTALL_DIR } else { "$env:LOCALAPPDATA\Programs\forgemax" }
$BinaryName = "forgemax.exe"
$WorkerName = "forgemax-worker.exe"

function Write-Info { param($Message) Write-Host "info  " -ForegroundColor Green -NoNewline; Write-Host $Message }
function Write-Warn { param($Message) Write-Host "warn  " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
function Write-Err  { param($Message) Write-Host "error " -ForegroundColor Red -NoNewline; Write-Host $Message }

function Get-LatestVersion {
    $url = "https://api.github.com/repos/$Repo/releases/latest"
    try {
        $response = Invoke-RestMethod -Uri $url -Headers @{ "User-Agent" = "forgemax-installer" }
        return $response.tag_name -replace "^v", ""
    }
    catch {
        Write-Err "Failed to fetch latest version: $_"
        Write-Err "Try: cargo install forge-cli"
        exit 1
    }
}

function Install-Forgemax {
    Write-Info "Detecting platform..."

    $arch = if ([System.Environment]::Is64BitOperatingSystem) { "x86_64" } else {
        Write-Err "Unsupported architecture (32-bit)"
        exit 1
    }

    Write-Info "Platform: windows-$arch"

    $version = if ($env:FORGEMAX_VERSION) {
        Write-Info "Using specified version: v$($env:FORGEMAX_VERSION)"
        $env:FORGEMAX_VERSION
    }
    else {
        Write-Info "Fetching latest version..."
        $v = Get-LatestVersion
        Write-Info "Latest version: v$v"
        $v
    }

    $archiveUrl = "https://github.com/$Repo/releases/download/v$version/forgemax-v$version-windows-$arch.zip"
    $tempFile = Join-Path $env:TEMP "forgemax-$([guid]::NewGuid()).zip"

    Write-Info "Downloading $archiveUrl..."
    try {
        Invoke-WebRequest -Uri $archiveUrl -OutFile $tempFile -UseBasicParsing
    }
    catch {
        Write-Err "Download failed: $_"
        Write-Err "Try: cargo install forge-cli"
        exit 1
    }

    Write-Info "Installing to $InstallDir..."
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

    try {
        Expand-Archive -Path $tempFile -DestinationPath $InstallDir -Force
    }
    finally {
        Remove-Item -Force -Path $tempFile -ErrorAction SilentlyContinue
    }

    # Verify
    $binaryPath = Join-Path $InstallDir $BinaryName
    if (Test-Path $binaryPath) {
        try {
            $versionOutput = & $binaryPath --version 2>&1
            Write-Info "Installed: $versionOutput"
        }
        catch {
            Write-Warn "Installed but version check failed"
        }
    }
    else {
        Write-Err "Binary not found after extraction: $binaryPath"
        exit 1
    }

    # Check worker
    $workerPath = Join-Path $InstallDir $WorkerName
    if (-not (Test-Path $workerPath)) {
        Write-Warn "forgemax-worker.exe not found in archive"
    }

    # Add to PATH if not already there
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$InstallDir*") {
        Write-Info "Adding $InstallDir to user PATH..."
        [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$userPath", "User")
        $env:Path = "$InstallDir;$env:Path"
        Write-Info "PATH updated. Restart your terminal for changes to take effect."
    }

    Write-Info ""
    Write-Info "Quick start:"
    Write-Host ""
    Write-Host "  1. Download forge.toml.example from the GitHub repo"
    Write-Host "     and configure your tokens"
    Write-Host ""
    Write-Host "  2. Configure your MCP client:"
    Write-Host ""
    Write-Host "     Claude Desktop (%APPDATA%\Claude\claude_desktop_config.json):"
    Write-Host '     { "mcpServers": { "forge": { "command": "forgemax" } } }'
    Write-Host ""
    Write-Host "     VS Code / Cursor (.mcp.json):"
    Write-Host '     { "servers": { "forge": { "command": "forgemax", "type": "stdio" } } }'
    Write-Host ""
}

Install-Forgemax
