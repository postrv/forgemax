# Forgemax installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/postrv/forgemax/main/install.ps1 | iex

$ErrorActionPreference = "Stop"
$Repo = "postrv/forgemax"
$InstallDir = if ($env:FORGEMAX_INSTALL_DIR) { $env:FORGEMAX_INSTALL_DIR } else { "$env:LOCALAPPDATA\Programs\forgemax" }
$BinaryName = "forgemax.exe"
$WorkerName = "forgemax-worker.exe"

function Write-Info { param($Message) Write-Host "info  " -ForegroundColor Green -NoNewline; Write-Host $Message }
function Write-Warn { param($Message) Write-Host "warn  " -ForegroundColor Yellow -NoNewline; Write-Host $Message }

function Get-ReleaseAsset {
    param([string]$Url, [string]$Destination)
    Add-Type -AssemblyName System.Net.Http
    $handler = [Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(300)
    $client.MaxResponseContentBufferSize = 268435456
    $client.DefaultRequestHeaders.UserAgent.ParseAdd("forgemax-installer")
    try {
        $uri = [uri]$Url
        for ($redirect = 0; $redirect -le 5; $redirect++) {
            if ($uri.Scheme -ne 'https') { throw 'Installer downloads require HTTPS' }
            $response = $client.GetAsync($uri).GetAwaiter().GetResult()
            try {
                if ([int]$response.StatusCode -in @(301, 302, 303, 307, 308)) {
                    if (-not $response.Headers.Location) { throw 'Redirect has no destination' }
                    $uri = [uri]::new($uri, $response.Headers.Location)
                    continue
                }
                $response.EnsureSuccessStatusCode() | Out-Null
                $bytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
                [IO.File]::WriteAllBytes($Destination, $bytes)
                return
            }
            finally { $response.Dispose() }
        }
        throw 'Too many download redirects'
    }
    finally { $client.Dispose() }
}

function Verify-Checksum {
    param([string]$ArchivePath, [string]$Version, [string]$ArchiveName)
    $checksumPath = Join-Path (Split-Path $ArchivePath -Parent) 'SHA256SUMS.txt'
    Get-ReleaseAsset -Url "https://github.com/$Repo/releases/download/v$Version/SHA256SUMS.txt" -Destination $checksumPath
    $checksums = @(foreach ($line in [IO.File]::ReadAllLines($checksumPath)) {
        if ($line -cmatch '^([0-9a-fA-F]{64})[ \t]+\*?([^\r\n]+)$') {
            if ($Matches[2] -ceq $ArchiveName) { $Matches[1].ToLowerInvariant() }
        }
    })
    if ($checksums.Count -ne 1) { throw "Expected exactly one valid SHA256 checksum for $ArchiveName" }
    $actual = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($checksums[0] -ne $actual) { throw "SHA256 mismatch for $ArchiveName" }
    Write-Info 'SHA256 verified'
}

function Expand-ReleaseBinaries {
    param([string]$ArchivePath, [string]$Destination)
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        foreach ($name in @($BinaryName, $WorkerName)) {
            $entries = @($zip.Entries | Where-Object { $_.FullName -ceq $name -or $_.FullName -ceq "./$name" })
            if ($entries.Count -ne 1 -or $entries[0].Length -eq 0) { throw "Archive must contain one nonempty $name" }
            if ($entries[0].Length -gt 268435456) { throw 'Binary exceeds size limit' }
            # Only these exact files are copied; archive paths and metadata are
            # never used to choose a filesystem destination.
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], (Join-Path $Destination $name))
        }
    }
    finally { $zip.Dispose() }
}

function Publish-ReleaseBinaries {
    param([string]$SourceDirectory, [string]$Destination, [ref]$PreserveStaging)
    New-Item -ItemType Directory -Force -Path $Destination | Out-Null
    $directory = Get-Item -LiteralPath $Destination -Force
    if (-not $directory.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Binary destination must be a directory, not a link'
    }
    $backupDir = Join-Path $SourceDirectory 'previous'
    New-Item -ItemType Directory -Path $backupDir | Out-Null
    $originals = [Collections.Generic.List[string]]::new()
    foreach ($name in @($BinaryName, $WorkerName)) {
        $target = Join-Path $Destination $name
        $existing = $null
        try { $existing = Get-Item -LiteralPath $target -Force -ErrorAction Stop }
        catch [System.Management.Automation.ItemNotFoundException] { }
        if ($null -ne $existing) {
            if ($existing -isnot [IO.FileInfo] -or ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw "Existing $name must be a regular file"
            }
            [IO.File]::Copy($target, (Join-Path $backupDir $name))
            $originals.Add($name)
        }
    }
    $installed = [Collections.Generic.List[string]]::new()
    try {
        foreach ($name in @($BinaryName, $WorkerName)) {
            # PowerShell may remove an existing destination before a forced
            # move fails. Include the attempted file in rollback as well.
            $installed.Add($name)
            Move-Item -LiteralPath (Join-Path $SourceDirectory $name) -Destination (Join-Path $Destination $name) -Force
        }
    }
    catch {
        $installError = $_
        $rollbackErrors = [Collections.Generic.List[string]]::new()
        for ($index = $installed.Count - 1; $index -ge 0; $index--) {
            $name = $installed[$index]
            try {
                if ($originals.Contains($name)) {
                    Move-Item -LiteralPath (Join-Path $backupDir $name) -Destination (Join-Path $Destination $name) -Force
                }
                elseif (Test-Path -LiteralPath (Join-Path $Destination $name)) {
                    Remove-Item -LiteralPath (Join-Path $Destination $name) -Force
                }
            }
            catch { $rollbackErrors.Add($_.Exception.Message) }
        }
        if ($rollbackErrors.Count -gt 0) {
            $PreserveStaging.Value = $true
            throw "$($installError.Exception.Message); rollback incomplete, backups preserved at ${backupDir}: $($rollbackErrors -join '; ')"
        }
        throw $installError
    }
}

function Install-Forgemax {
    if (-not [Environment]::Is64BitOperatingSystem) { throw 'Unsupported architecture (32-bit)' }
    $arch = 'x86_64'
    Write-Info "Platform: windows-$arch"
    $tempDir = Join-Path ([IO.Path]::GetTempPath()) "forgemax-$([guid]::NewGuid())"
    New-Item -ItemType Directory -Path $tempDir | Out-Null
    $preserveStaging = $false
    try {
        $version = $env:FORGEMAX_VERSION
        if (-not $version) {
            $metadataPath = Join-Path $tempDir 'latest.json'
            Get-ReleaseAsset -Url "https://api.github.com/repos/$Repo/releases/latest" -Destination $metadataPath
            $metadata = [IO.File]::ReadAllText($metadataPath) | ConvertFrom-Json
            $version = $metadata.tag_name -replace '^v', ''
        }
        if ($version -cnotmatch '^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$') {
            throw "Invalid release version: $version"
        }
        $archiveName = "forgemax-v$version-windows-$arch.zip"
        $archivePath = Join-Path $tempDir 'release.zip'
        Write-Info "Downloading forgemax v$version..."
        Get-ReleaseAsset -Url "https://github.com/$Repo/releases/download/v$version/$archiveName" -Destination $archivePath
        Verify-Checksum -ArchivePath $archivePath -Version $version -ArchiveName $archiveName
        Expand-ReleaseBinaries -ArchivePath $archivePath -Destination $tempDir

        $versionOutput = & (Join-Path $tempDir $BinaryName) --version
        if ($LASTEXITCODE -ne 0 -or $versionOutput -cne "forgemax $version") {
            throw 'Downloaded binary version does not match the requested release'
        }
        Publish-ReleaseBinaries -SourceDirectory $tempDir -Destination $InstallDir -PreserveStaging ([ref]$preserveStaging)
        Write-Info "Installed: $versionOutput"
    }
    finally {
        if (-not $preserveStaging) { Remove-Item -LiteralPath $tempDir -Recurse -Force }
    }

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', "$InstallDir;$userPath", 'User')
        $env:Path = "$InstallDir;$env:Path"
        Write-Info 'PATH updated. Restart your terminal for changes to take effect.'
    }
    Write-Info 'Copy forge.toml.example to forge.toml, configure your tokens, and add forgemax to your MCP client.'
}

# Dot-sourcing exposes helpers for offline verification without installing.
if ($MyInvocation.InvocationName -ne '.') { Install-Forgemax }
