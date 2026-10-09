$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../install.ps1')

function Assert-Throws {
    param([scriptblock]$Action, [string]$Expected)
    try { & $Action } catch {
        if ($_.Exception.Message -notlike "*$Expected*") { throw "Unexpected failure: $_" }
        return
    }
    throw "Expected failure containing: $Expected"
}
function Assert-Equal {
    param($Actual, $Expected)
    if ($Actual -cne $Expected) { throw "Expected '$Expected', got '$Actual'" }
}

$root = Join-Path ([IO.Path]::GetTempPath()) "forgemax test's $([guid]::NewGuid())"
New-Item -ItemType Directory -Path $root | Out-Null
try {
    $archivePath = Join-Path $root 'release.zip'
    [IO.File]::WriteAllText($archivePath, 'verified archive fixture')
    $hash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
    $archiveName = 'forgemax-v1.2.3-windows-x86_64.zip'
    $script:checksumFixture = "$hash  $archiveName`n"
    $script:downloadFails = $false
    function Get-ReleaseAsset {
        param([string]$Url, [string]$Destination)
        if ($script:downloadFails) { throw 'offline' }
        [IO.File]::WriteAllText($Destination, $script:checksumFixture)
    }
    Verify-Checksum -ArchivePath $archivePath -Version '1.2.3' -ArchiveName $archiveName
    $script:checksumFixture = "$hash *$archiveName`r`n"
    Verify-Checksum -ArchivePath $archivePath -Version '1.2.3' -ArchiveName $archiveName
    foreach ($invalid in @('', "$hash  $archiveName.old`n", "invalid  $archiveName`n", "$hash  $archiveName`n$hash  $archiveName`n")) {
        $script:checksumFixture = $invalid
        Assert-Throws { Verify-Checksum $archivePath '1.2.3' $archiveName } 'exactly one valid SHA256'
    }
    $script:checksumFixture = "$('0' * 64)  $archiveName`n"
    Assert-Throws { Verify-Checksum $archivePath '1.2.3' $archiveName } 'SHA256 mismatch'
    $script:downloadFails = $true
    Assert-Throws { Verify-Checksum $archivePath '1.2.3' $archiveName } 'offline'

    Add-Type -AssemblyName System.IO.Compression.FileSystem
    Remove-Item -LiteralPath $archivePath
    $zip = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($name in @('forgemax.exe', 'forgemax-worker.exe', 'forge.toml.example')) {
            $entry = $zip.CreateEntry($name)
            $writer = [IO.StreamWriter]::new($entry.Open())
            try { $writer.Write("fixture $name") } finally { $writer.Dispose() }
        }
    } finally { $zip.Dispose() }
    $destination = Join-Path $root 'extracted'
    New-Item -ItemType Directory -Path $destination | Out-Null
    Expand-ReleaseBinaries -ArchivePath $archivePath -Destination $destination
    Assert-Equal (Get-ChildItem -LiteralPath $destination).Count 2
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $destination 'forgemax.exe'))) 'fixture forgemax.exe'
    Assert-Equal ([IO.File]::ReadAllText((Join-Path $destination 'forgemax-worker.exe'))) 'fixture forgemax-worker.exe'

    $zip = [IO.Compression.ZipFile]::Open($archivePath, [IO.Compression.ZipArchiveMode]::Update)
    try { $zip.GetEntry('forgemax-worker.exe').Delete() } finally { $zip.Dispose() }
    Remove-Item -LiteralPath $destination -Recurse
    New-Item -ItemType Directory -Path $destination | Out-Null
    Assert-Throws { Expand-ReleaseBinaries -ArchivePath $archivePath -Destination $destination } 'one nonempty forgemax-worker.exe'
    function Move-Item {
        param([string]$LiteralPath, [string]$Destination, [switch]$Force)
        if ($script:publicationCase -in @('worker-busy', 'rollback-busy')) {
            if ([IO.Path]::GetFileName($LiteralPath) -eq $WorkerName -and [IO.Path]::GetFileName((Split-Path $LiteralPath -Parent)) -ne 'previous') {
                # Simulate a failed overwrite after the old destination was removed.
                Remove-Item -LiteralPath $Destination -Force
                throw 'worker is busy'
            }
            if ($script:publicationCase -eq 'rollback-busy' -and [IO.Path]::GetFileName($LiteralPath) -eq $BinaryName -and [IO.Path]::GetFileName((Split-Path $LiteralPath -Parent)) -eq 'previous') {
                throw 'restoration is busy'
            }
        }
        Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    }
    try {
        foreach ($case in @('fresh', 'success', 'worker-busy', 'rollback-busy', 'directory')) {
            $script:publicationCase = $case
            $source = Join-Path $root "$case-source"
            $installed = Join-Path $root "$case-installed"
            New-Item -ItemType Directory -Path $source, $installed | Out-Null
            foreach ($name in @($BinaryName, $WorkerName)) {
                [IO.File]::WriteAllText((Join-Path $source $name), "new $name")
                if ($case -ne 'fresh') { [IO.File]::WriteAllText((Join-Path $installed $name), "old $name") }
            }
            $preserve = $false
            if ($case -eq 'directory') {
                Remove-Item -LiteralPath (Join-Path $installed $WorkerName)
                New-Item -ItemType Directory -Path (Join-Path $installed $WorkerName) | Out-Null
                Assert-Throws { Publish-ReleaseBinaries $source $installed ([ref]$preserve) } 'must be a regular file'
                Assert-Equal ([IO.File]::ReadAllText((Join-Path $installed $BinaryName))) "old $BinaryName"
            }
            elseif ($case -in @('fresh', 'success')) {
                Publish-ReleaseBinaries $source $installed ([ref]$preserve)
                foreach ($name in @($BinaryName, $WorkerName)) {
                    Assert-Equal ([IO.File]::ReadAllText((Join-Path $installed $name))) "new $name"
                }
            }
            elseif ($case -eq 'worker-busy') {
                Assert-Throws { Publish-ReleaseBinaries $source $installed ([ref]$preserve) } 'worker is busy'
                foreach ($name in @($BinaryName, $WorkerName)) {
                    Assert-Equal ([IO.File]::ReadAllText((Join-Path $installed $name))) "old $name"
                }
                Assert-Equal $preserve $false
            }
            else {
                Assert-Throws { Publish-ReleaseBinaries $source $installed ([ref]$preserve) } 'rollback incomplete, backups preserved'
                Assert-Equal $preserve $true
                Assert-Equal ([IO.File]::ReadAllText((Join-Path (Join-Path $source 'previous') $BinaryName))) "old $BinaryName"
                Assert-Equal ([IO.File]::ReadAllText((Join-Path $installed $WorkerName))) "old $WorkerName"
            }
        }
    }
    finally { Remove-Item Function:\Move-Item }
    Write-Host 'PowerShell installer: checksums, extraction, publication, rollback, recovery backups, and destination checks passed.'
}
finally { Remove-Item -LiteralPath $root -Recurse -Force }
