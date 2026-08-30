$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

Write-Host ''
Write-Host '  InNasc Vault - local Windows launcher' -ForegroundColor Cyan
Write-Host '  Systems in context.' -ForegroundColor DarkGray
Write-Host ''

$nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
$npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $nodeCommand -or -not $npmCommand) {
    Write-Host 'Node.js is required for this local build.' -ForegroundColor Yellow
    Write-Host 'Install the current Node.js 22 LTS release from https://nodejs.org, then run this file again.'
    exit 1
}

$nodeVersionText = (& node.exe --version).TrimStart('v')
$nodeMajor = [int]($nodeVersionText.Split('.')[0])
if ($nodeMajor -lt 22) {
    Write-Host "Node.js 22 or newer is required. Installed version: $nodeVersionText" -ForegroundColor Yellow
    exit 1
}

if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'node_modules'))) {
    Write-Host 'Preparing InNasc Vault for first use. This downloads the locked application dependencies...' -ForegroundColor Cyan
    & npm.cmd ci
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$buildMarker = Join-Path $projectRoot '.local-build-stamp'
$buildRequired = -not (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\server\wrangler.json')) -or
                 -not (Test-Path -LiteralPath (Join-Path $projectRoot 'dist\local-server\index.js')) -or
                 -not (Test-Path -LiteralPath $buildMarker)

if (-not $buildRequired) {
    $markerTime = (Get-Item -LiteralPath $buildMarker).LastWriteTimeUtc
    $sourceRoots = @('app', 'components', 'hooks', 'lib', 'server', 'public')
    foreach ($sourceRoot in $sourceRoots) {
        $fullRoot = Join-Path $projectRoot $sourceRoot
        $newerSource = Get-ChildItem -LiteralPath $fullRoot -Recurse -File | Where-Object { $_.LastWriteTimeUtc -gt $markerTime } | Select-Object -First 1
        if ($newerSource) { $buildRequired = $true; break }
    }
    if ((Get-Item -LiteralPath (Join-Path $projectRoot 'package-lock.json')).LastWriteTimeUtc -gt $markerTime) { $buildRequired = $true }
}

if ($buildRequired) {
    Write-Host 'Building the verified local application...' -ForegroundColor Cyan
    & npm.cmd run build
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Set-Content -LiteralPath $buildMarker -Value (Get-Date).ToUniversalTime().ToString('O') -Encoding utf8
}

try {
    $health = Invoke-RestMethod -Uri 'http://127.0.0.1:3778/api/health' -TimeoutSec 2 -ErrorAction Stop
    $existingUi = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:3000/' -TimeoutSec 2 -ErrorAction Stop
} catch {
    $health = $null
    $existingUi = $null
}

if ($health -and $health.status -eq 'ok' -and $existingUi -and $existingUi.StatusCode -eq 200) {
    Write-Host 'InNasc Vault is already running. Opening it now...' -ForegroundColor Green
    if ($env:INNASC_NO_BROWSER -ne '1') { Start-Process 'http://localhost:3000' }
    exit 0
}

Write-Host 'Starting the encrypted local workspace...' -ForegroundColor Cyan
$apiProcess = $null
$uiProcess = $null

try {
    $nodePath = $nodeCommand.Source
    $apiScript = Join-Path $projectRoot 'dist\local-server\index.js'
    $uiScript = Join-Path $projectRoot 'node_modules\vinext\dist\cli.js'

    $apiProcess = Start-Process -FilePath $nodePath -ArgumentList @($apiScript) -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    $uiProcess = Start-Process -FilePath $nodePath -ArgumentList @($uiScript, 'start', '--port', '3000', '--hostname', '127.0.0.1') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru

    $ready = $false
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if ($apiProcess.HasExited) { throw 'The secure local service stopped before it was ready.' }
        if ($uiProcess.HasExited) { throw 'The InNasc Vault interface stopped before it was ready.' }
        try {
            $apiReady = Invoke-RestMethod -Uri 'http://127.0.0.1:3778/api/health' -TimeoutSec 2 -ErrorAction Stop
            $uiReady = Invoke-WebRequest -UseBasicParsing -Uri 'http://127.0.0.1:3000/' -TimeoutSec 2 -ErrorAction Stop
            if ($apiReady.status -eq 'ok' -and $uiReady.StatusCode -eq 200) { $ready = $true; break }
        } catch {
            Start-Sleep -Milliseconds 750
        }
    }
    if (-not $ready) { throw 'InNasc Vault did not become ready within 120 seconds.' }

    Write-Host ''
    Write-Host 'InNasc Vault is ready at http://localhost:3000' -ForegroundColor Green
    Write-Host 'Keep this window open while using the vault.' -ForegroundColor DarkGray
    Write-Host ''
    if ($env:INNASC_NO_BROWSER -ne '1') { Start-Process 'http://localhost:3000' }
    Read-Host 'Press Enter in this window when you are ready to stop InNasc Vault' | Out-Null
} finally {
    if ($null -ne $apiProcess -and -not $apiProcess.HasExited) {
        Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
    }
    if ($null -ne $uiProcess -and -not $uiProcess.HasExited) {
        Stop-Process -Id $uiProcess.Id -Force -ErrorAction SilentlyContinue
    }
}
