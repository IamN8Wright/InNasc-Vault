$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $PSScriptRoot
$workspaceRoot = Split-Path -Parent $projectRoot
$package = Get-Content -Raw -LiteralPath (Join-Path $projectRoot 'package.json') | ConvertFrom-Json
$archiveName = "InNasc_Vault_Windows_$($package.version).zip"
$archivePath = Join-Path $workspaceRoot $archiveName
$checksumPath = "$archivePath.sha256.txt"

if (Test-Path -LiteralPath $archivePath) {
    throw "Package already exists: $archivePath"
}

$temporaryRoot = Join-Path ([IO.Path]::GetTempPath()) ("InNascVaultPackage-" + [guid]::NewGuid().ToString('N'))
$stagedProject = Join-Path $temporaryRoot 'InNasc_Vault'

try {
    New-Item -ItemType Directory -Path $stagedProject -Force | Out-Null

    $excludedDirectories = @(
        'node_modules',
        'data',
        '.next',
        '.vinext',
        '.wrangler'
    )
    $excludedFiles = @(
        '.local-build-stamp',
        'tsconfig.tsbuildinfo'
    )

    $copyArguments = @(
        $projectRoot,
        $stagedProject,
        '/E',
        '/NFL',
        '/NDL',
        '/NJH',
        '/NJS',
        '/NP',
        '/XD'
    ) + $excludedDirectories + @('/XF') + $excludedFiles

    & robocopy.exe @copyArguments | Out-Null
    if ($LASTEXITCODE -gt 7) {
        throw "Packaging copy failed with robocopy exit code $LASTEXITCODE."
    }

    Compress-Archive -LiteralPath $stagedProject -DestinationPath $archivePath -CompressionLevel Optimal
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $archivePath
    "$($hash.Hash)  $archiveName" | Set-Content -LiteralPath $checksumPath -Encoding ascii

    Write-Host "Created: $archivePath" -ForegroundColor Green
    Write-Host "SHA-256: $($hash.Hash)" -ForegroundColor Green
} finally {
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    $resolvedSystemTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if ($resolvedTemporaryRoot.StartsWith($resolvedSystemTemp, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith('InNascVaultPackage-', [StringComparison]::Ordinal)) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
}
