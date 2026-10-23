$ErrorActionPreference = 'Stop'

$repoUrl = 'https://github.com/A-Network-2026/anet-testnet-phase3.git'
$repoPath = Join-Path $HOME 'anet-testnet-phase3'
$toolsPath = Join-Path $HOME '.anet-phase3-tools'
$vsWhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run PowerShell as Administrator to install the C++ build tools.'
}

if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    throw 'winget is required. Install App Installer from Microsoft Store, then rerun this script.'
}

foreach ($package in @('Git.Git', 'Python.Python.3.12', 'Rustlang.Rustup', 'GoLang.Go')) {
    winget install --exact --id $package --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "winget failed to install $package (exit $LASTEXITCODE)."
    }
}

$vsInstallPath = $null
if (Test-Path $vsWhere) {
    $vsInstallPath = & $vsWhere -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $vsInstallPath) {
    winget install --exact --id Microsoft.VisualStudio.2022.BuildTools `
        --override '--wait --quiet --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended' `
        --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -ne 0) {
        throw "Visual Studio Build Tools installation failed (exit $LASTEXITCODE)."
    }
    $vsInstallPath = & $vsWhere -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $vsInstallPath) {
    throw 'MSVC C++ Build Tools were not found. Rerun the installer with the C++ workload.'
}

$machinePath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
$env:Path = "$machinePath;$userPath"
. (Join-Path $vsInstallPath 'Common7\Tools\Launch-VsDevShell.ps1') `
    -Arch amd64 -HostArch amd64 -SkipAutomaticLocation | Out-Null

if (-not (Test-Path $repoPath)) {
    git clone $repoUrl $repoPath
    if ($LASTEXITCODE -ne 0) { throw 'Could not clone the Phase 3 repository.' }
} else {
    git -C $repoPath pull --ff-only
    if ($LASTEXITCODE -ne 0) { throw 'Could not fast-forward the existing testnet checkout.' }
}

New-Item -ItemType Directory -Force -Path $toolsPath | Out-Null
$cometSource = Join-Path $toolsPath 'cometbft-v0.40.0'
$cometBinary = Join-Path $toolsPath 'cometbft-0.40.0.exe'
if (-not (Test-Path $cometSource)) {
    git clone --depth 1 --branch v0.40.0 https://github.com/cometbft/cometbft.git $cometSource
    if ($LASTEXITCODE -ne 0) { throw 'Could not download the pinned CometBFT source.' }
}
$expectedCommit = '0880b4d378f347ab16e54ec677ff50d803f37d62'
$actualCommit = git -C $cometSource rev-parse HEAD
if ($actualCommit -ne $expectedCommit) {
    throw "CometBFT source mismatch: expected $expectedCommit, got $actualCommit. Remove $cometSource and rerun."
}
Push-Location $cometSource
try {
    go build -trimpath `
        -ldflags "-X github.com/cometbft/cometbft/version.TMCoreSemVer=0.40.0 -X github.com/cometbft/cometbft/version.TMGitCommitHash=$expectedCommit" `
        -o $cometBinary ./cmd/cometbft
    if ($LASTEXITCODE -ne 0) { throw 'CometBFT build failed.' }
} finally {
    Pop-Location
}

Push-Location $repoPath
try {
    cargo build --locked --features abci-testnet
    if ($LASTEXITCODE -ne 0) { throw 'ANET node build failed.' }
    Push-Location (Join-Path $repoPath 'tools/testnet-signer')
    try {
        cargo build --locked
        if ($LASTEXITCODE -ne 0) { throw 'Testnet signer build failed.' }
    } finally {
        Pop-Location
    }
} finally {
    Pop-Location
}

Write-Host ''
Write-Host 'Prerequisites installed and testnet binaries built.' -ForegroundColor Green
Write-Host "Repository: $repoPath"
Write-Host "CometBFT:   $cometBinary"
Write-Host 'No validator identity was created; no firewall rule was added; no node was started.'
Write-Host 'Next: follow the README operator steps. Never share priv_validator_key.json or node_key.json.'