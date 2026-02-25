param(
    [string]$Branch = "beta",
    [ValidateSet("tui", "gui", "both")]
    [string]$Mode = "tui"
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required for installer smoke test"
}

$TempHome = Join-Path $env:RUNNER_TEMP ("seedpass-installer-home-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempHome -Force | Out-Null

try {
    $env:USERPROFILE = $TempHome
    $env:HOME = $TempHome

    Write-Host "[INFO] Smoke install start: branch=$Branch mode=$Mode home=$TempHome"

    if ($Mode -eq "tui") {
        & "$PSScriptRoot\install.ps1" -Branch $Branch
    } else {
        & "$PSScriptRoot\install.ps1" -Branch $Branch -IncludeGui
    }

    $LauncherPath = Join-Path $env:USERPROFILE ".seedpass\app\bin\seedpass.cmd"
    $AppDir = Join-Path $env:USERPROFILE ".seedpass\app"
    if (-not (Test-Path $LauncherPath)) {
        throw "launcher missing: $LauncherPath"
    }
    if (-not (Test-Path (Join-Path $AppDir ".git"))) {
        throw "install dir missing git checkout: $AppDir"
    }

    $ActualBranch = (git -C $AppDir rev-parse --abbrev-ref HEAD).Trim()
    if ($ActualBranch -ne $Branch) {
        throw "expected branch '$Branch', got '$ActualBranch'"
    }

    cmd /c "`"$LauncherPath`" --help" | Out-Null

    Write-Host "[INFO] Re-running installer to validate idempotence"
    if ($Mode -eq "tui") {
        & "$PSScriptRoot\install.ps1" -Branch $Branch
    } else {
        & "$PSScriptRoot\install.ps1" -Branch $Branch -IncludeGui
    }
    cmd /c "`"$LauncherPath`" --help" | Out-Null

    Write-Host "[SUCCESS] Installer smoke test passed (branch=$Branch mode=$Mode)"
}
finally {
    if (Test-Path $TempHome) {
        Remove-Item -Recurse -Force $TempHome
    }
}
