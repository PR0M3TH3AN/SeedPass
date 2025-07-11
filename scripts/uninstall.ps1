#
# SeedPass Uninstaller for Windows
#
# Removes the SeedPass application files but preserves user data under ~/.seedpass

$AppRootDir = Join-Path $env:USERPROFILE ".seedpass"
$InstallDir = Join-Path $AppRootDir "app"
$LauncherDir = Join-Path $InstallDir "bin"
$LauncherName = "seedpass.cmd"

function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[ERROR] $Message" -ForegroundColor Red }

Write-Info "Removing SeedPass installation..."

if (Test-Path $InstallDir) {
    Remove-Item -Recurse -Force $InstallDir
    Write-Info "Deleted '$InstallDir'"
} else {
    Write-Info "Installation directory not found."
}

$LauncherPath = Join-Path $LauncherDir $LauncherName
if (Test-Path $LauncherPath) {
    Remove-Item -Force $LauncherPath
    Write-Info "Removed launcher '$LauncherPath'"
} else {
    Write-Info "Launcher not found."
}

Write-Info "Attempting to uninstall any global 'seedpass' package with pip..."
try {
    pip uninstall -y seedpass | Out-Null
} catch {
    try { pip3 uninstall -y seedpass | Out-Null } catch {}
}

Write-Success "SeedPass uninstalled. User data under '$AppRootDir' was left intact."

