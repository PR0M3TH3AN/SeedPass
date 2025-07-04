#
# SeedPass Universal Installer for Windows
#
# Supports installing from a specific branch using the -Branch parameter.
# Example: .\install.ps1 -Branch beta

param(
    [string]$Branch = "main" # The git branch to install from
)

# --- Configuration ---
$RepoUrl = "https://github.com/PR0M3TH3AN/SeedPass.git"
$AppRootDir = Join-Path $env:USERPROFILE ".seedpass"
$InstallDir = Join-Path $AppRootDir "app"
$VenvDir = Join-Path $InstallDir "venv"
$LauncherDir = Join-Path $InstallDir "bin"
$LauncherName = "seedpass.cmd"

# --- Helper Functions ---
function Write-Info { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[SUCCESS] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARNING] $Message" -ForegroundColor Yellow }
function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit 1
}

# --- Main Script ---

# 1. Check for prerequisites
Write-Info "Installing SeedPass from branch: '$Branch'"
Write-Info "Checking for prerequisites..."
if (-not (Get-Command git -ErrorAction SilentlyContinue)) { Write-Error "Git is not installed. Please install it from https://git-scm.com/ and ensure it's in your PATH." }
$pythonExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonExe) { Write-Error "Python 3 is not installed or not in your PATH. Please install it from https://www.python.org/" }

# 2. Clone or update the repository
if (Test-Path (Join-Path $InstallDir ".git")) {
    Write-Info "SeedPass directory found. Fetching updates and switching to '$Branch' branch..."
    try {
        Set-Location $InstallDir
        git fetch origin
        git checkout $Branch
        git pull origin $Branch --ff-only
    } catch { Write-Error "Failed to update repository. Error: $_" }
} else {
    Write-Info "Cloning SeedPass '$Branch' branch..."
    try {
        if (-not(Test-Path $AppRootDir)) { New-Item -ItemType Directory -Path $AppRootDir | Out-Null }
        git clone --branch $Branch $RepoUrl $InstallDir
        Set-Location $InstallDir
    } catch { Write-Error "Failed to clone repository. Error: $_" }
}

# 3. Set up Python virtual environment
Write-Info "Setting up Python virtual environment..."
if (-not (Test-Path $VenvDir)) {
    try { python -m venv $VenvDir } catch { Write-Error "Failed to create virtual environment. Error: $_" }
}

# 4. Install/Update Python dependencies
Write-Info "Installing/updating Python dependencies..."
try {
    & "$VenvDir\Scripts\pip.exe" install --upgrade pip
    & "$VenvDir\Scripts\pip.exe" install -r "src\requirements.txt"
} catch {
    Write-Warning "Failed to install Python dependencies. If errors mention C++, install Microsoft C++ Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    Write-Error "Dependency installation failed. Error: $_"
}

# 5. Create launcher script
Write-Info "Creating launcher script..."
if (-not (Test-Path $LauncherDir)) { New-Item -ItemType Directory -Path $LauncherDir | Out-Null }
$LauncherPath = Join-Path $LauncherDir $LauncherName
$LauncherContent = @"
@echo off
setlocal
call "%~dp0..\venv\Scripts\activate.bat"
python "%~dp0..\src\main.py" %*
endlocal
"@
Set-Content -Path $LauncherPath -Value $LauncherContent -Force

# 6. Add launcher directory to User's PATH if needed
Write-Info "Checking if '$LauncherDir' is in your PATH..."
$UserPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
if (($UserPath -split ';') -notcontains $LauncherDir) {
    Write-Info "Adding '$LauncherDir' to your user PATH."
    $NewPath = "$LauncherDir;$UserPath".Trim(";")
    [System.Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    Write-Warning "PATH has been updated. You MUST open a new terminal for the 'seedpass' command to be available."
} else {
    Write-Info "'$LauncherDir' is already in your user PATH."
}

Write-Success "Installation/update complete!"
Write-Info "To run the application, please open a NEW terminal window and type: seedpass"
