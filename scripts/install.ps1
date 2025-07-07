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

# Check for Microsoft C++ Build Tools and try to install them if missing
function Ensure-BuildTools {
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        Write-Warning "Microsoft C++ Build Tools not found. Some packages may fail to build."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Info "Attempting to install Microsoft C++ Build Tools via winget..."
            try {
                winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget -h
            } catch {
                Write-Warning "Failed to install Build Tools via winget. Please install them manually from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            }
        } else {
            Write-Warning "Winget is not available. Please install Build Tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        }
        if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
            Write-Warning "Microsoft C++ Build Tools still not found. Dependency installation may fail."
        }
    } else {
        Write-Info "Microsoft C++ Build Tools found."
    }
}

# --- Main Script ---

# 1. Check for prerequisites
Write-Info "Installing SeedPass from branch: '$Branch'"
Write-Info "Checking for prerequisites..."
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Warning "Git is not installed. Attempting to install..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try { winget install --id Git.Git -e --source winget -h } catch { Write-Error "Failed to install Git via winget. Error: $_" }
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        try { choco install git -y } catch { Write-Error "Failed to install Git via Chocolatey. Error: $_" }
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        try { scoop install git } catch { Write-Error "Failed to install Git via Scoop. Error: $_" }
    } else {
        Write-Error "Git is not installed. Please install it from https://git-scm.com/ and ensure it's in your PATH."
    }
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
        # Refresh PATH from machine and user environment in case the installer updated it
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                     [System.Environment]::GetEnvironmentVariable('Path','User')
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            # Fallback to common install locations if PATH isn't updated for this session
            $possibleGit = @(
                Join-Path $env:ProgramFiles 'Git\cmd\git.exe'
                Join-Path $env:ProgramFiles 'Git\bin\git.exe'
                Join-Path ${env:ProgramFiles(x86)} 'Git\cmd\git.exe'
                Join-Path ${env:ProgramFiles(x86)} 'Git\bin\git.exe'
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($possibleGit) { $env:Path = "$(Split-Path $possibleGit);$env:Path" }
        }
        if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
            Write-Error "Git installation succeeded but git not found in PATH. Please open a new terminal or add Git to PATH manually."
        }
    }
}
$pythonExe = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonExe) {
    Write-Warning "Python 3 is not installed. Attempting to install..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try { winget install --id Python.Python.3 -e --source winget -h } catch { Write-Warning "Failed to install Python via winget." }
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        try { choco install python -y } catch { Write-Warning "Failed to install Python via Chocolatey." }
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        try { scoop install python } catch { Write-Warning "Failed to install Python via Scoop." }
    } else {
        Write-Error "Python 3 is not installed. Please install it from https://www.python.org/ and ensure it's in your PATH."
    }
    if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
        $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                     [System.Environment]::GetEnvironmentVariable('Path','User')
        if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
            Write-Error "Python installation succeeded but python not found in PATH. Please open a new terminal or add Python to PATH manually."
        }
    }
}

# Warn about unsupported Python versions
$pyVersionString = (& python --version) -replace '[^0-9\.]', ''
try { $pyVersion = [version]$pyVersionString } catch { $pyVersion = $null }
if ($pyVersion -and $pyVersion.Major -eq 3 -and $pyVersion.Minor -ge 13) {
    Write-Warning "Python $pyVersionString detected. Some dependencies may not have prebuilt wheels yet."
    Write-Warning "If installation fails, install Python 3.11 or 3.12 or ensure Microsoft C++ Build Tools are available."
}

# Ensure C++ build tools are available before installing dependencies
Ensure-BuildTools

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
& "$VenvDir\Scripts\python.exe" -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to upgrade pip"
}

& "$VenvDir\Scripts\python.exe" -m pip install -r "src\requirements.txt"
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Failed to install Python dependencies. If errors mention C++, install Microsoft C++ Build Tools: https://visualstudio.microsoft.com/visual-cpp-build-tools/"
    Write-Error "Dependency installation failed."
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
