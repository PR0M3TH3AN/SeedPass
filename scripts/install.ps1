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
function Get-ClPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        try {
            $cl = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find '**\\cl.exe' 2>$null
            if ($cl) { return $cl | Select-Object -First 1 }
        } catch {}
    }
    $common = "Microsoft Visual Studio\\2022\\BuildTools"
    $guess = @(
        Join-Path ${env:ProgramFiles(x86)} "$common\\VC\\Tools\\MSVC";
        Join-Path ${env:ProgramFiles} "$common\\VC\\Tools\\MSVC"
    ) | Where-Object { Test-Path $_ }
    foreach ($path in $guess) {
        $cl = Get-ChildItem -Path $path -Filter cl.exe -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cl) { return $cl.FullName }
    }
    return $null
}

function Ensure-BuildTools {
    $clCmd = Get-Command cl.exe -ErrorAction SilentlyContinue
    if (-not $clCmd) {
        $clPath = Get-ClPath
        if ($clPath) {
            $env:Path = "$(Split-Path $clPath);$env:Path"
            $clCmd = Get-Command cl.exe -ErrorAction SilentlyContinue
        }
    }

    if (-not $clCmd) {
        Write-Warning "Microsoft C++ Build Tools not found. Some packages may fail to build."
        if (Get-Command winget -ErrorAction SilentlyContinue) {
            Write-Info "Attempting to install Microsoft C++ Build Tools via winget..."
            try {
                winget install --id Microsoft.VisualStudio.2022.BuildTools -e --source winget -h --accept-package-agreements --accept-source-agreements
            } catch {
                Write-Warning "Failed to install Build Tools via winget. Please install them manually from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
            }
        } else {
            Write-Warning "Winget is not available. Please install Build Tools from https://visualstudio.microsoft.com/visual-cpp-build-tools/"
        }

        $clPath = Get-ClPath
        if ($clPath) {
            $env:Path = "$(Split-Path $clPath);$env:Path"
            $clCmd = Get-Command cl.exe -ErrorAction SilentlyContinue
        }

        if (-not $clCmd) {
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

# 🔧 merged conflicting changes from update-install-scripts-to-check-for-python vs main
function Get-PythonCommand {
    $cmd = Get-Command python -ErrorAction SilentlyContinue
    if ($cmd) {
        $out = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $out -match '^Python') { return ,('python') }
    }
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) {
        $out = & $cmd -3 --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $out -match '^Python') { return @('py','-3') }
    }
    return $null
}

# Try to locate a specific Python version using the `py` launcher or
# versioned executables like `python3.12`.
function Get-PythonCommandByVersion {
    param([string]$Version)
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) {
        $out = & $cmd -$Version --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $out -match '^Python') {
            return @('py', "-$Version")
        }
    }
    $cmd = Get-Command "python$Version" -ErrorAction SilentlyContinue
    if ($cmd) {
        $out = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -and $out -match '^Python') {
            return ,("python$Version")
        }
    }
    return $null
}

$PythonCmd = Get-PythonCommand
if (-not $PythonCmd) {
    Write-Warning "Python 3 is not installed. Attempting to install..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try { winget install --id Python.Python.3 -e --source winget -h } catch { Write-Warning "Failed to install Python via winget." }
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        try { choco install python -y } catch { Write-Warning "Failed to install Python via Chocolatey." }
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        try { scoop install python } catch { Write-Warning "Failed to install Python via Scoop." }
    } else {
        Write-Error "Python 3 is not installed. Download it from https://www.python.org/downloads/windows/ and ensure it's in your PATH."
    }

    # 🔧 merged conflicting changes from update-install-scripts-to-check-for-python vs main
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                 [System.Environment]::GetEnvironmentVariable('Path','User')
    $PythonCmd = Get-PythonCommand
    if (-not $PythonCmd) {
        Write-Error "Python installation failed or python not found in PATH. Download Python from https://www.python.org/downloads/windows/, install it, then reopen PowerShell and rerun this script."
    }
}

# Warn about unsupported Python versions
$pyVersionString = (& $PythonCmd --version) -replace '[^0-9\.]', ''
try { $pyVersion = [version]$pyVersionString } catch { $pyVersion = $null }
if ($pyVersion -and $pyVersion.Major -eq 3 -and $pyVersion.Minor -ge 13) {
    Write-Warning "Python $pyVersionString detected. Some dependencies may not have prebuilt wheels yet."
    Write-Warning "If installation fails, install Python 3.11 or 3.12 or ensure Microsoft C++ Build Tools are available."
}

# Ensure C++ build tools are available before installing dependencies
Ensure-BuildTools

# If build tools are still missing and Python 3.13+ is in use, try to
# install Python 3.12 automatically since many packages lack wheels for
# newer versions.
$buildOk = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $buildOk -and $pyVersion -and $pyVersion.Major -eq 3 -and $pyVersion.Minor -ge 13) {
    Write-Warning "No Microsoft C++ Build Tools detected and Python $pyVersionString is in use."
    Write-Info "Attempting to install Python 3.12 for compatibility..."
    if (Get-Command winget -ErrorAction SilentlyContinue) {
        try { winget install --id Python.Python.3.12 -e --source winget -h } catch { Write-Warning "Failed to install Python 3.12 via winget." }
    } elseif (Get-Command choco -ErrorAction SilentlyContinue) {
        try { choco install python --version=3.12 -y } catch { Write-Warning "Failed to install Python 3.12 via Chocolatey." }
    } elseif (Get-Command scoop -ErrorAction SilentlyContinue) {
        try { scoop install python@3.12 } catch { Write-Warning "Failed to install Python 3.12 via Scoop." }
    } else {
        Write-Warning "Please install Python 3.12 manually from https://www.python.org/downloads/windows/"
    }

    $env:Path = [System.Environment]::GetEnvironmentVariable('Path','Machine') + ';' +
                 [System.Environment]::GetEnvironmentVariable('Path','User')
    $py12 = Get-PythonCommandByVersion '3.12'
    if ($py12) {
        Write-Info "Using Python 3.12 for installation."
        $PythonCmd = $py12
    } else {
        Write-Warning "Python 3.12 not found after installation attempt."
    }
}

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
    try { & $PythonCmd -m venv $VenvDir } catch { Write-Error "Failed to create virtual environment. Error: $_" }
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
