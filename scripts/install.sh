#!/bin/bash
#
# SeedPass Universal Installer for Linux and macOS
#
# Supports installing from a specific branch using the -b or --branch flag.
# Example: ./install.sh -b beta

set -e

# --- Configuration ---
REPO_URL="https://github.com/PR0M3TH3AN/SeedPass.git"
APP_ROOT_DIR="$HOME/.seedpass"
INSTALL_DIR="$APP_ROOT_DIR/app"
VENV_DIR="$INSTALL_DIR/venv"
LAUNCHER_DIR="$HOME/.local/bin"
LAUNCHER_PATH="$LAUNCHER_DIR/seedpass"
BRANCH="main" # Default branch
HEADLESS_MODE="${SEEDPASS_HEADLESS:-}"
SKIP_GUI=0

is_truthy() {
    case "$1" in
        1|y|Y|yes|Yes|YES|true|True|TRUE|on|On|ON|enable|Enable|enabled|Enabled)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# --- Helper Functions ---
print_info() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }
print_error() { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; exit 1; }

run_with_privilege() {
    if [ "$EUID" -eq 0 ]; then
        "$@"
    elif command -v sudo &>/dev/null; then
        sudo "$@"
    else
        print_error "Elevated privileges are required to install system packages, but 'sudo' was not found."
    fi
}

check_pkg_config_cairo() {
    if ! command -v pkg-config >/dev/null 2>&1; then
        return 1
    fi
    pkg-config --exists cairo gobject-2.0 >/dev/null 2>&1
}

check_python_has_gtk() {
    python3 - <<'PY' >/dev/null 2>&1
import sys
try:
    import gi
    gi.require_version('Gtk', '3.0')
    from gi.repository import Gtk  # noqa: F401
    import cairo  # noqa: F401
except Exception:
    sys.exit(1)
PY
}
    if ! check_pkg_config_cairo; then
+        run_with_privilege updatedb >/dev/null 2>&1 || true
+        if command -v locate >/dev/null 2>&1; then
+            CAIRO_PC_PATH=$(locate -n 1 "cairo.pc" 2>/dev/null || true)
+            if [ -n "$CAIRO_PC_PATH" ]; then
+                export PKG_CONFIG_PATH="$(dirname "$CAIRO_PC_PATH"):${PKG_CONFIG_PATH:-}"
+            fi
+        fi
+    fi
+
+    if ! check_pkg_config_cairo; then
         print_error "Cairo/GObject development files are still missing (pkg-config cannot locate 'cairo' and 'gobject-2.0')."
     fi
 }


ensure_linux_gui_prereqs() {
    if command -v pkg-config &>/dev/null && pkg-config --exists cairo gobject-2.0 >/dev/null 2>&1; then
        print_info "Cairo/GObject development libraries detected."
        return 0
    fi

    print_info "Installing system packages required for Gtk/pycairo (this may prompt for your password)..."

    if command -v apt-get &>/dev/null; then
        run_with_privilege apt-get update
        run_with_privilege env DEBIAN_FRONTEND=noninteractive apt-get install -y \
            build-essential pkg-config python3-dev python3-venv python3-gi \
            libgirepository-2.0-dev libcairo2-dev gir1.2-gtk-3.0 \
            libcanberra-gtk3-module gobject-introspection
    elif command -v dnf &>/dev/null; then
        run_with_privilege dnf groupinstall -y "Development Tools"
        run_with_privilege dnf install -y \
            gcc make pkgconf-pkg-config python3-devel python3-gobject \
            gobject-introspection-devel cairo-devel cairo-gobject-devel \
            gtk3 libcanberra-gtk3
    elif command -v yum &>/dev/null; then
        run_with_privilege yum groupinstall -y "Development Tools"
        run_with_privilege yum install -y \
            cairo cairo-devel gobject-introspection-devel gtk3-devel \
            python3-devel python3-gobject pkgconf-pkg-config libcanberra-gtk3
    elif command -v pacman &>/dev/null; then
        run_with_privilege pacman -Syu --noconfirm --needed \
            base-devel pkgconf python python-pip python-gobject \
            cairo gobject-introspection gtk3 libcanberra
    elif command -v zypper &>/dev/null; then
        run_with_privilege zypper install -y -t pattern devel_basis || true
        run_with_privilege zypper install -y \
            pkgconf-pkg-config python3-devel python3-gobject gobject-introspection-devel \
            cairo-devel gtk3 'typelib(Gtk)=3.0' libcanberra-gtk3-module
    elif command -v apk &>/dev/null; then
        run_with_privilege apk add --no-cache \
            build-base pkgconf python3-dev py3-gobject3 \
            gobject-introspection-dev cairo-dev gtk+3.0-dev
    elif command -v brew &>/dev/null; then
        brew install pkg-config cairo gobject-introspection gtk+3 pygobject3
    else
        print_warning "Unsupported package manager. Please install cairo/GTK development libraries manually."
    fi

    if ! check_pkg_config_cairo; then
        print_error "Cairo/GObject development files are still missing (pkg-config cannot locate 'cairo' and 'gobject-2.0')."
    fi
}
usage() {
    echo "Usage: $0 [-b | --branch <branch_name>] [-h | --help]"
    echo "  -b, --branch   Specify the git branch to install (default: main)"
    echo "  -h, --help     Display this help message"
    exit 0
}

# --- Main Script ---
main() {
    # Parse command-line arguments
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            -b|--branch)
                if [ -n "$2" ]; then
                    BRANCH="$2"
                    shift 2
                else
                    print_error "Error: --branch requires a non-empty option argument."
                fi
                ;;
            -h|--help)
                usage
                ;;
            *)
                print_error "Unknown parameter passed: $1"; usage
                ;;
        esac
    done

    # 1. Detect OS
    OS_NAME=$(uname -s)
    print_info "Installing SeedPass from branch: '$BRANCH'"
    print_info "Detected Operating System: $OS_NAME"

    # 2. Check for prerequisites
    print_info "Checking for prerequisites (git, python3, pip)..."
    if ! command -v git &> /dev/null; then
        print_warning "Git is not installed. Attempting to install..."
        if [ "$OS_NAME" = "Linux" ]; then
            if command -v apt-get &> /dev/null; then sudo apt-get update && sudo apt-get install -y git;
            elif command -v dnf &> /dev/null; then sudo dnf install -y git;
            elif command -v pacman &> /dev/null; then sudo pacman -Syu --noconfirm git;
            else print_error "Git is not installed and automatic installation is not supported on this system."; fi
        elif [ "$OS_NAME" = "Darwin" ]; then
            if command -v brew &> /dev/null; then brew install git;
            else print_error "Git is not installed and Homebrew was not found. Please install Git manually."; fi
        else
            print_error "Git is not installed. Please install it."
        fi
        if ! command -v git &> /dev/null; then print_error "Git installation failed or git not found in PATH."; fi
    fi
    if ! command -v python3 &> /dev/null; then print_error "Python 3 is not installed. Please install it."; fi
    if ! python3 -m ensurepip --default-pip &> /dev/null && ! command -v pip3 &> /dev/null; then print_error "pip for Python 3 is not available. Please install it."; fi
    if ! python3 -c "import venv" &> /dev/null; then
        print_warning "Python 'venv' module not found. Attempting to install..."
        if [ "$OS_NAME" = "Linux" ]; then
            if command -v apt-get &> /dev/null; then sudo apt-get update && sudo apt-get install -y python3-venv;
            elif command -v dnf &> /dev/null; then sudo dnf install -y python3-virtualenv;
            else print_error "Could not auto-install python3-venv. Please install it for your distribution."; fi
        else print_error "Python 'venv' module is missing."; fi
    fi

    # 3. Install OS-specific dependencies
    if [ "$OS_NAME" = "Linux" ]; then
        else
            print_info "Checking for Gtk/cairo development libraries..."
            if check_pkg_config_cairo && check_python_has_gtk; then
                print_info "Gtk/cairo bindings already available."
            else
                print_warning "Gtk/cairo bindings not fully available. Attempting to install prerequisites..."
                ensure_linux_gui_prereqs
                if ! check_pkg_config_cairo; then
                    print_error "pkg-config could not locate 'cairo' and 'gobject-2.0' after attempting installation."
                fi
                if ! check_python_has_gtk; then
                    print_error "Gtk/cairo Python bindings are still missing after installing prerequisites."
                fi
                print_info "Gtk/cairo bindings are now available."
            fi
        fi
    fi

    # 4. Clone or update the repository
    if [ -d "$INSTALL_DIR/.git" ]; then
        print_info "SeedPass directory found. Fetching updates and switching to '$BRANCH' branch..."
        cd "$INSTALL_DIR"
        git fetch origin
        git checkout "$BRANCH"
        git pull origin "$BRANCH" --ff-only
    else
        print_info "Cloning SeedPass '$BRANCH' branch to '$INSTALL_DIR'..."
        mkdir -p "$APP_ROOT_DIR"
        git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
        cd "$INSTALL_DIR"
    fi

    # 5. Set up Python virtual environment
    print_info "Setting up Python virtual environment in '$VENV_DIR'..."
    if [ ! -d "$VENV_DIR" ]; then python3 -m venv "$VENV_DIR"; fi
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    # 6. Install/Update Python dependencies
    print_info "Installing/updating Python dependencies from src/requirements.txt..."
    pip install --upgrade pip
    pip install -r src/requirements.txt
    pip install -e .
    print_info "Installing platform-specific Toga backend..."
    if [ "$OS_NAME" = "Linux" ]; then
        if [ "$SKIP_GUI" -eq 1 ]; then
            print_info "Installing toga-dummy backend for headless Linux..."
            pip install --upgrade "toga-dummy>=0.5.2"
        else
            print_info "Installing toga-gtk for Linux..."
            pip install --upgrade "toga-gtk>=0.5.2"
        fi
    elif [ "$OS_NAME" = "Darwin" ]; then
        print_info "Installing toga-cocoa for macOS..."
        pip install --upgrade "toga-cocoa>=0.5.2"
    fi
    deactivate

    # 7. Create launcher script
    print_info "Creating launcher script at '$LAUNCHER_PATH'..."
    mkdir -p "$LAUNCHER_DIR"
cat > "$LAUNCHER_PATH" << EOF2
#!/bin/bash
source "$VENV_DIR/bin/activate"
exec "$VENV_DIR/bin/seedpass" "\$@"
EOF2
    chmod +x "$LAUNCHER_PATH"

    existing_cmd=$(command -v seedpass 2>/dev/null || true)
    if [ -n "$existing_cmd" ] && [ "$existing_cmd" != "$LAUNCHER_PATH" ]; then
        print_warning "Another 'seedpass' command was found at $existing_cmd."
        print_warning "Ensure '$LAUNCHER_DIR' comes first in your PATH or remove the old installation."
    fi

    # Detect any additional seedpass executables on PATH that are not our launcher
    IFS=':' read -ra _sp_paths <<< "$PATH"
    stale_cmds=()
    for _dir in "${_sp_paths[@]}"; do
        _candidate="$_dir/seedpass"
        if [ -x "$_candidate" ] && [ "$_candidate" != "$LAUNCHER_PATH" ]; then
            stale_cmds+=("$_candidate")
        fi
    done
    if [ ${#stale_cmds[@]} -gt 0 ]; then
        print_warning "Stale 'seedpass' executables detected:"
        for cmd in "${stale_cmds[@]}"; do
            print_warning "  - $cmd"
        done
        print_warning "Remove or rename these to avoid launching outdated code."
    fi

    # 8. Final instructions
    print_success "Installation/update complete!"
    print_info "You can now launch the interactive TUI by typing: seedpass"
    print_info "'seedpass' resolves to: $(command -v seedpass)"
    if [[ ":$PATH:" != *":$LAUNCHER_DIR:"* ]]; then
        print_warning "Directory '$LAUNCHER_DIR' is not in your PATH."
        print_warning "Please add 'export PATH=\"$HOME/.local/bin:$PATH\"' to your shell's config file (e.g., ~/.bashrc, ~/.zshrc) and restart your terminal."
    fi
}

main "$@"
