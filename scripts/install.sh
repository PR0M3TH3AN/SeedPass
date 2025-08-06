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

# --- Helper Functions ---
print_info() { echo -e "\033[1;34m[INFO]\033[0m $1"; }
print_success() { echo -e "\033[1;32m[SUCCESS]\033[0m $1"; }
print_warning() { echo -e "\033[1;33m[WARNING]\033[0m $1"; }
print_error() { echo -e "\033[1;31m[ERROR]\033[0m $1" >&2; exit 1; }

# Install build dependencies for Gtk/GObject if available via the system package manager
install_dependencies() {
    print_info "Installing system packages required for Gtk bindings..."
    if command -v apt-get &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y \\
            build-essential pkg-config libcairo2 libcairo2-dev \\
            libgirepository1.0-dev gobject-introspection \\
            gir1.2-gtk-3.0 python3-dev libffi-dev libssl-dev
    elif command -v yum &>/dev/null; then
        sudo yum install -y @'Development Tools' cairo cairo-devel \\
            gobject-introspection-devel gtk3-devel python3-devel \\
            libffi-devel openssl-devel
    elif command -v dnf &>/dev/null; then
        sudo dnf groupinstall -y "Development Tools" && sudo dnf install -y \\
            cairo cairo-devel gobject-introspection-devel gtk3-devel \\
            python3-devel libffi-devel openssl-devel
    elif command -v pacman &>/dev/null; then
        sudo pacman -Syu --noconfirm base-devel pkgconf cairo \\
            gobject-introspection gtk3 python
    elif command -v brew &>/dev/null; then
        brew install pkg-config cairo gobject-introspection gtk+3
    else
        print_warning "Unsupported package manager. Please install Gtk/GObject dependencies manually."
    fi
    print_warning "Install 'xclip' manually to enable clipboard features in secret mode."
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
    print_info "Checking for Gtk development libraries..."
    if ! python3 -c "import gi" &>/dev/null; then
        print_warning "Gtk introspection bindings not found. Installing dependencies..."
        install_dependencies
    else
        print_info "Gtk bindings already available."
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
    print_info "Installing Python dependencies with Poetry..."
    pip install --upgrade pip
    pip install poetry
    poetry install
    print_info "Installing platform-specific Toga backend..."
    if [ "$OS_NAME" = "Linux" ]; then
        print_info "Installing toga-gtk for Linux..."
        pip install toga-gtk
    elif [ "$OS_NAME" = "Darwin" ]; then
        print_info "Installing toga-cocoa for macOS..."
        pip install toga-cocoa
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
